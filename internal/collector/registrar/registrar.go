package registrar

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

const (
	// InfiniteTTL bounds bindings registered with an infinite valid lifetime.
	InfiniteTTL = 12 * time.Hour
	// AgentPrefix starts the first Vendor Class string sent by ra-logger agents.
	AgentPrefix = "ra-logger-agent/"

	OriginNative = "native"
	OriginAgent  = "agent"

	MACSrcCLLAO  = "cllao"
	MACSrcVendor = "vendor"
	MACSrcDUID   = "duid"
)

// BindingStore reads current bindings.
type BindingStore interface {
	GetBinding(ctx context.Context, addr netip.Addr) (store.Binding, bool, error)
	ExpiredBindings(ctx context.Context, now time.Time) ([]store.Binding, error)
}

// Recorder writes changes (satisfied by *recorder.Recorder).
type Recorder interface {
	Record(ctx context.Context, c store.Change) error
}

// Stats are cumulative counters, reported in the periodic stats event.
type Stats struct {
	Received, Replied, Rejected, RateLimited atomic.Uint64
}

// Snapshot returns the counters as a map.
func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"received":     s.Received.Load(),
		"replied":      s.Replied.Load(),
		"rejected":     s.Rejected.Load(),
		"rate_limited": s.RateLimited.Load(),
	}
}

// Registrar is the RFC 9686 server state machine.
type Registrar struct {
	Bindings BindingStore
	Rec      Recorder
	Policy   *PrefixPolicy
	Limits   *Limiter
	ServerID []byte
	PEN      uint32
	Now      func() time.Time
	Log      *slog.Logger
	Stats    Stats

	mu                sync.Mutex // serializes binding read-modify-write and expiry
	rejectLog         *rate.Limiter
	suppressed        atomic.Uint64
	limitedSinceSweep atomic.Uint64
}

// New returns a Registrar with default limits.
func New(b BindingStore, rec Recorder, pol *PrefixPolicy, serverID []byte, pen uint32) *Registrar {
	return &Registrar{
		Bindings: b, Rec: rec, Policy: pol, Limits: NewLimiter(DefaultLimits),
		ServerID: serverID, PEN: pen, Now: time.Now, Log: slog.Default(),
		rejectLog: rate.NewLimiter(1, 20), // at most 20 individual reject events per burst, 1/s sustained
	}
}

// Handle processes one request and returns the reply, or nil to drop it.
func (r *Registrar) Handle(ctx context.Context, req *Request) *dhcp6.Message {
	now := r.Now()
	r.Stats.Received.Add(1)
	// Validate (including the prefix policy) runs before any token bucket is
	// charged, so spoofed or out-of-policy traffic cannot drain the global
	// bucket; rejects are bounded separately by rejectLog.
	v, reason := Validate(req, r.Policy)
	if reason != "" {
		r.reject(ctx, req, reason, now)
		return nil
	}
	if !r.Limits.AllowSource(limitKey(req), now) {
		r.limited()
		return nil
	}
	if !r.Limits.AllowDUID(v.DUID, now) {
		r.limited()
		return nil
	}
	r.mu.Lock()
	ok := r.apply(ctx, req, v, now)
	r.mu.Unlock()
	if !ok {
		return nil
	}
	r.Stats.Replied.Add(1)
	return r.reply(req.Msg, v.IARaw)
}

func limitKey(req *Request) netip.Addr {
	if req.Via == ViaRelay && req.Relay != nil {
		return req.Relay.PeerAddr
	}
	return req.Src.Addr()
}

func (r *Registrar) limited() {
	r.Stats.RateLimited.Add(1)
	r.limitedSinceSweep.Add(1)
}

func (r *Registrar) reply(in *dhcp6.Message, iaRaw []byte) *dhcp6.Message {
	cid, _ := in.Options.Get(dhcp6.OptClientID)
	return &dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: in.XID, Options: dhcp6.Options{
		{Code: dhcp6.OptClientID, Data: cid.Data},
		{Code: dhcp6.OptServerID, Data: r.ServerID},
		{Code: dhcp6.OptIAAddr, Data: iaRaw},
	}}
}

// apply returns false when the binding store could not be read; nothing is
// recorded and the request is dropped so the client retransmits.
func (r *Registrar) apply(ctx context.Context, req *Request, v Valid, now time.Time) bool {
	b := r.bindingFor(req, v, now)
	old, found, err := r.Bindings.GetBinding(ctx, b.Addr)
	if err != nil {
		r.Log.Error("registrar: read binding", "addr", b.Addr, "err", err)
		return false
	}
	ev := eventFor(event.RegAdd, b, now)
	ev.DUIDType = dhcp6.DUIDTypeName(v.DUID)
	ev.Preferred = event.U32(v.IA.Preferred)
	ev.Valid = event.U32(v.IA.Valid)
	ev.XID = hex.EncodeToString(req.Msg.XID[:])
	ev.Src = req.Src.Addr().String()

	var c store.Change
	switch {
	case v.IA.Valid == 0:
		if !found {
			return true
		}
		if old.DUID != b.DUID {
			r.reject(ctx, req, ReasonDeregForeign, now)
			return true
		}
		ev.Type = event.RegDereg
		ev.FirstSeen = event.TimePtr(old.FirstSeen)
		ev.LastSeen = event.TimePtr(now)
		c = store.Change{Events: []event.Event{ev}, Delete: []netip.Addr{b.Addr}}
	case !found:
		c = store.Change{Events: []event.Event{ev}, Put: []store.Binding{b}}
	case old.DUID != b.DUID:
		ev.Type = event.RegConflict
		ev.PrevDUID = old.DUID
		c = store.Change{Events: []event.Event{ev}, Put: []store.Binding{b}}
	default:
		b.FirstSeen = old.FirstSeen
		keepProvenance(old, &b)
		ev.MAC, ev.MACSrc, ev.Via, ev.Link = b.MAC, b.MACSrc, b.Via, b.Link
		c.Put = []store.Binding{b}
		if materialChange(old, b) {
			ev.Type = event.RegChange
			c.Events = []event.Event{ev}
		}
	}
	if err := r.Rec.Record(ctx, c); err != nil {
		r.Log.Error("registrar: record", "addr", b.Addr, "err", err)
	}
	return true
}

func (r *Registrar) bindingFor(req *Request, v Valid, now time.Time) store.Binding {
	b := store.Binding{
		Addr: v.IA.Addr, DUID: dhcp6.FormatHex(v.DUID), Origin: OriginNative,
		Via: req.Via, Link: req.IfName, Preferred: v.IA.Preferred, Valid: v.IA.Valid,
		FirstSeen: now, LastSeen: now,
	}
	if req.Via == ViaRelay && req.Relay != nil {
		b.Link = "relay/" + req.Relay.LinkAddr.String()
	}
	if v.IA.Valid == dhcp6.Infinity {
		b.ExpiresAt = now.Add(InfiniteTTL)
	} else {
		b.ExpiresAt = now.Add(time.Duration(v.IA.Valid) * time.Second)
	}
	info, isAgent := r.agentInfo(req.Msg)
	if isAgent {
		b.Origin = OriginAgent
	}
	// MAC precedence: relay-inserted CLLAO (observed by network gear), then the
	// agent-reported current interface MAC, then the MAC embedded in the DUID.
	switch {
	case req.Relay != nil && len(req.Relay.CLLAO) == 6:
		b.MAC, b.MACSrc = req.Relay.CLLAO.String(), MACSrcCLLAO
	case isAgent && validMAC(info["mac"]) != "":
		b.MAC, b.MACSrc = validMAC(info["mac"]), MACSrcVendor
	default:
		if mac, ok := dhcp6.MACFromDUID(v.DUID); ok {
			b.MAC, b.MACSrc = mac.String(), MACSrcDUID
		}
	}
	if o, ok := req.Msg.Options.Get(dhcp6.OptClientFQDN); ok {
		if _, name, err := dhcp6.ParseFQDN(o.Data); err == nil {
			b.Host = name
		}
	}
	return b
}

// agentInfo returns key=value pairs from an ra-logger agent Vendor Class.
func (r *Registrar) agentInfo(m *dhcp6.Message) (map[string]string, bool) {
	opt, ok := m.Options.Get(dhcp6.OptVendorClass)
	if !ok {
		return nil, false
	}
	vc, err := dhcp6.ParseVendorClass(opt.Data)
	if err != nil || vc.Enterprise != r.PEN || len(vc.Data) == 0 || !bytes.HasPrefix(vc.Data[0], []byte(AgentPrefix)) {
		return nil, false
	}
	kv := map[string]string{"agent": string(vc.Data[0])}
	for _, d := range vc.Data[1:] {
		if k, val, ok := strings.Cut(string(d), "="); ok {
			kv[k] = val
		}
	}
	return kv, true
}

func validMAC(s string) string {
	if s == "" {
		return ""
	}
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return ""
	}
	return m.String()
}

// macRank orders MAC sources by precedence.
func macRank(src string) int {
	switch src {
	case MACSrcCLLAO:
		return 3
	case MACSrcVendor:
		return 2
	case MACSrcDUID:
		return 1
	}
	return 0
}

// keepProvenance stops copies of one registration that arrive by different
// paths from churning a live binding of the same DUID: a lower-precedence MAC
// source never replaces a higher one, and a unicast copy (whose ingress
// interface says little about the client's link) never replaces the link and
// via learned from a multicast or relayed copy.
func keepProvenance(old store.Binding, nb *store.Binding) {
	if macRank(nb.MACSrc) < macRank(old.MACSrc) {
		nb.MAC, nb.MACSrc = old.MAC, old.MACSrc
	}
	if nb.Via == ViaUnicast && (old.Via == ViaMulticast || old.Via == ViaRelay) {
		nb.Link, nb.Via = old.Link, old.Via
	}
}

// materialChange reports changes worth a reg.change event. A change of via
// alone is not one: topology C delivers each registration both ways.
func materialChange(old, nb store.Binding) bool {
	if old.MAC != nb.MAC || old.Link != nb.Link || old.Host != nb.Host || old.Origin != nb.Origin {
		return true
	}
	if nb.Valid != dhcp6.Infinity {
		slack := time.Duration(nb.Valid) * time.Second / 100
		if old.ExpiresAt.Sub(nb.ExpiresAt) > slack {
			return true // lifetime shortened, e.g. renumbering
		}
	}
	return false
}

func eventFor(typ string, b store.Binding, now time.Time) event.Event {
	e := event.New(typ, now)
	e.Addr = b.Addr.String()
	e.DUID = b.DUID
	e.MAC = b.MAC
	e.MACSrc = b.MACSrc
	e.Origin = b.Origin
	e.Host = b.Host
	e.Via = b.Via
	e.Link = b.Link
	return e
}

func (r *Registrar) reject(ctx context.Context, req *Request, reason string, now time.Time) {
	r.Stats.Rejected.Add(1)
	if !r.rejectLog.AllowN(now, 1) {
		r.suppressed.Add(1)
		return
	}
	e := event.New(event.RegReject, now)
	e.Reason = reason
	e.Via = req.Via
	e.Link = req.IfName
	e.Src = req.Src.Addr().String()
	if m := req.Msg; m != nil {
		e.XID = hex.EncodeToString(m.XID[:])
		if cid, ok := m.Options.Get(dhcp6.OptClientID); ok && len(cid.Data) <= MaxDUIDLen {
			e.DUID = dhcp6.FormatHex(cid.Data)
		}
		if o, ok := m.Options.Get(dhcp6.OptIAAddr); ok {
			if ia, err := dhcp6.ParseIAAddress(o.Data); err == nil {
				e.Addr = ia.Addr.String()
			}
		}
	}
	if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}}); err != nil {
		r.Log.Error("registrar: record reject", "err", err)
	}
}

// Sweep expires bindings past their lifetime and emits reject summaries.
// The collector calls it every minute.
func (r *Registrar) Sweep(ctx context.Context) {
	now := r.Now()
	r.mu.Lock()
	expired, err := r.Bindings.ExpiredBindings(ctx, now)
	if err != nil {
		r.Log.Error("registrar: list expired", "err", err)
	}
	for _, b := range expired {
		e := eventFor(event.RegExpire, b, now)
		if d, err := dhcp6.ParseHex(b.DUID); err == nil {
			e.DUIDType = dhcp6.DUIDTypeName(d)
		}
		e.FirstSeen = event.TimePtr(b.FirstSeen)
		e.LastSeen = event.TimePtr(b.LastSeen)
		e.Valid = event.U32(b.Valid)
		e.Preferred = event.U32(b.Preferred)
		if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}, Delete: []netip.Addr{b.Addr}}); err != nil {
			r.Log.Error("registrar: record expire", "addr", b.Addr, "err", err)
		}
	}
	r.mu.Unlock()
	r.summary(ctx, now, ReasonSuppressed, r.suppressed.Swap(0))
	r.summary(ctx, now, ReasonRateLimited, r.limitedSinceSweep.Swap(0))
}

func (r *Registrar) summary(ctx context.Context, now time.Time, reason string, n uint64) {
	if n == 0 {
		return
	}
	e := event.New(event.RegReject, now)
	e.Reason = reason
	e.Count = n
	if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}}); err != nil {
		r.Log.Error("registrar: record summary", "err", err)
	}
}
