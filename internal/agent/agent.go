// Package agent runs the RFC 9686 address registration loop: it watches the
// host's addresses, schedules ADDR-REG-INFORM messages and sends them.
package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/sched"
	"github.com/buraglio/ipv6-ra-logger/internal/agent/sender"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

const (
	debounceDelay = time.Second
	probeTTL      = time.Hour // probe results are refreshed at heartbeat
	serverPort    = 547
)

// Tx sends messages and delivers replies.
type Tx interface {
	Send(a addrsrc.Addr, d sender.Dest, payload []byte) error
	Replies() <-chan sender.Reply
	Drop(addr netip.Addr)
}

// Agent registers local addresses with DHCPv6 servers and collectors.
type Agent struct {
	Src        addrsrc.Source
	Filter     addrsrc.IfFilter
	DUID       []byte
	Info       sender.Info
	Collectors []netip.AddrPort
	Multicast  string // "auto" | "always"
	Tx         Tx
	Probe      func(ctx context.Context, ifname string) bool // nil => sender.Probe with port 547
	MAC        func(ifname string) net.HardwareAddr          // default via net.InterfaceByName
	Sched      *sched.Scheduler
	Rescan     time.Duration // 5m
	Poll       time.Duration // 30s; used when Watch fails or closes
	Now        func() time.Time
	Log        *slog.Logger

	// Loop-goroutine state.
	ctx      context.Context
	ticker   *time.Ticker
	debounce *time.Timer
	keys     map[netip.Addr]sched.Key
	probes   map[string]*probeState
	probeCh  chan probeResult
	noDests  map[string]bool
	warned   map[sched.Key][3]byte
}

type probeState struct {
	ok      bool
	at      time.Time
	pending bool
}

type probeResult struct {
	ifname string
	ok     bool
}

func (a *Agent) init(ctx context.Context) {
	a.ctx = ctx
	if a.Sched == nil {
		a.Sched = sched.New(sched.DefaultParams())
	}
	if a.Rescan <= 0 {
		a.Rescan = 5 * time.Minute
	}
	if a.Poll <= 0 {
		a.Poll = 30 * time.Second
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Log == nil {
		a.Log = slog.Default()
	}
	if a.MAC == nil {
		a.MAC = func(ifname string) net.HardwareAddr {
			if ifi, err := net.InterfaceByName(ifname); err == nil {
				return ifi.HardwareAddr
			}
			return nil
		}
	}
	if a.Probe == nil {
		a.Probe = func(ctx context.Context, ifname string) bool {
			ok, err := sender.Probe(ctx, ifname, a.DUID, serverPort)
			if err != nil {
				a.Log.Debug("option 148 probe failed", "if", ifname, "err", err)
			}
			return ok
		}
	}
	a.keys = map[netip.Addr]sched.Key{}
	a.probes = map[string]*probeState{}
	a.probeCh = make(chan probeResult, 16)
	a.noDests = map[string]bool{}
	a.warned = map[sched.Key][3]byte{}
}

// Run registers addresses until ctx is done and returns ctx.Err(). It never
// de-registers.
func (a *Agent) Run(ctx context.Context) error {
	a.init(ctx)
	if _, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, a.Info.Hostname); err != nil {
		a.Log.Debug("hostname not encodable; FQDN option omitted", "hostname", a.Info.Hostname, "err", err)
	}

	a.ticker = time.NewTicker(a.Rescan)
	defer a.ticker.Stop()
	defer func() {
		if a.debounce != nil {
			a.debounce.Stop()
		}
	}()

	watch, err := a.Src.Watch(ctx)
	if err != nil {
		a.fallbackToPolling("address watch unavailable", err)
		watch = nil
	}
	a.onRescan(a.Now())

	for {
		var timerC <-chan time.Time
		var timer *time.Timer
		if next, ok := a.Sched.Next(); ok {
			timer = time.NewTimer(max(0, next.Sub(a.Now())))
			timerC = timer.C
		}
		var debounceC <-chan time.Time
		if a.debounce != nil {
			debounceC = a.debounce.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-timerC:
			a.step(a.Now())
		case _, ok := <-watch:
			if !ok {
				watch = nil
				if ctx.Err() == nil {
					a.fallbackToPolling("address watch closed", nil)
				}
				continue
			}
			a.onWatch()
		case <-debounceC:
			a.debounce = nil
			a.onRescan(a.Now())
		case <-a.ticker.C:
			a.onRescan(a.Now())
		case r := <-a.Tx.Replies():
			a.onReply(r)
		case pr := <-a.probeCh:
			a.onProbeResult(pr.ifname, pr.ok, a.Now())
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (a *Agent) fallbackToPolling(msg string, err error) {
	if err != nil {
		a.Log.Info(msg+"; polling", "interval", a.Poll, "err", err)
	} else {
		a.Log.Info(msg+"; polling", "interval", a.Poll)
	}
	a.Rescan = a.Poll
	if a.ticker != nil {
		a.ticker.Reset(a.Poll)
	}
}

// onWatch arms the debounce timer; further signals while it is pending do nothing.
func (a *Agent) onWatch() {
	if a.debounce == nil {
		a.debounce = time.NewTimer(debounceDelay)
	}
}

// onRescan lists, selects and reconciles the scheduler with the host's addresses.
func (a *Agent) onRescan(now time.Time) {
	all, err := a.Src.List()
	if err != nil {
		a.Log.Warn("listing addresses failed; keeping previous state", "err", err)
		return
	}
	sel := addrsrc.Select(all, a.Filter)
	for _, k := range a.Sched.Update(now, sel) {
		a.Tx.Drop(k.Addr)
		delete(a.warned, k)
	}
	a.keys = make(map[netip.Addr]sched.Key, len(sel))
	for _, s := range sel {
		a.keys[s.Addr] = sched.Key{Addr: s.Addr, IfIndex: s.IfIndex}
	}
}

// step runs one scheduler iteration: it sends everything due at now.
func (a *Agent) step(now time.Time) {
	for _, s := range a.Sched.Due(now, a.destsFor(now)) {
		a.send(s)
	}
}

// destsFor returns the destination-name function used when a cycle starts.
func (a *Agent) destsFor(now time.Time) func(addrsrc.Addr) []string {
	return func(ad addrsrc.Addr) []string {
		var out []string
		if a.Multicast == "always" || a.multicastOK(ad.IfName, now) {
			out = append(out, sender.DestMulticast)
		}
		for _, c := range a.Collectors {
			out = append(out, sender.UnicastDest(c).Name)
		}
		if len(out) == 0 && !a.noDests[ad.IfName] {
			a.noDests[ad.IfName] = true
			a.Log.Debug("no destinations for interface", "if", ad.IfName)
		}
		return out
	}
}

// multicastOK returns the cached probe result for ifname, starting a probe
// when none exists or it is older than probeTTL.
func (a *Agent) multicastOK(ifname string, now time.Time) bool {
	st := a.probes[ifname]
	if st == nil {
		st = &probeState{}
		a.probes[ifname] = st
	}
	if !st.pending && (st.at.IsZero() || now.Sub(st.at) >= probeTTL) {
		st.pending = true
		go func() {
			ok := a.Probe(a.ctx, ifname)
			select {
			case a.probeCh <- probeResult{ifname, ok}:
			case <-a.ctx.Done():
			}
		}()
	}
	return st.ok
}

func (a *Agent) onProbeResult(ifname string, ok bool, now time.Time) {
	st := a.probes[ifname]
	if st == nil {
		st = &probeState{}
		a.probes[ifname] = st
	}
	if st.ok != ok {
		a.Log.Info("multicast registration support", "if", ifname, "enabled", ok)
	}
	st.ok, st.at, st.pending = ok, now, false
}

func (a *Agent) dest(name, ifname string) (sender.Dest, bool) {
	if name == sender.DestMulticast {
		return sender.MulticastDest(ifname), true
	}
	for _, c := range a.Collectors {
		if d := sender.UnicastDest(c); d.Name == name {
			return d, true
		}
	}
	return sender.Dest{}, false
}

func (a *Agent) send(s sched.Send) {
	payload, err := sender.BuildInform(s.XID, a.DUID, s.Addr, a.MAC(s.Addr.IfName), a.Info)
	if err != nil {
		a.Log.Warn("building ADDR-REG-INFORM failed", "addr", s.Addr.Addr, "err", err)
		return
	}
	for _, name := range s.Dests {
		d, ok := a.dest(name, s.Addr.IfName)
		if !ok {
			continue
		}
		err := a.Tx.Send(s.Addr, d, payload)
		switch {
		case err == nil:
		case errors.Is(err, sender.ErrAddrGone):
			a.Log.Info("address gone", "addr", s.Addr.Addr, "if", s.Addr.IfName)
			a.Sched.Forget(s.Key)
			a.Tx.Drop(s.Addr.Addr)
			delete(a.keys, s.Addr.Addr)
			delete(a.warned, s.Key)
			return
		case errors.Is(err, net.ErrClosed):
			// Socket was just dropped; the next cycle rebinds.
			a.Log.Debug("send on closed socket; will retry", "addr", s.Addr.Addr, "dest", name)
		default:
			if w, seen := a.warned[s.Key]; !seen || w != s.XID {
				a.warned[s.Key] = s.XID
				a.Log.Warn("send failed", "addr", s.Addr.Addr, "dest", name, "err", err)
			}
		}
	}
}

func (a *Agent) onReply(r sender.Reply) {
	key, ok := a.keys[r.Local]
	if !ok {
		return
	}
	if i := slices.IndexFunc(a.Collectors, func(c netip.AddrPort) bool { return c.Addr() == r.From }); i >= 0 {
		a.Sched.Ack(key, r.XID, sender.UnicastDest(a.Collectors[i]).Name)
	}
	a.Sched.Ack(key, r.XID, sender.DestMulticast)
}
