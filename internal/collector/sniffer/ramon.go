package sniffer

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
	"github.com/buraglio/ipv6-ra-logger/internal/nd"
)

type routerKey struct {
	link string
	vlan uint16
	mac  string
	addr netip.Addr
}

type routerEntry struct {
	store.Router
	dirty     bool
	lastWrite time.Time
	// gen increments on every in-memory change so an outcome applied after an
	// unlocked Record can tell whether the entry changed meanwhile.
	gen uint64
}

// RAMonitor tracks routers from observed Router Advertisements.
type RAMonitor struct {
	rec   Recorder
	flush time.Duration
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	routers map[routerKey]*routerEntry
	invalid uint64
	seen    uint64
}

// NewRAMonitor returns a monitor recording through rec; last_seen is flushed at most every flush.
func NewRAMonitor(rec Recorder, flush time.Duration, now func() time.Time, log *slog.Logger) *RAMonitor {
	return &RAMonitor{rec: rec, flush: flush, now: now, log: log, routers: map[routerKey]*routerEntry{}}
}

// Load seeds the monitor from stored rows without emitting events.
func (m *RAMonitor) Load(rows []store.Router) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, r := range rows {
		k := routerKey{r.Link, r.VLAN, r.MAC, r.Addr}
		if _, ok := m.routers[k]; !ok {
			m.routers[k] = &routerEntry{Router: r, lastWrite: now}
		}
	}
}

func (m *RAMonitor) newEvent(typ string, e *routerEntry, now time.Time) event.Event {
	ev := event.New(typ, now)
	ev.MAC, ev.Addr, ev.Link, ev.VLAN = e.MAC, e.Addr.String(), e.Link, e.VLAN
	ev.Origin, ev.Via = "sniffer", "sniff"
	ev.Managed, ev.Other = event.Bool(e.Managed), event.Bool(e.Other)
	ev.Prefixes = slices.Clone(e.Prefixes)
	ev.RouterLft = event.U32(uint32(e.Lifetime))
	return ev
}

// Observe records one packet; anything but a Router Advertisement is ignored.
func (m *RAMonitor) Observe(ctx context.Context, p nd.Packet, link string) {
	if p.Type != nd.TypeRA || p.RA == nil {
		return
	}
	m.mu.Lock()
	if !p.Src.IsLinkLocalUnicast() {
		m.invalid++
		m.mu.Unlock()
		return
	}
	m.seen++
	now := m.now()
	mac := p.SrcMAC
	if len(p.LLAddr) > 0 {
		mac = p.LLAddr
	}
	prefixes := make([]string, 0, len(p.RA.Prefixes))
	for _, pr := range p.RA.Prefixes {
		prefixes = append(prefixes, pr.Prefix.String())
	}
	slices.Sort(prefixes)

	k := routerKey{link, p.VLAN, mac.String(), p.Src}
	e, known := m.routers[k]
	var typ string
	if !known {
		e = &routerEntry{Router: store.Router{
			Link: k.link, VLAN: k.vlan, MAC: k.mac, Addr: k.addr, FirstSeen: now,
		}}
		m.routers[k] = e
		typ = event.RASeen
	} else if e.Managed != p.RA.Managed || e.Other != p.RA.Other || !slices.Equal(e.Prefixes, prefixes) {
		typ = event.RAChange
	}
	e.Managed, e.Other, e.Prefixes, e.Lifetime = p.RA.Managed, p.RA.Other, prefixes, p.RA.RouterLifetime
	e.LastSeen = now
	e.gen++
	if typ == "" {
		e.dirty = true
		m.mu.Unlock()
		return
	}
	ch := store.Change{
		Events:     []event.Event{m.newEvent(typ, e, now)},
		PutRouters: []store.Router{e.Router},
	}
	gen := e.gen
	m.mu.Unlock()

	// The event is handed to Record exactly once; on error only the row is
	// retried (via the dirty flag), never the event.
	err := m.rec.Record(ctx, ch)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.routers[k] != e {
		return
	}
	if err != nil {
		m.log.Error("record router", "err", err)
		e.dirty, e.lastWrite = true, time.Time{}
		return
	}
	if e.gen == gen {
		e.dirty = false
	}
	e.lastWrite = now
}

// Tick flushes dirty routers whose last write is at least flush old.
func (m *RAMonitor) Tick(ctx context.Context) {
	type pending struct {
		e   *routerEntry
		gen uint64
	}
	m.mu.Lock()
	now := m.now()
	var ch store.Change
	var flushed []pending
	for _, e := range m.routers {
		if e.dirty && now.Sub(e.lastWrite) >= m.flush {
			ch.PutRouters = append(ch.PutRouters, e.Router)
			flushed = append(flushed, pending{e, e.gen})
		}
	}
	m.mu.Unlock()
	if len(ch.PutRouters) == 0 {
		return
	}

	err := m.rec.Record(ctx, ch)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.log.Error("record router tick", "err", err)
		return
	}
	for _, p := range flushed {
		if p.e.gen == p.gen {
			p.e.dirty, p.e.lastWrite = false, now
		} else {
			p.e.lastWrite = now
		}
	}
}

// Counters returns cumulative monitor counters.
func (m *RAMonitor) Counters() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]uint64{"nd_invalid": m.invalid, "ra_seen_total": m.seen}
}
