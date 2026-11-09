package sniffer

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"

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

// RAMonitorConfig tunes router tracking and its bounds.
type RAMonitorConfig struct {
	Flush      time.Duration // 5m: last_seen is written at most this often per router
	Idle       time.Duration // 24h: routers not seen for this long are dropped from memory
	MaxRouters int           // 1000
	EventRate  float64       // 2 per second
	EventBurst int           // 50
}

// DefaultRAMonitorConfig returns the documented defaults.
func DefaultRAMonitorConfig() RAMonitorConfig {
	return RAMonitorConfig{
		Flush:      5 * time.Minute,
		Idle:       24 * time.Hour,
		MaxRouters: 1000,
		EventRate:  2,
		EventBurst: 50,
	}
}

// RAMonitor tracks routers from observed Router Advertisements.
type RAMonitor struct {
	cfg RAMonitorConfig
	rec Recorder
	now func() time.Time
	log *slog.Logger

	mu      sync.Mutex
	routers map[routerKey]*routerEntry
	bucket  *rate.Limiter

	invalid, seen, overflow, suppressed uint64
}

// NewRAMonitor returns a monitor recording through rec.
func NewRAMonitor(cfg RAMonitorConfig, rec Recorder, now func() time.Time, log *slog.Logger) *RAMonitor {
	return &RAMonitor{
		cfg: cfg, rec: rec, now: now, log: log,
		routers: map[routerKey]*routerEntry{},
		bucket:  rate.NewLimiter(rate.Limit(cfg.EventRate), cfg.EventBurst),
	}
}

// Load seeds the monitor from stored rows without emitting events. Routers
// idle for Idle or longer are skipped, and at most MaxRouters are kept.
func (m *RAMonitor) Load(rows []store.Router) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, r := range rows {
		if now.Sub(r.LastSeen) >= m.cfg.Idle {
			continue
		}
		k := routerKey{r.Link, r.VLAN, r.MAC, r.Addr}
		if _, ok := m.routers[k]; ok {
			continue
		}
		if len(m.routers) >= m.cfg.MaxRouters {
			m.overflow++
			continue
		}
		m.routers[k] = &routerEntry{Router: r, lastWrite: now}
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
		if len(m.routers) >= m.cfg.MaxRouters {
			m.overflow++
			m.mu.Unlock()
			return
		}
		e = &routerEntry{Router: store.Router{
			Link: k.link, VLAN: k.vlan, MAC: k.mac, Addr: k.addr, FirstSeen: now,
		}, lastWrite: now}
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
	// A new or changed router's row is written now; its event only while the
	// bucket allows.
	ch := store.Change{PutRouters: []store.Router{e.Router}}
	if m.bucket.AllowN(now, 1) {
		ch.Events = []event.Event{m.newEvent(typ, e, now)}
	} else {
		m.suppressed++
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

// Tick flushes dirty routers whose last write is at least Flush old and drops
// routers idle for Idle or longer from memory. Eviction logs nothing (there is
// no ra.expire); the row stays in the database until retention removes it.
func (m *RAMonitor) Tick(ctx context.Context) { m.tick(ctx, false) }

// Flush writes every dirty router row now, regardless of the flush interval,
// and evicts nothing. It is called on shutdown.
func (m *RAMonitor) Flush(ctx context.Context) { m.tick(ctx, true) }

func (m *RAMonitor) tick(ctx context.Context, flushAll bool) {
	type pending struct {
		k   routerKey
		e   *routerEntry
		gen uint64
	}
	m.mu.Lock()
	now := m.now()
	var ch store.Change
	var flushed, evicted []pending
	for k, e := range m.routers {
		idle := !flushAll && now.Sub(e.LastSeen) >= m.cfg.Idle
		switch {
		case idle && !e.dirty:
			delete(m.routers, k)
		case idle:
			// Write its final last_seen first; evict once that succeeded.
			ch.PutRouters = append(ch.PutRouters, e.Router)
			evicted = append(evicted, pending{k, e, e.gen})
		case e.dirty && (flushAll || now.Sub(e.lastWrite) >= m.cfg.Flush):
			ch.PutRouters = append(ch.PutRouters, e.Router)
			flushed = append(flushed, pending{k, e, e.gen})
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
		if m.routers[p.k] != p.e {
			continue
		}
		p.e.lastWrite = now
		if p.e.gen == p.gen {
			p.e.dirty = false
		}
	}
	for _, p := range evicted {
		if m.routers[p.k] != p.e {
			continue
		}
		if p.e.gen == p.gen {
			delete(m.routers, p.k)
		} else {
			p.e.lastWrite = now // seen again meanwhile: stays, still dirty
		}
	}
}

// Counters returns cumulative monitor counters.
func (m *RAMonitor) Counters() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]uint64{
		"nd_invalid":    m.invalid,
		"ra_seen_total": m.seen,
		"ra_overflow":   m.overflow,
		"ra_suppressed": m.suppressed,
	}
}
