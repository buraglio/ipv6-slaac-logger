package sniffer

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Recorder persists and emits one Change atomically (same shape as registrar.Recorder).
type Recorder interface {
	Record(ctx context.Context, c store.Change) error
}

// TrackerConfig tunes sighting tracking and its bounds.
type TrackerConfig struct {
	Idle           time.Duration // 24h
	Flush          time.Duration // 5m
	LogLinkLocal   bool          // false
	ProxyThreshold int           // 32
	MaxEntries     int           // 100000
	EventRate      float64       // 20 per second
	EventBurst     int           // 200
}

// DefaultTrackerConfig returns the documented defaults.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		Idle:           24 * time.Hour,
		Flush:          5 * time.Minute,
		ProxyThreshold: 32,
		MaxEntries:     100000,
		EventRate:      20,
		EventBurst:     200,
	}
}

type key struct {
	mac  string
	addr netip.Addr
	link string
	vlan uint16
}

type macLV struct {
	mac  string
	link string
	vlan uint16
}

type entry struct {
	store.Sighting
	dirty     bool
	lastWrite time.Time
	// gen increments on every in-memory change, so an outcome applied after an
	// unlocked Record can tell whether the entry changed meanwhile.
	gen uint64
	// expireEmitted is set once the nd.expire event was handed to Record, so
	// retries after a recorder error write only the Expired row.
	expireEmitted bool
	// announced is set once an nd.new or nd.conflict for this window was
	// handed to Record (warm-loaded rows count as announced). Only announced
	// keys get an nd.expire, so a flood whose nd.new events were suppressed
	// does not return as an unlimited burst of expiries.
	announced bool
}

func (k key) macLV() macLV { return macLV{k.mac, k.link, k.vlan} }

// Tracker turns observations into sightings and nd.* events.
type Tracker struct {
	cfg TrackerConfig
	rec Recorder
	now func() time.Time
	log *slog.Logger

	mu      sync.Mutex
	entries map[key]*entry
	byAddr  map[netip.Addr]map[key]*entry
	byMAC   map[macLV]map[key]*entry
	proxy   map[macLV]bool
	bucket  *rate.Limiter

	overflow, suppressed, sightings uint64
}

// NewTracker returns a Tracker recording through rec.
func NewTracker(cfg TrackerConfig, rec Recorder, now func() time.Time, log *slog.Logger) *Tracker {
	return &Tracker{
		cfg: cfg, rec: rec, now: now, log: log,
		entries: map[key]*entry{},
		byAddr:  map[netip.Addr]map[key]*entry{},
		byMAC:   map[macLV]map[key]*entry{},
		proxy:   map[macLV]bool{},
		bucket:  rate.NewLimiter(rate.Limit(cfg.EventRate), cfg.EventBurst),
	}
}

func (t *Tracker) add(k key, e *entry) {
	t.entries[k] = e
	if t.byAddr[k.addr] == nil {
		t.byAddr[k.addr] = map[key]*entry{}
	}
	t.byAddr[k.addr][k] = e
	m := k.macLV()
	if t.byMAC[m] == nil {
		t.byMAC[m] = map[key]*entry{}
	}
	t.byMAC[m][k] = e
}

func (t *Tracker) remove(k key) {
	delete(t.entries, k)
	if s := t.byAddr[k.addr]; s != nil {
		delete(s, k)
		if len(s) == 0 {
			delete(t.byAddr, k.addr)
		}
	}
	m := k.macLV()
	if s := t.byMAC[m]; s != nil {
		delete(s, k)
		if len(s) == 0 {
			delete(t.byMAC, m)
			delete(t.proxy, m)
		}
	}
}

// markProxy flags every key of m proxy-suspect.
func (t *Tracker) markProxy(m macLV) {
	t.proxy[m] = true
	for _, e := range t.byMAC[m] {
		if !e.ProxySuspect {
			e.ProxySuspect = true
			e.dirty = true
			e.gen++
		}
	}
}

// checkProxy marks every key of m proxy-suspect once its count exceeds the
// threshold, and reports whether m crossed it just now.
func (t *Tracker) checkProxy(m macLV) bool {
	if t.proxy[m] || len(t.byMAC[m]) <= t.cfg.ProxyThreshold {
		return false
	}
	t.markProxy(m)
	t.log.Warn("proxy_suspect", "mac", m.mac, "link", m.link)
	return true
}

// Load seeds the tracker from stored rows without emitting events.
func (t *Tracker) Load(rows []store.Sighting) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, r := range rows {
		if r.Expired {
			continue
		}
		k := key{r.MAC, r.Addr, r.Link, r.VLAN}
		if _, ok := t.entries[k]; ok {
			continue
		}
		if len(t.entries) >= t.cfg.MaxEntries {
			t.overflow++
			continue
		}
		t.add(k, &entry{Sighting: r, lastWrite: now, announced: true})
		if r.ProxySuspect {
			t.proxy[k.macLV()] = true
		}
	}
	for m := range t.byMAC {
		if t.proxy[m] {
			// One stored suspect row flags its live siblings too.
			t.markProxy(m)
		} else {
			t.checkProxy(m)
		}
	}
}

func (t *Tracker) newEvent(typ string, e *entry, now time.Time) event.Event {
	ev := event.New(typ, now)
	ev.MAC, ev.Addr, ev.Link, ev.VLAN, ev.Kind = e.MAC, e.Addr.String(), e.Link, e.VLAN, e.Kind
	ev.Origin, ev.Via = "sniffer", "sniff"
	return ev
}

// quiet reports whether non-rate-limit suppression rules silence e's events.
func (t *Tracker) quiet(e *entry) bool {
	return e.ProxySuspect || (e.Addr.IsLinkLocalUnicast() && !t.cfg.LogLinkLocal)
}

// Observe records one observation.
func (t *Tracker) Observe(ctx context.Context, o Observation) {
	t.mu.Lock()
	now := t.now()
	k := key{o.MAC.String(), o.Addr, o.Link, o.VLAN}
	if e, ok := t.entries[k]; ok {
		e.LastSeen, e.Kind, e.dirty, e.expireEmitted = now, o.Kind, true, false
		e.gen++
		t.mu.Unlock()
		return
	}
	if len(t.entries) >= t.cfg.MaxEntries {
		t.overflow++
		t.mu.Unlock()
		return
	}
	// lastWrite = now: the row is written below, so a Tick racing with that
	// write must not flush it again.
	e := &entry{Sighting: store.Sighting{
		MAC: k.mac, Addr: k.addr, Link: k.link, VLAN: k.vlan, Kind: o.Kind,
		FirstSeen: now, LastSeen: now,
		ProxySuspect: t.proxy[k.macLV()],
	}, lastWrite: now}
	t.add(k, e)
	t.sightings++
	crossed := t.checkProxy(k.macLV())

	var ch store.Change
	if !t.quiet(e) {
		typ, prev := event.NDNew, ""
		var prevE *entry
		for ok2, other := range t.byAddr[k.addr] {
			if ok2.link != k.link || ok2.vlan != k.vlan || ok2.mac == k.mac || other.ProxySuspect {
				continue
			}
			if prevE == nil || other.LastSeen.After(prevE.LastSeen) {
				typ, prev, prevE = event.NDConflict, ok2.mac, other
			}
		}
		if t.bucket.AllowN(now, 1) {
			ev := t.newEvent(typ, e, now)
			ev.PrevMAC = prev
			ch.Events = append(ch.Events, ev)
			e.announced = true
		} else {
			t.suppressed++
		}
	}
	type pending struct {
		k   key
		e   *entry
		gen uint64
	}
	written := []pending{{k, e, e.gen}}
	ch.PutSightings = []store.Sighting{e.Sighting}
	if crossed {
		// Every row of the MAC carries the new proxy flag in this same Change.
		for ok2, other := range t.byMAC[k.macLV()] {
			if other != e {
				ch.PutSightings = append(ch.PutSightings, other.Sighting)
				written = append(written, pending{ok2, other, other.gen})
			}
		}
	}
	t.mu.Unlock()

	// The event is handed to Record exactly once; on error only the rows are
	// retried (via the dirty flag), never the event.
	err := t.rec.Record(ctx, ch)

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.log.Error("record sighting", "err", err)
	}
	for _, p := range written {
		if t.entries[p.k] != p.e {
			continue
		}
		switch {
		case err != nil:
			p.e.dirty, p.e.lastWrite = true, time.Time{}
		case p.e.gen == p.gen:
			p.e.dirty, p.e.lastWrite = false, now
		default:
			p.e.lastWrite = now // changed meanwhile: still dirty
		}
	}
}

// Tick expires idle keys and flushes dirty ones in a single Change.
func (t *Tracker) Tick(ctx context.Context) { t.tick(ctx, false) }

// Flush writes every dirty row now, regardless of the flush interval, and
// expires nothing. It is called on shutdown.
func (t *Tracker) Flush(ctx context.Context) { t.tick(ctx, true) }

func (t *Tracker) tick(ctx context.Context, flushAll bool) {
	type pending struct {
		k   key
		e   *entry
		gen uint64
	}
	t.mu.Lock()
	now := t.now()
	var ch store.Change
	var expired, flushed []pending
	for k, e := range t.entries {
		if !flushAll && now.Sub(e.LastSeen) >= t.cfg.Idle {
			if !e.expireEmitted {
				if e.announced && !t.quiet(e) {
					ev := t.newEvent(event.NDExpire, e, now)
					ev.FirstSeen, ev.LastSeen = event.TimePtr(e.FirstSeen), event.TimePtr(e.LastSeen)
					ch.Events = append(ch.Events, ev)
				}
				e.expireEmitted = true
			}
			row := e.Sighting
			row.Expired = true
			ch.PutSightings = append(ch.PutSightings, row)
			expired = append(expired, pending{k, e, e.gen})
		} else if e.dirty && (flushAll || now.Sub(e.lastWrite) >= t.cfg.Flush) {
			ch.PutSightings = append(ch.PutSightings, e.Sighting)
			flushed = append(flushed, pending{k, e, e.gen})
		}
	}
	t.mu.Unlock()
	if len(ch.PutSightings) == 0 {
		return
	}

	err := t.rec.Record(ctx, ch)

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.log.Error("record tick", "err", err)
		return
	}
	for _, p := range flushed {
		if t.entries[p.k] == p.e && p.e.gen == p.gen {
			p.e.dirty, p.e.lastWrite = false, now
		}
	}
	for _, p := range expired {
		if t.entries[p.k] != p.e {
			continue
		}
		if p.e.gen == p.gen {
			t.remove(p.k)
		} else {
			// Observed again while the Expired row was in flight: rewrite it live.
			p.e.dirty, p.e.lastWrite = true, time.Time{}
		}
	}
}

// MACFor returns the most recently seen non-proxy MAC for addr.
func (t *Tracker) MACFor(addr netip.Addr) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var best *entry
	for _, e := range t.byAddr[addr] {
		if e.ProxySuspect || now.Sub(e.LastSeen) >= t.cfg.Idle {
			continue
		}
		if best == nil || e.LastSeen.After(best.LastSeen) {
			best = e
		}
	}
	if best == nil {
		return "", false
	}
	return best.MAC, true
}

// Counters returns cumulative tracker counters.
func (t *Tracker) Counters() map[string]uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]uint64{
		"sniff_overflow": t.overflow,
		"nd_suppressed":  t.suppressed,
		"nd_sightings":   t.sightings,
	}
}
