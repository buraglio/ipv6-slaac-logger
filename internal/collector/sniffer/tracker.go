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

// checkProxy marks every key of m proxy-suspect once its count exceeds the threshold.
func (t *Tracker) checkProxy(m macLV) {
	if t.proxy[m] || len(t.byMAC[m]) <= t.cfg.ProxyThreshold {
		return
	}
	t.proxy[m] = true
	for _, e := range t.byMAC[m] {
		e.ProxySuspect = true
		e.dirty = true
	}
	t.log.Warn("proxy_suspect", "mac", m.mac, "link", m.link)
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
		t.add(k, &entry{Sighting: r, lastWrite: now})
		if r.ProxySuspect {
			t.proxy[k.macLV()] = true
		}
	}
	for m := range t.byMAC {
		t.checkProxy(m)
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
	defer t.mu.Unlock()
	now := t.now()
	k := key{o.MAC.String(), o.Addr, o.Link, o.VLAN}
	if e, ok := t.entries[k]; ok {
		e.LastSeen, e.Kind, e.dirty = now, o.Kind, true
		return
	}
	if len(t.entries) >= t.cfg.MaxEntries {
		t.overflow++
		return
	}
	e := &entry{Sighting: store.Sighting{
		MAC: k.mac, Addr: k.addr, Link: k.link, VLAN: k.vlan, Kind: o.Kind,
		FirstSeen: now, LastSeen: now,
		ProxySuspect: t.proxy[k.macLV()],
	}}
	t.add(k, e)
	t.sightings++
	t.checkProxy(k.macLV())

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
		} else {
			t.suppressed++
		}
	}
	ch.PutSightings = []store.Sighting{e.Sighting}
	if err := t.rec.Record(ctx, ch); err != nil {
		t.log.Error("record sighting", "err", err)
		e.dirty, e.lastWrite = true, time.Time{}
		return
	}
	e.lastWrite = now
}

// Tick expires idle keys and flushes dirty ones in a single Change.
func (t *Tracker) Tick(ctx context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var ch store.Change
	var expired []key
	var flushed []*entry
	for k, e := range t.entries {
		if now.Sub(e.LastSeen) >= t.cfg.Idle {
			if !t.quiet(e) {
				ev := t.newEvent(event.NDExpire, e, now)
				ev.FirstSeen, ev.LastSeen = event.TimePtr(e.FirstSeen), event.TimePtr(e.LastSeen)
				ch.Events = append(ch.Events, ev)
			}
			row := e.Sighting
			row.Expired = true
			ch.PutSightings = append(ch.PutSightings, row)
			expired = append(expired, k)
		} else if e.dirty && now.Sub(e.lastWrite) >= t.cfg.Flush {
			ch.PutSightings = append(ch.PutSightings, e.Sighting)
			flushed = append(flushed, e)
		}
	}
	if len(ch.PutSightings) == 0 {
		return
	}
	if err := t.rec.Record(ctx, ch); err != nil {
		t.log.Error("record tick", "err", err)
		return
	}
	for _, e := range flushed {
		e.dirty, e.lastWrite = false, now
	}
	for _, k := range expired {
		t.remove(k)
	}
}

// MACFor returns the most recently seen non-proxy MAC for addr.
func (t *Tracker) MACFor(addr netip.Addr) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *entry
	for _, e := range t.byAddr[addr] {
		if e.ProxySuspect || e.Expired {
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
