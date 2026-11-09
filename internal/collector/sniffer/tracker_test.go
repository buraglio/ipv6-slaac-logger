package sniffer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

type fakeRec struct {
	mu      sync.Mutex
	changes []store.Change
	err     error
}

func (f *fakeRec) Record(_ context.Context, c store.Change) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.changes = append(f.changes, c)
	return nil
}

func (f *fakeRec) all() []store.Change {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Change(nil), f.changes...)
}

func (f *fakeRec) events() []event.Event {
	var out []event.Event
	for _, c := range f.all() {
		out = append(out, c.Events...)
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestTracker(t *testing.T, cfg TrackerConfig) (*Tracker, *fakeRec, *clock, *bytes.Buffer) {
	t.Helper()
	rec := &fakeRec{}
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	return NewTracker(cfg, rec, clk.now, log), rec, clk, buf
}

func obs(t testing.TB, mac, addr string) Observation {
	return Observation{MAC: mustMAC(t, mac), Addr: netip.MustParseAddr(addr), Link: "eth0", Kind: KindDAD}
}

func TestTrackerNewSighting(t *testing.T) {
	tr, rec, _, _ := newTestTracker(t, DefaultTrackerConfig())
	tr.Observe(context.Background(), obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	cs := rec.all()
	if len(cs) != 1 || len(cs[0].Events) != 1 || len(cs[0].PutSightings) != 1 {
		t.Fatalf("changes = %+v", cs)
	}
	e := cs[0].Events[0]
	if e.Type != event.NDNew || e.Kind != "dad" || e.Origin != "sniffer" || e.Via != "sniff" ||
		e.MAC != "aa:bb:cc:00:00:01" || e.Addr != "2001:db8::1" || e.Link != "eth0" {
		t.Fatalf("event = %+v", e)
	}
}

func TestTrackerRepeatIsSilentAndBatched(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	o := obs(t, "aa:bb:cc:00:00:01", "2001:db8::1")
	tr.Observe(ctx, o)
	start := clk.t
	for i := 1; i <= 100; i++ {
		clk.t = start.Add(time.Duration(i) * 2400 * time.Millisecond)
		tr.Observe(ctx, o)
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("changes after repeats = %d", n)
	}
	clk.t = start.Add(5 * time.Minute)
	last := clk.t
	tr.Observe(ctx, o)
	tr.Tick(ctx)
	cs := rec.all()
	if len(cs) != 2 || len(cs[1].Events) != 0 || len(cs[1].PutSightings) != 1 {
		t.Fatalf("changes = %+v", cs)
	}
	if !cs[1].PutSightings[0].LastSeen.Equal(last) {
		t.Fatalf("last seen = %v want %v", cs[1].PutSightings[0].LastSeen, last)
	}
}

func TestTrackerConflict(t *testing.T) {
	tr, rec, _, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:02", "2001:db8::1"))
	ev := rec.events()
	if len(ev) != 2 || ev[1].Type != event.NDConflict || ev[1].PrevMAC != "aa:bb:cc:00:00:01" || ev[1].MAC != "aa:bb:cc:00:00:02" {
		t.Fatalf("events = %+v", ev)
	}
	if len(tr.entries) != 2 {
		t.Fatalf("live = %d", len(tr.entries))
	}
}

func TestTrackerExpire(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	o := obs(t, "aa:bb:cc:00:00:01", "2001:db8::1")
	first := clk.t
	tr.Observe(ctx, o)
	clk.t = clk.t.Add(24 * time.Hour)
	tr.Tick(ctx)
	cs := rec.all()
	if len(cs) != 2 || len(cs[1].Events) != 1 || len(cs[1].PutSightings) != 1 {
		t.Fatalf("changes = %+v", cs)
	}
	e := cs[1].Events[0]
	if e.Type != event.NDExpire || e.FirstSeen == nil || e.LastSeen == nil ||
		!e.FirstSeen.Equal(first) || !e.LastSeen.Equal(first) || e.Origin != "sniffer" || e.Via != "sniff" {
		t.Fatalf("event = %+v", e)
	}
	if !cs[1].PutSightings[0].Expired {
		t.Fatal("row not expired")
	}
	tr.Observe(ctx, o)
	ev := rec.events()
	if len(ev) != 3 || ev[2].Type != event.NDNew {
		t.Fatalf("events = %+v", ev)
	}
}

func TestTrackerLinkLocalDBOnly(t *testing.T) {
	for _, on := range []bool{false, true} {
		cfg := DefaultTrackerConfig()
		cfg.LogLinkLocal = on
		tr, rec, _, _ := newTestTracker(t, cfg)
		tr.Observe(context.Background(), obs(t, "aa:bb:cc:00:00:01", "fe80::1"))
		cs := rec.all()
		want := 0
		if on {
			want = 1
		}
		if len(cs) != 1 || len(cs[0].PutSightings) != 1 || len(cs[0].Events) != want {
			t.Fatalf("LogLinkLocal=%v changes = %+v", on, cs)
		}
	}
}

func TestTrackerProxySuspect(t *testing.T) {
	tr, rec, clk, buf := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	for i := 1; i <= 33; i++ {
		tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", fmt.Sprintf("2001:db8::%x", i)))
	}
	if n := len(rec.events()); n != 32 {
		t.Fatalf("events = %d want 32", n)
	}
	clk.t = clk.t.Add(5 * time.Minute)
	tr.Tick(ctx)
	cs := rec.all()
	rows := cs[len(cs)-1].PutSightings
	if len(rows) != 33 {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, r := range rows {
		if !r.ProxySuspect {
			t.Fatalf("row not suspect: %+v", r)
		}
	}
	if _, ok := tr.MACFor(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("MACFor should be false for proxy")
	}
	if n := strings.Count(buf.String(), "proxy_suspect"); n != 1 {
		t.Fatalf("warn lines = %d: %s", n, buf.String())
	}
}

func TestTrackerBoundsEntries(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.MaxEntries = 10
	cfg.ProxyThreshold = 1000
	tr, _, _, _ := newTestTracker(t, cfg)
	for i := 1; i <= 50; i++ {
		tr.Observe(context.Background(), obs(t, fmt.Sprintf("aa:bb:cc:00:00:%02x", i), fmt.Sprintf("2001:db8::%x", i)))
	}
	if len(tr.entries) != 10 || tr.Counters()["sniff_overflow"] != 40 {
		t.Fatalf("live=%d counters=%v", len(tr.entries), tr.Counters())
	}
}

func TestTrackerBoundsEventRate(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EventBurst = 5
	cfg.EventRate = 0
	tr, rec, _, _ := newTestTracker(t, cfg)
	for i := 1; i <= 20; i++ {
		tr.Observe(context.Background(), obs(t, fmt.Sprintf("aa:bb:cc:00:00:%02x", i), fmt.Sprintf("2001:db8::%x", i)))
	}
	sightings := 0
	for _, c := range rec.all() {
		sightings += len(c.PutSightings)
	}
	if len(rec.events()) != 5 || sightings != 20 || tr.Counters()["nd_suppressed"] != 15 {
		t.Fatalf("events=%d sightings=%d counters=%v", len(rec.events()), sightings, tr.Counters())
	}
}

func TestTrackerWarmStartNoDuplicateNew(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	o := obs(t, "aa:bb:cc:00:00:01", "2001:db8::1")
	tr.Load([]store.Sighting{
		{MAC: o.MAC.String(), Addr: o.Addr, Link: "eth0", Kind: "ns", FirstSeen: clk.t.Add(-time.Hour), LastSeen: clk.t.Add(-time.Hour)},
		{MAC: "aa:bb:cc:00:00:02", Addr: netip.MustParseAddr("2001:db8::2"), Link: "eth0", Expired: true},
	})
	if len(tr.entries) != 1 {
		t.Fatalf("live = %d", len(tr.entries))
	}
	tr.Observe(context.Background(), o)
	if len(rec.all()) != 0 {
		t.Fatalf("changes = %+v", rec.all())
	}
}

func TestTrackerMACFor(t *testing.T) {
	tr, _, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	a := netip.MustParseAddr("2001:db8::1")
	if _, ok := tr.MACFor(a); ok {
		t.Fatal("unexpected hit")
	}
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	clk.t = clk.t.Add(time.Second)
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:02", "2001:db8::1"))
	if m, ok := tr.MACFor(a); !ok || m != "aa:bb:cc:00:00:02" {
		t.Fatalf("MACFor = %q %v", m, ok)
	}
	clk.t = clk.t.Add(25 * time.Hour)
	tr.Tick(ctx)
	if _, ok := tr.MACFor(a); ok {
		t.Fatal("expired should miss")
	}
}

func TestTrackerRecorderErrorKeepsDirty(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	rec.err = errors.New("boom")
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	if len(tr.entries) != 1 {
		t.Fatal("state lost")
	}
	clk.t = clk.t.Add(time.Second)
	tr.Tick(ctx) // still failing, stays dirty
	rec.err = nil
	clk.t = clk.t.Add(time.Second)
	tr.Tick(ctx)
	cs := rec.all()
	if len(cs) != 1 || len(cs[0].PutSightings) != 1 {
		t.Fatalf("changes = %+v", cs)
	}
}
