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
	calls   []store.Change // every Record call, including failed ones
	err     error
	delay   time.Duration
	// hook, if set, runs once at the start of the next Record call.
	hook func()
}

func (f *fakeRec) Record(_ context.Context, c store.Change) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	hook := f.hook
	f.hook = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
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

func TestTrackerExpireEventNotResentOnRetry(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	rec.mu.Lock()
	rec.calls = nil
	rec.err = errors.New("boom")
	rec.mu.Unlock()
	clk.t = clk.t.Add(25 * time.Hour)
	tr.Tick(ctx)
	tr.Tick(ctx)
	rec.mu.Lock()
	rec.err = nil
	rec.mu.Unlock()
	tr.Tick(ctx)
	rec.mu.Lock()
	calls := append([]store.Change(nil), rec.calls...)
	rec.mu.Unlock()
	expires := 0
	for _, c := range calls {
		for _, e := range c.Events {
			if e.Type == event.NDExpire {
				expires++
			}
		}
	}
	last := calls[len(calls)-1]
	if len(calls) != 3 || expires != 1 || len(last.PutSightings) != 1 || !last.PutSightings[0].Expired {
		t.Fatalf("calls=%d expires=%d last=%+v", len(calls), expires, last)
	}
	if len(tr.entries) != 0 {
		t.Fatal("entry should be removed after success")
	}
}

func TestTrackerMACForIgnoresIdle(t *testing.T) {
	tr, _, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	tr.Observe(context.Background(), obs(t, "aa:bb:cc:00:00:01", "2001:db8::1"))
	clk.t = clk.t.Add(24 * time.Hour) // no Tick yet
	if _, ok := tr.MACFor(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("idle entry should miss before Tick")
	}
}

func TestTrackerConcurrentObserve(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.ProxyThreshold = 1000
	tr, rec, _, _ := newTestTracker(t, cfg)
	rec.delay = 2 * time.Millisecond
	ctx := context.Background()
	const workers, keys = 8, 40
	var wg sync.WaitGroup
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < keys; i++ {
				// overlapping across workers: key index i%20 shared, plus per-worker keys
				tr.Observe(ctx, obs(t, fmt.Sprintf("aa:bb:cc:00:01:%02x", i%20), fmt.Sprintf("2001:db8::%x", i%20)))
				tr.Observe(ctx, obs(t, fmt.Sprintf("aa:bb:cc:00:02:%02x", w), fmt.Sprintf("2001:db8:1::%x", i)))
			}
		}()
	}
	var bg sync.WaitGroup
	bg.Add(1)
	go func() {
		defer bg.Done()
		for {
			select {
			case <-done:
				return
			default:
				tr.Tick(ctx)
				tr.MACFor(netip.MustParseAddr("2001:db8::1"))
			}
		}
	}()
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock")
	}
	close(done)
	bg.Wait()
	want := 20 + workers*keys
	tr.mu.Lock()
	got := len(tr.entries)
	tr.mu.Unlock()
	if got != want {
		t.Fatalf("live = %d want %d", got, want)
	}
}

func countType(evs []event.Event, typ string) int {
	n := 0
	for _, e := range evs {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// Keys whose nd.new was suppressed by the bucket must not come back as an
// unlimited burst of nd.expire lines.
func TestTrackerExpireOnlyAnnounced(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EventBurst, cfg.EventRate, cfg.ProxyThreshold = 5, 0, 1000
	tr, rec, clk, _ := newTestTracker(t, cfg)
	ctx := context.Background()
	for i := 1; i <= 20; i++ {
		tr.Observe(ctx, obs(t, fmt.Sprintf("aa:bb:cc:00:00:%02x", i), fmt.Sprintf("2001:db8::%x", i)))
	}
	clk.t = clk.t.Add(24 * time.Hour)
	tr.Tick(ctx)
	if n := countType(rec.events(), event.NDExpire); n != 5 {
		t.Fatalf("nd.expire = %d, want 5", n)
	}
	expiredRows := 0
	for _, c := range rec.all() {
		for _, r := range c.PutSightings {
			if r.Expired {
				expiredRows++
			}
		}
	}
	if expiredRows != 20 || len(tr.entries) != 0 {
		t.Fatalf("expired rows = %d, live = %d", expiredRows, len(tr.entries))
	}
}

// Warm-loaded rows were announced by the previous run, so they still expire
// with an event.
func TestTrackerWarmLoadedExpireLogged(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	tr.Load([]store.Sighting{{MAC: "aa:bb:cc:00:00:01", Addr: netip.MustParseAddr("2001:db8::1"), Link: "eth0",
		FirstSeen: clk.t, LastSeen: clk.t}})
	clk.t = clk.t.Add(24 * time.Hour)
	tr.Tick(context.Background())
	if n := countType(rec.events(), event.NDExpire); n != 1 {
		t.Fatalf("nd.expire = %d, want 1", n)
	}
}

// The key that crosses the proxy threshold writes every row of that MAC as
// proxy-suspect in its own Change, not five minutes later.
func TestTrackerProxyFlagWrittenAtOnce(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	for i := 1; i <= 33; i++ {
		tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:01", fmt.Sprintf("2001:db8::%x", i)))
	}
	cs := rec.all()
	rows := cs[len(cs)-1].PutSightings
	if len(cs) != 33 || len(rows) != 33 {
		t.Fatalf("changes = %d, rows in crossing change = %d", len(cs), len(rows))
	}
	for _, r := range rows {
		if !r.ProxySuspect {
			t.Fatalf("row not suspect: %+v", r)
		}
	}
	clk.t = clk.t.Add(5 * time.Minute)
	tr.Tick(ctx)
	if n := len(rec.all()); n != 33 {
		t.Fatalf("tick rewrote clean rows: %d changes", n)
	}
}

// A stored proxy-suspect row marks its live siblings suspect on warm start.
func TestTrackerLoadMarksProxySiblings(t *testing.T) {
	tr, _, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	sib := netip.MustParseAddr("2001:db8::2")
	tr.Load([]store.Sighting{
		{MAC: "aa:bb:cc:00:00:01", Addr: netip.MustParseAddr("2001:db8::1"), Link: "eth0", FirstSeen: clk.t, LastSeen: clk.t, ProxySuspect: true},
		{MAC: "aa:bb:cc:00:00:01", Addr: sib, Link: "eth0", FirstSeen: clk.t, LastSeen: clk.t},
	})
	if _, ok := tr.MACFor(sib); ok {
		t.Fatal("sibling of a proxy-suspect row should be suspect")
	}
	for k, e := range tr.entries {
		// The sibling's row changed, so it is dirty and gets rewritten.
		if !e.ProxySuspect || (k.addr == sib && !e.dirty) {
			t.Fatalf("entry %v = %+v", k, e)
		}
	}
}

// A just-created entry must not be flushed by a Tick that runs while its
// first write is still in flight.
func TestTrackerNewEntryNotFlushedWhileInFlight(t *testing.T) {
	tr, rec, _, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	o := obs(t, "aa:bb:cc:00:00:01", "2001:db8::1")
	rec.hook = func() {
		tr.Observe(ctx, o) // repeat: marks it dirty
		tr.Tick(ctx)
	}
	tr.Observe(ctx, o)
	if n := len(rec.all()); n != 1 {
		t.Fatalf("changes = %d, want 1", n)
	}
}

// Flush writes every dirty row now, regardless of the interval, and emits
// nothing; it is called on shutdown so the database's last_seen does not lag.
func TestTrackerFlush(t *testing.T) {
	tr, rec, clk, _ := newTestTracker(t, DefaultTrackerConfig())
	ctx := context.Background()
	o := obs(t, "aa:bb:cc:00:00:01", "2001:db8::1")
	tr.Observe(ctx, o)
	tr.Observe(ctx, obs(t, "aa:bb:cc:00:00:02", "2001:db8::2")) // stays clean
	clk.t = clk.t.Add(time.Minute)
	tr.Observe(ctx, o)
	tr.Tick(ctx) // within the flush interval: nothing written
	before := len(rec.all())
	tr.Flush(ctx)
	cs := rec.all()
	if len(cs) != before+1 || len(cs[before].Events) != 0 || len(cs[before].PutSightings) != 1 ||
		!cs[before].PutSightings[0].LastSeen.Equal(clk.t) || cs[before].PutSightings[0].Expired {
		t.Fatalf("flush changes = %+v", cs[before:])
	}
	tr.Flush(ctx)
	if len(rec.all()) != before+1 {
		t.Fatal("second flush wrote again")
	}
}
