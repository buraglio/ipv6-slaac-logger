package sniffer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
	"github.com/buraglio/ipv6-ra-logger/internal/nd"
)

const raLL = "fe80::1"

func newTestRAMon(t *testing.T) (*RAMonitor, *fakeRec, *clock) {
	t.Helper()
	return newTestRAMonCfg(t, DefaultRAMonitorConfig())
}

func newTestRAMonCfg(t *testing.T, cfg RAMonitorConfig) (*RAMonitor, *fakeRec, *clock) {
	t.Helper()
	rec := &fakeRec{}
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	return NewRAMonitor(cfg, rec, clk.now, log), rec, clk
}

func raPkt(t testing.TB, src string, managed, other bool, lft uint16, prefixes ...string) nd.Packet {
	ra := &nd.RA{Managed: managed, Other: other, RouterLifetime: lft}
	for _, p := range prefixes {
		ra.Prefixes = append(ra.Prefixes, nd.Prefix{Prefix: netip.MustParsePrefix(p)})
	}
	return nd.Packet{
		SrcMAC: mustMAC(t, "aa:bb:cc:00:00:01"), Src: netip.MustParseAddr(src),
		Type: nd.TypeRA, RA: ra,
	}
}

func lastRouter(t *testing.T, rec *fakeRec) store.Router {
	t.Helper()
	var r *store.Router
	for _, c := range rec.all() {
		if len(c.PutRouters) > 0 {
			r = &c.PutRouters[len(c.PutRouters)-1]
		}
	}
	if r == nil {
		t.Fatal("no router row written")
	}
	return *r
}

func TestRAMonitorSeen(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	m.Observe(context.Background(), raPkt(t, raLL, true, false, 1800, "2001:db8:2::/64", "2001:db8:1::/64"), "eth0")
	evs := rec.events()
	if len(evs) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	e := evs[0]
	if e.Type != event.RASeen || e.MAC != "aa:bb:cc:00:00:01" || e.Addr != raLL || e.Link != "eth0" ||
		e.Origin != "sniffer" || e.Via != "sniff" || *e.Managed != true || *e.Other != false ||
		*e.RouterLft != 1800 || len(e.Prefixes) != 2 || e.Prefixes[0] != "2001:db8:1::/64" {
		t.Fatalf("event = %+v", e)
	}
	r := lastRouter(t, rec)
	if r.Lifetime != 1800 || !r.Managed || r.Prefixes[0] != "2001:db8:1::/64" {
		t.Fatalf("row = %+v", r)
	}
	if m.Counters()["ra_seen_total"] != 1 {
		t.Fatalf("counters = %v", m.Counters())
	}
}

func TestRAMonitorLLAddrPreferred(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	p := raPkt(t, raLL, false, false, 1800)
	p.LLAddr = mustMAC(t, "aa:bb:cc:00:00:99")
	m.Observe(context.Background(), p, "eth0")
	if got := rec.events()[0].MAC; got != "aa:bb:cc:00:00:99" {
		t.Fatalf("mac = %s", got)
	}
}

func TestRAMonitorRepeatSilent(t *testing.T) {
	m, rec, clk := newTestRAMon(t)
	ctx := context.Background()
	p := raPkt(t, raLL, false, false, 1800, "2001:db8::/64")
	for i := 0; i < 10; i++ {
		m.Observe(ctx, p, "eth0")
		clk.t = clk.t.Add(time.Minute)
	}
	if n := len(rec.events()); n != 1 {
		t.Fatalf("events = %d, want 1", n)
	}
	before := len(rec.all())
	m.Tick(ctx)
	cs := rec.all()
	if len(cs) != before+1 || len(cs[before].PutRouters) != 1 || len(cs[before].Events) != 0 {
		t.Fatalf("tick changes = %+v", cs[before:])
	}
	if !lastRouter(t, rec).LastSeen.Equal(clk.t.Add(-time.Minute)) {
		t.Fatalf("last_seen = %v", lastRouter(t, rec).LastSeen)
	}
	m.Tick(ctx) // clean now
	if len(rec.all()) != before+1 {
		t.Fatal("second tick wrote again")
	}
}

func TestRAMonitorChangeOnFlags(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	ctx := context.Background()
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800), "eth0")
	m.Observe(ctx, raPkt(t, raLL, false, true, 1800), "eth0")
	evs := rec.events()
	if len(evs) != 2 || evs[1].Type != event.RAChange || !*evs[1].Other {
		t.Fatalf("events = %+v", evs)
	}
	if !lastRouter(t, rec).Other {
		t.Fatal("row not written immediately")
	}
}

func TestRAMonitorChangeOnPrefixes(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	ctx := context.Background()
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800, "2001:db8:1::/64"), "eth0")
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800, "2001:db8:1::/64", "2001:db8:2::/64"), "eth0")
	evs := rec.events()
	if len(evs) != 2 || evs[1].Type != event.RAChange || len(evs[1].Prefixes) != 2 {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRAMonitorLifetimeOnlyNoEvent(t *testing.T) {
	m, rec, clk := newTestRAMon(t)
	ctx := context.Background()
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800), "eth0")
	m.Observe(ctx, raPkt(t, raLL, false, false, 0), "eth0")
	if n := len(rec.events()); n != 1 {
		t.Fatalf("events = %d", n)
	}
	clk.t = clk.t.Add(5 * time.Minute)
	m.Tick(ctx)
	if r := lastRouter(t, rec); r.Lifetime != 0 {
		t.Fatalf("lifetime = %d", r.Lifetime)
	}
}

func TestRAMonitorRejectsGlobalSource(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	m.Observe(context.Background(), raPkt(t, "2001:db8::1", false, false, 1800), "eth0")
	if len(rec.all()) != 0 {
		t.Fatal("recorded")
	}
	if c := m.Counters(); c["nd_invalid"] != 1 || c["ra_seen_total"] != 0 {
		t.Fatalf("counters = %v", c)
	}
}

func TestRAMonitorIgnoresNonRA(t *testing.T) {
	m, rec, _ := newTestRAMon(t)
	m.Observe(context.Background(), nd.Packet{Type: nd.TypeNS, Src: netip.MustParseAddr(raLL)}, "eth0")
	if len(rec.all()) != 0 || m.Counters()["nd_invalid"] != 0 {
		t.Fatal("non-RA not ignored")
	}
}

func TestRAMonitorWarmStart(t *testing.T) {
	m, rec, clk := newTestRAMon(t)
	m.Load([]store.Router{{
		Link: "eth0", MAC: "aa:bb:cc:00:00:01", Addr: netip.MustParseAddr(raLL),
		Managed: true, Prefixes: []string{"2001:db8:1::/64"}, Lifetime: 1800, LastSeen: clk.t.Add(-time.Hour),
	}})
	m.Observe(context.Background(), raPkt(t, raLL, true, false, 1800, "2001:db8:1::/64"), "eth0")
	if len(rec.events()) != 0 {
		t.Fatalf("events = %+v", rec.events())
	}
}

func TestRAMonitorRecordErrorRetriesRowOnly(t *testing.T) {
	m, rec, clk := newTestRAMon(t)
	ctx := context.Background()
	rec.err = errors.New("boom")
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800), "eth0")
	rec.err = nil
	m.Observe(ctx, raPkt(t, raLL, false, false, 1800), "eth0")
	m.Tick(ctx)
	if len(rec.events()) != 0 {
		t.Fatalf("event re-sent: %+v", rec.events())
	}
	_ = clk
	if lastRouter(t, rec).Link != "eth0" {
		t.Fatal("row not retried")
	}
}

func routerRows(rec *fakeRec) int {
	n := 0
	for _, c := range rec.all() {
		n += len(c.PutRouters)
	}
	return n
}

// A flood of forged RAs from ever-new link-local sources must not grow memory
// (or the routers table) without bound.
func TestRAMonitorBoundsRouters(t *testing.T) {
	cfg := DefaultRAMonitorConfig()
	cfg.MaxRouters = 3
	m, rec, _ := newTestRAMonCfg(t, cfg)
	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		m.Observe(ctx, raPkt(t, fmt.Sprintf("fe80::%x", i), false, false, 1800), "eth0")
	}
	if len(m.routers) != 3 || len(rec.events()) != 3 || routerRows(rec) != 3 {
		t.Fatalf("routers=%d events=%d rows=%d", len(m.routers), len(rec.events()), routerRows(rec))
	}
	if c := m.Counters(); c["ra_overflow"] != 7 || c["ra_seen_total"] != 10 {
		t.Fatalf("counters = %v", c)
	}
	// A known router is still tracked at the cap.
	m.Observe(ctx, raPkt(t, "fe80::1", true, false, 1800), "eth0")
	if evs := rec.events(); len(evs) != 4 || evs[3].Type != event.RAChange {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRAMonitorBoundsEventRate(t *testing.T) {
	cfg := DefaultRAMonitorConfig()
	cfg.EventRate, cfg.EventBurst = 0, 2
	m, rec, _ := newTestRAMonCfg(t, cfg)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		m.Observe(ctx, raPkt(t, fmt.Sprintf("fe80::%x", i), false, false, 1800), "eth0")
	}
	// A change over the bucket is stored but not logged either.
	m.Observe(ctx, raPkt(t, "fe80::1", true, false, 1800), "eth0")
	if len(rec.events()) != 2 || routerRows(rec) != 6 || !lastRouter(t, rec).Managed {
		t.Fatalf("events=%d rows=%d last=%+v", len(rec.events()), routerRows(rec), lastRouter(t, rec))
	}
	if c := m.Counters(); c["ra_suppressed"] != 4 {
		t.Fatalf("counters = %v", c)
	}
}

func TestRAMonitorEvictsIdle(t *testing.T) {
	m, rec, clk := newTestRAMon(t)
	ctx := context.Background()
	m.Observe(ctx, raPkt(t, "fe80::1", false, false, 1800), "eth0")
	clk.t = clk.t.Add(time.Minute)
	m.Observe(ctx, raPkt(t, "fe80::1", false, false, 1800), "eth0") // dirty, not yet flushed
	last := clk.t
	m.Observe(ctx, raPkt(t, "fe80::2", false, false, 1800), "eth0")
	clk.t = clk.t.Add(24*time.Hour - time.Second)
	m.Observe(ctx, raPkt(t, "fe80::2", false, false, 1800), "eth0")
	clk.t = clk.t.Add(time.Second)
	m.Tick(ctx)
	if len(m.routers) != 1 {
		t.Fatalf("routers = %d, want 1", len(m.routers))
	}
	cs := rec.all()
	var final *store.Router
	for i, r := range cs[len(cs)-1].PutRouters {
		if r.Addr == netip.MustParseAddr("fe80::1") {
			final = &cs[len(cs)-1].PutRouters[i]
		}
	}
	if final == nil || !final.LastSeen.Equal(last) {
		t.Fatalf("idle router's final row not written: %+v", cs[len(cs)-1])
	}
	if n := len(rec.events()); n != 2 {
		t.Fatalf("events = %d (eviction must not log)", n)
	}
}

func TestRAMonitorWarmStartSkipsIdle(t *testing.T) {
	m, _, clk := newTestRAMon(t)
	base := store.Router{Link: "eth0", MAC: "aa:bb:cc:00:00:01", Prefixes: []string{}}
	fresh, stale := base, base
	fresh.Addr, fresh.LastSeen = netip.MustParseAddr("fe80::1"), clk.t.Add(-time.Hour)
	stale.Addr, stale.LastSeen = netip.MustParseAddr("fe80::2"), clk.t.Add(-25*time.Hour)
	m.Load([]store.Router{fresh, stale})
	if len(m.routers) != 1 || m.routers[routerKey{"eth0", 0, base.MAC, fresh.Addr}] == nil {
		t.Fatalf("routers = %+v", m.routers)
	}
}

func TestRAMonitorWarmStartCapped(t *testing.T) {
	cfg := DefaultRAMonitorConfig()
	cfg.MaxRouters = 2
	m, _, clk := newTestRAMonCfg(t, cfg)
	var rows []store.Router
	for i := 1; i <= 5; i++ {
		rows = append(rows, store.Router{Link: "eth0", MAC: "aa:bb:cc:00:00:01",
			Addr: netip.MustParseAddr(fmt.Sprintf("fe80::%x", i)), LastSeen: clk.t})
	}
	m.Load(rows)
	if len(m.routers) != 2 || m.Counters()["ra_overflow"] != 3 {
		t.Fatalf("routers=%d counters=%v", len(m.routers), m.Counters())
	}
}
