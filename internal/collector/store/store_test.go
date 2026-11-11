package store

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/event"
)

var (
	ctx   = context.Background()
	t0    = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	addrA = netip.MustParseAddr("2001:db8:10::5")
	addrB = netip.MustParseAddr("2001:db8:10::6")
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func sampleBinding(a netip.Addr) Binding {
	return Binding{
		Addr: a, DUID: "00:03:00:01:5c:1e:9a:3b:21:aa", MAC: "5c:1e:9a:3b:21:aa", MACSrc: "duid",
		Origin: "native", Via: "multicast", Link: "eth0", Preferred: 3600, Valid: 7200,
		FirstSeen: t0, LastSeen: t0, ExpiresAt: t0.Add(2 * time.Hour),
	}
}

func ev(typ string, a netip.Addr, ts time.Time, reason string) event.Event {
	e := event.New(typ, ts)
	e.Addr = a.String()
	e.Reason = reason
	return e
}

func TestCommitAndGetBinding(t *testing.T) {
	s, _ := openTemp(t)
	b := sampleBinding(addrA)
	if err := s.Commit(ctx, Change{Events: []event.Event{ev(event.RegAdd, addrA, t0, "")}, Put: []Binding{b}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetBinding(ctx, addrA)
	if err != nil || !ok {
		t.Fatalf("GetBinding: %v %v", ok, err)
	}
	if got != b {
		t.Fatalf("got  %+v\nwant %+v", got, b)
	}
	if _, ok, _ := s.GetBinding(ctx, addrB); ok {
		t.Fatal("found a binding that was never stored")
	}
}

func TestUpsertAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	b := sampleBinding(addrA)
	_ = s.Commit(ctx, Change{Put: []Binding{b}})
	b.LastSeen = t0.Add(time.Hour)
	_ = s.Commit(ctx, Change{Put: []Binding{b}})
	got, _, _ := s.GetBinding(ctx, addrA)
	if !got.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("LastSeen = %v", got.LastSeen)
	}
	_ = s.Commit(ctx, Change{Delete: []netip.Addr{addrA}})
	if _, ok, _ := s.GetBinding(ctx, addrA); ok {
		t.Fatal("binding survived delete")
	}
}

func TestEventsAfterAndCursor(t *testing.T) {
	s, _ := openTemp(t)
	for _, r := range []string{"a", "b", "c"} {
		_ = s.Commit(ctx, Change{Events: []event.Event{ev(event.RegReject, addrA, t0, r)}})
	}
	first, err := s.EventsAfter(ctx, 0, 2)
	if err != nil || len(first) != 2 || first[0].Event.Reason != "a" || first[1].ID <= first[0].ID {
		t.Fatalf("first page: %+v %v", first, err)
	}
	rest, _ := s.EventsAfter(ctx, first[1].ID, 10)
	if len(rest) != 1 || rest[0].Event.Reason != "c" {
		t.Fatalf("rest: %+v", rest)
	}
	if c, _ := s.Cursor(ctx, "out"); c != 0 {
		t.Fatalf("initial cursor = %d", c)
	}
	_ = s.SetCursor(ctx, "out", 2)
	_ = s.SetCursor(ctx, "out", 3)
	if c, _ := s.Cursor(ctx, "out"); c != 3 {
		t.Fatalf("cursor = %d", c)
	}
}

func TestEventBodyRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	e := ev(event.RegAdd, addrA, t0, "")
	e.Host = "h1"
	e.Valid = event.U32(0)
	_ = s.Commit(ctx, Change{Events: []event.Event{e}})
	got, _ := s.EventsAfter(ctx, 0, 1)
	if got[0].Event.Host != "h1" || got[0].Event.Valid == nil || *got[0].Event.Valid != 0 || !got[0].Event.TS.Equal(t0) {
		t.Fatalf("got %+v", got[0].Event)
	}
}

func TestExpiredBindings(t *testing.T) {
	s, _ := openTemp(t)
	a, b := sampleBinding(addrA), sampleBinding(addrB)
	a.ExpiresAt, b.ExpiresAt = t0.Add(time.Hour), t0.Add(3*time.Hour)
	_ = s.Commit(ctx, Change{Put: []Binding{a, b}})
	got, err := s.ExpiredBindings(ctx, t0.Add(2*time.Hour))
	if err != nil || len(got) != 1 || got[0].Addr != addrA {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestWhereQueries(t *testing.T) {
	s, _ := openTemp(t)
	_ = s.Commit(ctx, Change{
		Events: []event.Event{
			ev(event.RegAdd, addrA, t0, "1"),
			ev(event.RegAdd, addrB, t0.Add(time.Hour), "2"),
			ev(event.RegChange, addrA, t0.Add(2*time.Hour), "3"),
		},
		Put: []Binding{sampleBinding(addrA)},
	})
	got, err := s.EventsWhere(ctx, "addr", addrA.String(), t0.Add(30*time.Minute), time.Time{})
	if err != nil || len(got) != 1 || got[0].Event.Reason != "3" {
		t.Fatalf("EventsWhere: %+v %v", got, err)
	}
	all, _ := s.EventsWhere(ctx, "addr", addrA.String(), time.Time{}, time.Time{})
	if len(all) != 2 {
		t.Fatalf("unbounded window: %d events", len(all))
	}
	if _, err := s.EventsWhere(ctx, "body", "x", time.Time{}, time.Time{}); err == nil {
		t.Fatal("accepted an invalid field")
	}
	bs, err := s.BindingsWhere(ctx, "duid", "00:03:00:01:5c:1e:9a:3b:21:aa")
	if err != nil || len(bs) != 1 {
		t.Fatalf("BindingsWhere: %+v %v", bs, err)
	}
}

func TestPurgeEventsBefore(t *testing.T) {
	s, _ := openTemp(t)
	_ = s.Commit(ctx, Change{Events: []event.Event{ev(event.RegAdd, addrA, t0, ""), ev(event.RegAdd, addrA, t0.Add(48*time.Hour), "")}})
	n, err := s.PurgeEventsBefore(ctx, t0.Add(24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
}

func TestPersistsAndReadOnly(t *testing.T) {
	s, path := openTemp(t)
	_ = s.Commit(ctx, Change{Put: []Binding{sampleBinding(addrA)}})
	s.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, ok, err := ro.GetBinding(ctx, addrA); !ok || err != nil {
		t.Fatalf("read-only GetBinding: %v %v", ok, err)
	}
	if err := ro.Commit(ctx, Change{Delete: []netip.Addr{addrA}}); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	if _, err := OpenReadOnly(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("OpenReadOnly created a missing database")
	}
}

func sampleSighting(mac string, a netip.Addr) Sighting {
	return Sighting{MAC: mac, Addr: a, Link: "eth0", VLAN: 20, Kind: "na", FirstSeen: t0, LastSeen: t0}
}

func commitOrFatal(t *testing.T, s *Store, c Change) {
	t.Helper()
	if err := s.Commit(ctx, c); err != nil {
		t.Fatal(err)
	}
}

func TestSightingsUpsertAndQuery(t *testing.T) {
	s, _ := openTemp(t)
	sg := sampleSighting("aa", addrA)
	commitOrFatal(t, s, Change{PutSightings: []Sighting{sg}})
	sg.LastSeen = t0.Add(time.Minute)
	sg.Kind = "dad"
	commitOrFatal(t, s, Change{PutSightings: []Sighting{sg}})
	got, err := s.SightingsWhere(ctx, "addr", addrA.String())
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
	if !got[0].LastSeen.Equal(t0.Add(time.Minute)) || got[0].Kind != "dad" || !got[0].FirstSeen.Equal(t0) || got[0].VLAN != 20 {
		t.Errorf("got %+v", got[0])
	}
	if by, _ := s.SightingsWhere(ctx, "mac", "aa"); len(by) != 1 {
		t.Errorf("by mac: %v", by)
	}
	if _, err := s.SightingsWhere(ctx, "duid", "x"); err == nil {
		t.Error("expected invalid field error")
	}
}

func TestSightingsIncludeExpired(t *testing.T) {
	s, _ := openTemp(t)
	ex := sampleSighting("bb", addrB)
	ex.Expired = true
	commitOrFatal(t, s, Change{PutSightings: []Sighting{sampleSighting("aa", addrA), ex}})
	if got, _ := s.Sightings(ctx, false); len(got) != 1 {
		t.Errorf("without expired: %v", got)
	}
	if got, _ := s.Sightings(ctx, true); len(got) != 2 {
		t.Errorf("with expired: %v", got)
	}
}

func TestRoutersRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	r := Router{Link: "eth0", VLAN: 20, MAC: "aa", Addr: netip.MustParseAddr("fe80::1"), Managed: true,
		Prefixes: []string{"2001:db8:10::/64", "2001:db8:11::/64"}, Lifetime: 1800, FirstSeen: t0, LastSeen: t0}
	commitOrFatal(t, s, Change{PutRouters: []Router{r}})
	r.LastSeen = t0.Add(time.Hour)
	commitOrFatal(t, s, Change{PutRouters: []Router{r}})
	got, err := s.Routers(ctx, time.Time{})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
	if !reflect.DeepEqual(got[0], Router{Link: "eth0", VLAN: 20, MAC: "aa", Addr: r.Addr, Managed: true, Other: false,
		Prefixes: r.Prefixes, Lifetime: 1800, FirstSeen: t0, LastSeen: t0.Add(time.Hour)}) {
		t.Errorf("got %+v", got[0])
	}
}

// Warm start reads only routers seen since a cutoff, so a flood of stale
// rows is not loaded back into memory.
func TestRoutersSince(t *testing.T) {
	s, _ := openTemp(t)
	old := Router{Link: "eth0", MAC: "aa", Addr: netip.MustParseAddr("fe80::1"), Prefixes: []string{}, FirstSeen: t0, LastSeen: t0}
	fresh := old
	fresh.MAC, fresh.LastSeen = "bb", t0.Add(2*time.Hour)
	commitOrFatal(t, s, Change{PutRouters: []Router{old, fresh}})
	got, err := s.Routers(ctx, t0.Add(time.Hour))
	if err != nil || len(got) != 1 || got[0].MAC != "bb" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestHostsViewJoins(t *testing.T) {
	s, _ := openTemp(t)
	addrC := netip.MustParseAddr("2001:db8:10::7")
	b1 := sampleBinding(addrA)
	b1.MAC, b1.MACSrc = "aa", "duid"
	b2 := sampleBinding(addrB)
	b2.MAC, b2.MACSrc = "", ""
	commitOrFatal(t, s, Change{
		Put:          []Binding{b1, b2},
		PutSightings: []Sighting{sampleSighting("aa", addrA), sampleSighting("bb", addrB), sampleSighting("cc", addrC)},
	})
	a, err := s.HostsWhere(ctx, "addr", addrA.String())
	if err != nil || len(a) != 1 || a[0].MAC != "aa" || a[0].MACSrc != "duid" || a[0].DUID == "" || a[0].VLAN != 20 {
		t.Errorf("A: %+v err %v", a, err)
	}
	b, _ := s.HostsWhere(ctx, "addr", addrB.String())
	if len(b) != 1 || b[0].MAC != "bb" || b[0].MACSrc != "nd" {
		t.Errorf("B: %+v", b)
	}
	c, _ := s.HostsWhere(ctx, "addr", addrC.String())
	if len(c) != 1 || c[0].DUID != "" || c[0].MACSrc != "nd" || c[0].MAC != "cc" {
		t.Errorf("C: %+v", c)
	}
	if m, _ := s.HostsWhere(ctx, "mac", "cc"); len(m) != 1 {
		t.Errorf("by mac: %v", m)
	}
	if d, _ := s.HostsWhere(ctx, "duid", b1.DUID); len(d) != 2 {
		t.Errorf("by duid: %v", d)
	}
	if _, err := s.HostsWhere(ctx, "host; drop", "x"); err == nil {
		t.Error("expected invalid field error")
	}
}

func TestHostsViewIgnoresProxySuspects(t *testing.T) {
	s, _ := openTemp(t)
	addrC := netip.MustParseAddr("2001:db8:10::7")
	b := sampleBinding(addrA)
	b.MAC, b.MACSrc = "", ""
	proxy := sampleSighting("xx", addrA)
	proxy.ProxySuspect = true
	expired := sampleSighting("yy", addrC)
	expired.Expired = true
	commitOrFatal(t, s, Change{Put: []Binding{b}, PutSightings: []Sighting{proxy, expired}})
	a, _ := s.HostsWhere(ctx, "addr", addrA.String())
	if len(a) != 1 || a[0].MAC != "" || a[0].MACSrc != "" {
		t.Errorf("proxy suspect leaked: %+v", a)
	}
	if c, _ := s.HostsWhere(ctx, "addr", addrC.String()); len(c) != 0 {
		t.Errorf("expired leaked: %+v", c)
	}
}

func TestPurgeStaleBefore(t *testing.T) {
	s, _ := openTemp(t)
	old := Router{Link: "eth0", MAC: "aa", Addr: netip.MustParseAddr("fe80::1"), Prefixes: []string{}, FirstSeen: t0, LastSeen: t0}
	fresh := old
	fresh.MAC, fresh.LastSeen = "bb", t0.Add(2*time.Hour)
	commitOrFatal(t, s, Change{
		PutSightings: []Sighting{sampleSighting("aa", addrA), func() Sighting { x := sampleSighting("bb", addrB); x.LastSeen = t0.Add(2 * time.Hour); return x }()},
		PutRouters:   []Router{old, fresh},
	})
	ns, nr, err := s.PurgeStaleBefore(ctx, t0.Add(time.Hour))
	if err != nil || ns != 1 || nr != 1 {
		t.Fatalf("sightings=%d routers=%d err=%v", ns, nr, err)
	}
	sg, _ := s.Sightings(ctx, true)
	rt, _ := s.Routers(ctx, time.Time{})
	if len(sg) != 1 || len(rt) != 1 {
		t.Errorf("remaining %d sightings %d routers", len(sg), len(rt))
	}
}

func TestOpenExistingPlan1Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	old := `CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, type TEXT NOT NULL,
  addr TEXT NOT NULL DEFAULT '', duid TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', body TEXT NOT NULL);
CREATE TABLE bindings (addr TEXT PRIMARY KEY, duid TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', mac_src TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '', via TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',
  preferred INTEGER NOT NULL, valid INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE forwarder_state (name TEXT PRIMARY KEY, last_id INTEGER NOT NULL);`
	if _, err := db.Exec(old); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	commitOrFatal(t, s, Change{PutSightings: []Sighting{sampleSighting("aa", addrA)}})
	if h, err := s.HostsWhere(ctx, "addr", addrA.String()); err != nil || len(h) != 1 {
		t.Errorf("hosts: %v %v", h, err)
	}
}

func TestSilentBindings(t *testing.T) {
	s, _ := openTemp(t)
	// a: last_seen t0 (old), b: last_seen t0+4h (recent)
	a, b := sampleBinding(addrA), sampleBinding(addrB)
	a.LastSeen = t0
	b.LastSeen = t0.Add(4 * time.Hour)
	// Both have expires_at well in the future.
	a.ExpiresAt = t0.Add(24 * time.Hour)
	b.ExpiresAt = t0.Add(24 * time.Hour)
	commitOrFatal(t, s, Change{Put: []Binding{a, b}})

	cutoff := t0.Add(3 * time.Hour) // silent_timeout=3h, so cutoff = now-3h = t0+1h
	got, err := s.SilentBindings(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != addrA {
		t.Fatalf("SilentBindings: got %v, want [%v]", got, addrA)
	}

	// Mark a as silenced; it should no longer appear.
	commitOrFatal(t, s, Change{Silence: []netip.Addr{addrA}})
	got, err = s.SilentBindings(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("after silence, SilentBindings returned %v", got)
	}

	// SilencedBindings should return a.
	silenced, err := s.SilencedBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(silenced) != 1 || silenced[0].Addr != addrA || !silenced[0].Silenced {
		t.Fatalf("SilencedBindings: got %v", silenced)
	}
}

func TestSilenceResetOnRenewal(t *testing.T) {
	s, _ := openTemp(t)
	b := sampleBinding(addrA)
	b.ExpiresAt = t0.Add(24 * time.Hour)
	commitOrFatal(t, s, Change{Put: []Binding{b}})
	commitOrFatal(t, s, Change{Silence: []netip.Addr{addrA}})

	got, _, _ := s.GetBinding(ctx, addrA)
	if !got.Silenced {
		t.Fatal("expected silenced=1 after Silence")
	}

	// Upsert (renewal) must reset silenced to 0.
	b.LastSeen = t0.Add(time.Hour)
	commitOrFatal(t, s, Change{Put: []Binding{b}})
	got, _, _ = s.GetBinding(ctx, addrA)
	if got.Silenced {
		t.Fatal("expected silenced=0 after renewal upsert")
	}
}

func TestOpenExistingPreSilencedDatabase(t *testing.T) {
	// Simulate a database that predates the silenced column.
	path := filepath.Join(t.TempDir(), "presil.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	preSilence := `CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, type TEXT NOT NULL,
  addr TEXT NOT NULL DEFAULT '', duid TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', body TEXT NOT NULL);
CREATE TABLE bindings (addr TEXT PRIMARY KEY, duid TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', mac_src TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '', via TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',
  preferred INTEGER NOT NULL, valid INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE forwarder_state (name TEXT PRIMARY KEY, last_id INTEGER NOT NULL);`
	if _, err := db.Exec(preSilence); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open pre-silenced DB: %v", err)
	}
	defer s.Close()
	// Should be able to read and write bindings including the silenced column.
	b := sampleBinding(addrA)
	b.ExpiresAt = t0.Add(time.Hour)
	commitOrFatal(t, s, Change{Put: []Binding{b}})
	got, ok, err := s.GetBinding(ctx, addrA)
	if err != nil || !ok {
		t.Fatalf("GetBinding: %v %v", ok, err)
	}
	if got.Silenced {
		t.Error("expected silenced=false on migrated binding")
	}
	commitOrFatal(t, s, Change{Silence: []netip.Addr{addrA}})
	got, _, _ = s.GetBinding(ctx, addrA)
	if !got.Silenced {
		t.Error("expected silenced=true after Silence on migrated DB")
	}
}
