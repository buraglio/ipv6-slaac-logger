package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
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
