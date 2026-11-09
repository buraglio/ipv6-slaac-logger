package registrar

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func TestKeyedBurstAndRefill(t *testing.T) {
	k := newKeyed(rate.Limit(1), 2)
	if !k.Allow("a", t0) || !k.Allow("a", t0) {
		t.Fatal("burst of 2 not allowed")
	}
	if k.Allow("a", t0) {
		t.Fatal("third request inside burst allowed")
	}
	if !k.Allow("b", t0) {
		t.Fatal("independent key limited")
	}
	if !k.Allow("a", t0.Add(time.Second)) {
		t.Fatal("token not refilled after 1s")
	}
}

func TestKeyedEvictsIdle(t *testing.T) {
	k := newKeyed(rate.Limit(1), 1)
	k.Allow("a", t0)
	k.Allow("b", t0.Add(11*time.Minute))
	if len(k.m) != 1 {
		t.Fatalf("entries = %d, want 1 after idle eviction", len(k.m))
	}
}

func TestLimiterSourceIsPerSlash64(t *testing.T) {
	l := NewLimiter(Limits{Global: Rate{1000, 1000}, PerPrefix: Rate{0.001, 1}, PerDUID: Rate{1000, 1000}})
	if !l.AllowSource(netip.MustParseAddr("2001:db8:10::5"), t0) {
		t.Fatal("first source denied")
	}
	if l.AllowSource(netip.MustParseAddr("2001:db8:10::6"), t0) {
		t.Fatal("same /64 not limited")
	}
	if !l.AllowSource(netip.MustParseAddr("2001:db8:11::5"), t0) {
		t.Fatal("different /64 limited")
	}
}

func TestLimiterGlobalAndDUID(t *testing.T) {
	l := NewLimiter(Limits{Global: Rate{0.001, 1}, PerPrefix: Rate{1000, 1000}, PerDUID: Rate{0.001, 1}})
	if !l.AllowSource(netip.MustParseAddr("2001:db8:10::5"), t0) || l.AllowSource(netip.MustParseAddr("2001:db8:20::5"), t0) {
		t.Fatal("global limit not enforced")
	}
	if !l.AllowDUID([]byte{0, 3, 1}, t0) || l.AllowDUID([]byte{0, 3, 1}, t0) {
		t.Fatal("per-DUID limit not enforced")
	}
}

func TestAllowSourceFloodDoesNotStarveGlobal(t *testing.T) {
	l := NewLimiter(Limits{Global: Rate{0.001, 2}, PerPrefix: Rate{0.001, 1}, PerDUID: Rate{1000, 1000}})
	flood := netip.MustParseAddr("2001:db8:10::5")
	if !l.AllowSource(flood, t0) {
		t.Fatal("first request from flooding /64 denied")
	}
	for i := 0; i < 4; i++ {
		src := netip.AddrFrom16(flood.As16())
		b := src.As16()
		b[15] = byte(6 + i)
		if l.AllowSource(netip.AddrFrom16(b), t0) {
			t.Fatalf("request %d from flooding /64 allowed by per-/64 bucket", i)
		}
	}
	if !l.AllowSource(netip.MustParseAddr("2001:db8:20::5"), t0) {
		t.Fatal("unrelated source starved: flood drained the global bucket")
	}
}

func TestKeyedHardCap(t *testing.T) {
	k := newKeyed(rate.Limit(1), 1)
	k.max = 2
	if !k.Allow("a", t0) || !k.Allow("b", t0) {
		t.Fatal("first two keys denied under cap")
	}
	if k.Allow("c", t0) {
		t.Fatal("third key admitted beyond hard cap")
	}
	if len(k.m) != 2 {
		t.Fatalf("entries = %d, want 2 (no insert past cap)", len(k.m))
	}
	if !k.Allow("c", t0.Add(11*time.Minute)) {
		t.Fatal("key denied after idle eviction freed capacity")
	}
}
