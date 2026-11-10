package sched

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func testParams() Params {
	p := DefaultParams()
	p.Rand = func() float64 { return 0.5 }
	var n uint32
	p.NewXID = func() [3]byte {
		n++
		return [3]byte{byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return p
}

func mkAddr(valid uint32) addrsrc.Addr {
	return addrsrc.Addr{
		Addr:       netip.MustParseAddr("2001:db8::1"),
		IfName:     "eth0",
		IfIndex:    2,
		Origin:     addrsrc.OriginSLAAC,
		Preferred:  valid,
		Valid:      valid,
		ObservedAt: t0,
	}
}

var bothDests = func(addrsrc.Addr) []string {
	return []string{"multicast", "unicast:[2001:db8::53]:547"}
}

func keyOfAddr(a addrsrc.Addr) Key { return Key{a.Addr, a.IfIndex} }

func TestNewAddressDueImmediately(t *testing.T) {
	s := New(testParams())
	a := mkAddr(86400)
	s.Update(t0, []addrsrc.Addr{a})
	got := s.Due(t0, bothDests)
	if len(got) != 1 || got[0].Try != 1 {
		t.Fatalf("got %+v", got)
	}
	if !slices.Equal(got[0].Dests, []string{"multicast", "unicast:[2001:db8::53]:547"}) {
		t.Fatalf("dests %v", got[0].Dests)
	}
	if s.Len() != 1 {
		t.Fatal("len")
	}
}

func TestRetransmitSchedule(t *testing.T) {
	s := New(testParams())
	s.Update(t0, []addrsrc.Addr{mkAddr(86400)})
	var xid [3]byte
	for i, off := range []time.Duration{0, time.Second, 3 * time.Second} {
		got := s.Due(t0.Add(off), bothDests)
		if len(got) != 1 || got[0].Try != i+1 {
			t.Fatalf("try %d at %v: %+v", i+1, off, got)
		}
		if i == 0 {
			xid = got[0].XID
		} else if got[0].XID != xid {
			t.Fatal("xid changed within cycle")
		}
		// nothing due just before the next one
		if i < 2 {
			next := []time.Duration{time.Second, 3 * time.Second}[i]
			if g := s.Due(t0.Add(next-time.Millisecond), bothDests); len(g) != 0 {
				t.Fatalf("early send %+v", g)
			}
		}
	}
	if g := s.Due(t0.Add(30*time.Minute), bothDests); len(g) != 0 {
		t.Fatalf("unexpected %+v", g)
	}
	got := s.Due(t0.Add(time.Hour), bothDests)
	if len(got) != 1 || got[0].Try != 1 || got[0].XID == xid {
		t.Fatalf("new cycle: %+v", got)
	}
}

func TestSchedGivesUpAfterMaxTriesUntilRefresh(t *testing.T) {
	s := New(testParams())
	s.Update(t0, []addrsrc.Addr{mkAddr(86400)})
	for _, off := range []time.Duration{0, time.Second, 3 * time.Second} {
		s.Due(t0.Add(off), bothDests)
	}
	if g := s.Due(t0.Add(10*time.Minute), bothDests); len(g) != 0 {
		t.Fatalf("got %+v", g)
	}
	n, ok := s.Next()
	if !ok || !n.Equal(t0.Add(time.Hour)) {
		t.Fatalf("next %v %v", n, ok)
	}
}

func TestAckPerDestination(t *testing.T) {
	s := New(testParams())
	a := mkAddr(86400)
	k := keyOfAddr(a)
	s.Update(t0, []addrsrc.Addr{a})
	first := s.Due(t0, bothDests)[0]

	s.Ack(k, [3]byte{9, 9, 9}, "multicast") // stale
	g := s.Due(t0.Add(time.Second), bothDests)
	if len(g) != 1 || len(g[0].Dests) != 2 {
		t.Fatalf("stale ack not ignored: %+v", g)
	}

	s.Ack(k, first.XID, "multicast")
	g = s.Due(t0.Add(3*time.Second), bothDests)
	if len(g) != 1 || !slices.Equal(g[0].Dests, []string{"unicast:[2001:db8::53]:547"}) {
		t.Fatalf("got %+v", g)
	}

	// Fresh cycle: ack both, no retransmits.
	s2 := New(testParams())
	s2.Update(t0, []addrsrc.Addr{a})
	f := s2.Due(t0, bothDests)[0]
	s2.Ack(k, f.XID, "multicast")
	s2.Ack(k, f.XID, "unicast:[2001:db8::53]:547")
	if g := s2.Due(t0.Add(time.Second), bothDests); len(g) != 0 {
		t.Fatalf("got %+v", g)
	}
	n, _ := s2.Next()
	if !n.Equal(t0.Add(time.Hour)) {
		t.Fatalf("next %v", n)
	}
}

func TestRefreshInterval(t *testing.T) {
	p := testParams()
	static := mkAddr(86400)
	static.Origin = addrsrc.OriginStatic
	h8 := p
	h8.Heartbeat = 8 * time.Hour
	tests := []struct {
		name string
		p    Params
		a    addrsrc.Addr
		want time.Duration
	}{
		{"cap", p, mkAddr(86400), time.Hour},
		{"600", p, mkAddr(600), 480 * time.Second},
		{"floor", p, mkAddr(5), 10 * time.Second},
		{"infinity", p, mkAddr(dhcp6.Infinity), time.Hour},
		{"static", p, static, time.Hour},
		{"infinity 8h heartbeat", h8, mkAddr(dhcp6.Infinity), 4 * time.Hour},
	}
	for _, tc := range tests {
		if got := tc.p.RefreshInterval(tc.a, t0); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestRetransmitCarriesUpdatedLifetimes(t *testing.T) {
	s := New(testParams())
	s.Update(t0, []addrsrc.Addr{mkAddr(600)})
	s.Due(t0, bothDests)
	s.Due(t0.Add(time.Second), bothDests)
	g := s.Due(t0.Add(3*time.Second), bothDests)
	if len(g) != 1 || g[0].Addr.Valid != 597 || g[0].Addr.Preferred != 597 {
		t.Fatalf("got %+v", g)
	}
}

func TestLifetimeChangeOverOnePercentReschedules(t *testing.T) {
	s := New(testParams())
	a := mkAddr(86400)
	k := keyOfAddr(a)
	s.Update(t0, []addrsrc.Addr{a})
	f := s.Due(t0, bothDests)[0]
	s.Ack(k, f.XID, "multicast")
	s.Ack(k, f.XID, "unicast:[2001:db8::53]:547")

	now := t0.Add(60 * time.Second)
	b := mkAddr(86400)
	b.ObservedAt = now
	s.Update(now, []addrsrc.Addr{b})
	if g := s.Due(now, bothDests); len(g) != 0 {
		t.Fatalf("small change rescheduled: %+v", g)
	}

	c := mkAddr(3600)
	c.ObservedAt = now
	s.Update(now, []addrsrc.Addr{c})
	g := s.Due(now, bothDests)
	if len(g) != 1 || g[0].XID == f.XID || g[0].Try != 1 {
		t.Fatalf("got %+v", g)
	}
}

func TestInfiniteFiniteChangeCounts(t *testing.T) {
	s := New(testParams())
	s.Update(t0, []addrsrc.Addr{mkAddr(dhcp6.Infinity)})
	s.Due(t0, bothDests)
	s.Update(t0, []addrsrc.Addr{mkAddr(86400)})
	if g := s.Due(t0, bothDests); len(g) != 1 || g[0].Try != 1 {
		t.Fatalf("got %+v", g)
	}
}

func TestUnchangedUpdateKeepsXID(t *testing.T) {
	s := New(testParams())
	a := mkAddr(86400)
	s.Update(t0, []addrsrc.Addr{a})
	f := s.Due(t0, bothDests)[0]
	s.Update(t0.Add(time.Second), []addrsrc.Addr{a})
	g := s.Due(t0.Add(time.Second), bothDests)
	if len(g) != 1 || g[0].XID != f.XID || g[0].Try != 2 {
		t.Fatalf("got %+v", g)
	}
}

func TestRemovedKeysReturned(t *testing.T) {
	s := New(testParams())
	a := mkAddr(86400)
	b := mkAddr(86400)
	b.Addr = netip.MustParseAddr("2001:db8::2")
	s.Update(t0, []addrsrc.Addr{a, b})
	rem := s.Update(t0, []addrsrc.Addr{b})
	if len(rem) != 1 || rem[0] != keyOfAddr(a) || s.Len() != 1 {
		t.Fatalf("rem %v len %d", rem, s.Len())
	}
	s.Forget(keyOfAddr(b))
	if s.Len() != 0 {
		t.Fatal("forget")
	}
	if _, ok := s.Next(); ok {
		t.Fatal("next on empty")
	}
}
