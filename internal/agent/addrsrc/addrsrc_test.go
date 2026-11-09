package addrsrc

import (
	"net/netip"
	"testing"
)

func TestEligible(t *testing.T) {
	tests := []struct {
		name string
		a    Addr
		want bool
	}{
		{"gua slaac", Addr{Addr: netip.MustParseAddr("2001:db8::1"), Origin: OriginSLAAC}, true},
		{"ula static", Addr{Addr: netip.MustParseAddr("fd00::1"), Origin: OriginStatic}, true},
		{"temporary", Addr{Addr: netip.MustParseAddr("2001:db8::2"), Origin: OriginTemporary}, true},
		{"link-local", Addr{Addr: netip.MustParseAddr("fe80::1"), Origin: OriginSLAAC}, false},
		{"loopback", Addr{Addr: netip.MustParseAddr("::1"), Origin: OriginStatic}, false},
		{"multicast", Addr{Addr: netip.MustParseAddr("ff02::1"), Origin: OriginStatic}, false},
		{"v4-mapped", Addr{Addr: netip.MustParseAddr("::ffff:192.0.2.1"), Origin: OriginStatic}, false},
		{"dhcpv6", Addr{Addr: netip.MustParseAddr("2001:db8::3"), Origin: OriginDHCPv6}, false},
		{"other", Addr{Addr: netip.MustParseAddr("2001:db8::4"), Origin: OriginOther}, false},
		{"not ready", Addr{Addr: netip.MustParseAddr("2001:db8::5"), Origin: OriginSLAAC, State: StateNotReady}, false},
		{"duplicate", Addr{Addr: netip.MustParseAddr("2001:db8::6"), Origin: OriginSLAAC, State: StateDuplicate}, false},
		{"zero addr", Addr{Origin: OriginSLAAC}, false},
	}
	for _, tt := range tests {
		if got := Eligible(tt.a); got != tt.want {
			t.Errorf("%s: Eligible = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIfFilter(t *testing.T) {
	f := IfFilter{Include: []string{"en*"}, Exclude: []string{"en9"}}
	for name, want := range map[string]bool{"en0": true, "en9": false, "utun0": false} {
		if got := f.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	var z IfFilter
	for _, n := range []string{"en0", "utun0", "lo0"} {
		if !z.Match(n) {
			t.Errorf("zero filter should match %q", n)
		}
	}
}

func TestSelectSortsAndFilters(t *testing.T) {
	mk := func(ip, ifn string, idx int, o Origin) Addr {
		return Addr{Addr: netip.MustParseAddr(ip), IfName: ifn, IfIndex: idx, Origin: o}
	}
	all := []Addr{
		mk("2001:db8::2", "en1", 5, OriginSLAAC),
		mk("2001:db8::9", "en0", 4, OriginSLAAC),
		mk("2001:db8::1", "en0", 4, OriginStatic),
		mk("fe80::1", "en0", 4, OriginSLAAC),
		mk("2001:db8::3", "en0", 4, OriginDHCPv6),
		mk("2001:db8::4", "utun0", 9, OriginSLAAC),
		mk("2001:db8::5", "en9", 12, OriginSLAAC),
	}
	got := Select(all, IfFilter{Include: []string{"en*"}, Exclude: []string{"en9"}})
	want := []string{"2001:db8::1", "2001:db8::9", "2001:db8::2"}
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Addr.String() != w {
			t.Errorf("got[%d] = %s, want %s", i, got[i].Addr, w)
		}
	}
}
