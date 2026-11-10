package sniffer

import (
	"net"
	"net/netip"
	"testing"

	"github.com/buraglio/ipv6-slaac-logger/internal/nd"
)

func TestObservations(t *testing.T) {
	host := mustMAC(t, hostMAC)
	other := mustMAC(t, "00:11:22:33:44:55")
	zero := mustMAC(t, "00:00:00:00:00:00")
	mcast := mustMAC(t, "33:33:00:00:00:01")
	gua, ll := netip.MustParseAddr(hostGUA), netip.MustParseAddr(hostLL)
	unspec := netip.IPv6Unspecified()

	tests := []struct {
		name string
		p    nd.Packet
		want []Observation
	}{
		{"dad ns", nd.Packet{Type: nd.TypeNS, SrcMAC: host, Src: unspec, Target: gua, VLAN: 7},
			[]Observation{{host, gua, "eth0", 7, KindDAD}}},
		{"ns with slla", nd.Packet{Type: nd.TypeNS, SrcMAC: host, Src: ll, Target: gua, LLAddr: other},
			[]Observation{{other, ll, "eth0", 0, KindNS}}},
		{"ns without slla", nd.Packet{Type: nd.TypeNS, SrcMAC: host, Src: ll, Target: gua}, nil},
		{"na with tlla", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Src: ll, Target: gua, LLAddr: other},
			[]Observation{{other, gua, "eth0", 0, KindNA}}},
		{"na without tlla", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Src: ll, Target: gua},
			[]Observation{{host, gua, "eth0", 0, KindNA}}},
		{"rs with slla", nd.Packet{Type: nd.TypeRS, SrcMAC: host, Src: ll, LLAddr: other},
			[]Observation{{other, ll, "eth0", 0, KindRS}}},
		{"rs unspecified source", nd.Packet{Type: nd.TypeRS, SrcMAC: host, Src: unspec, LLAddr: other}, nil},
		{"rs without slla", nd.Packet{Type: nd.TypeRS, SrcMAC: host, Src: ll}, nil},
		{"ra", nd.Packet{Type: nd.TypeRA, SrcMAC: host, Src: ll, LLAddr: other, RA: &nd.RA{}}, nil},
		{"na unspecified target", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Src: ll, Target: unspec}, nil},
		{"na multicast target", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Target: netip.MustParseAddr("ff02::1")}, nil},
		{"na loopback target", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Target: netip.IPv6Loopback()}, nil},
		{"dad multicast srcmac", nd.Packet{Type: nd.TypeNS, SrcMAC: mcast, Src: unspec, Target: gua}, nil},
		{"na zero tlla", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Target: gua, LLAddr: zero}, nil},
		{"na broadcast tlla", nd.Packet{Type: nd.TypeNA, SrcMAC: host, Target: gua, LLAddr: net.HardwareAddr{255, 255, 255, 255, 255, 255}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Observations(tc.p, "eth0")
			if len(got) != len(tc.want) {
				t.Fatalf("got %d observations, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				g, w := got[i], tc.want[i]
				if g.MAC.String() != w.MAC.String() || g.Addr != w.Addr || g.Link != w.Link || g.VLAN != w.VLAN || g.Kind != w.Kind {
					t.Errorf("obs %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}
