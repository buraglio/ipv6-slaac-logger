package registrar

import (
	"net"
	"net/netip"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

var (
	testAddr  = netip.MustParseAddr("2001:db8:10::5")
	testMAC   = net.HardwareAddr{0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa}
	testDUID  = dhcp6.NewDUIDLL(testMAC)
	otherDUID = dhcp6.NewDUIDLL(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99})
	onLink    = netip.MustParsePrefix("2001:db8:10::/64")
	relayAddr = netip.MustParseAddr("2001:db8:ffff::1")
	relayLink = netip.MustParseAddr("2001:db8:10::1")
)

func testPolicy() *PrefixPolicy {
	return &PrefixPolicy{
		OnLink:  func(string) []netip.Prefix { return []netip.Prefix{onLink} },
		Relay:   []netip.Prefix{onLink},
		Unicast: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
}

func inform(t *testing.T, addr netip.Addr, duid []byte, valid uint32, extra ...dhcp6.Option) *dhcp6.Message {
	t.Helper()
	pref := valid / 2
	if valid == dhcp6.Infinity {
		pref = dhcp6.Infinity
	}
	m, err := dhcp6.NewAddrRegInform([3]byte{1, 2, 3}, duid, dhcp6.IAAddress{Addr: addr, Preferred: pref, Valid: valid}, extra...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mcastReq(m *dhcp6.Message, src netip.Addr) *Request {
	return &Request{Msg: m, Src: netip.AddrPortFrom(src, 546), IfName: "eth0", Via: ViaMulticast}
}

func relayReq(m *dhcp6.Message, peer netip.Addr) *Request {
	return &Request{
		Msg: m, Src: netip.AddrPortFrom(relayAddr, 547), IfName: "eth0", Via: ViaRelay,
		Relay: &RelayInfo{LinkAddr: relayLink, PeerAddr: peer},
	}
}

func without(m *dhcp6.Message, code uint16) *dhcp6.Message {
	out := &dhcp6.Message{Type: m.Type, XID: m.XID}
	for _, o := range m.Options {
		if o.Code != code {
			out.Options = append(out.Options, o)
		}
	}
	return out
}

func with(m *dhcp6.Message, opts ...dhcp6.Option) *dhcp6.Message {
	out := &dhcp6.Message{Type: m.Type, XID: m.XID, Options: append(dhcp6.Options{}, m.Options...)}
	out.Options = append(out.Options, opts...)
	return out
}
