package nd

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func mustMAC(t testing.TB, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// frame builds an Ethernet frame carrying an IPv6 packet with the given ICMPv6
// message. The ICMPv6 checksum field (bytes 2-3 of icmp) is recomputed.
func frame(t testing.TB, ethSrc, ethDst string, vlans []uint16, ipSrc, ipDst string, hop uint8, icmp []byte) []byte {
	t.Helper()
	src, dst := netip.MustParseAddr(ipSrc), netip.MustParseAddr(ipDst)
	icmp = append([]byte(nil), icmp...)
	icmp[2], icmp[3] = 0, 0
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s16, d16 := src.As16(), dst.As16()
	add(s16[:])
	add(d16[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(icmp)))
	add(l[:])
	add([]byte{0, 0, 0, 58})
	add(icmp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(icmp[2:4], ^uint16(sum))

	var f []byte
	f = append(f, mustMAC(t, ethDst)...)
	f = append(f, mustMAC(t, ethSrc)...)
	for i, v := range vlans {
		tpid := uint16(0x8100)
		if i == 0 && len(vlans) == 2 {
			tpid = 0x88a8
		}
		f = binary.BigEndian.AppendUint16(f, tpid)
		f = binary.BigEndian.AppendUint16(f, v)
	}
	f = binary.BigEndian.AppendUint16(f, 0x86dd)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6] = 58
	ip[7] = hop
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	f = append(f, ip...)
	return append(f, icmp...)
}

func ns(target string, opts ...byte) []byte {
	b := make([]byte, 24)
	b[0] = 135
	t := netip.MustParseAddr(target).As16()
	copy(b[8:], t[:])
	return append(b, opts...)
}

func na(flags byte, target string, opts ...byte) []byte {
	b := make([]byte, 24)
	b[0] = 136
	b[4] = flags
	t := netip.MustParseAddr(target).As16()
	copy(b[8:], t[:])
	return append(b, opts...)
}

func llopt(typ byte, mac string) []byte {
	m, _ := net.ParseMAC(mac)
	return append([]byte{typ, 1}, m...)
}

func pfxopt(prefix string, plen, flags byte, valid, pref uint32) []byte {
	b := make([]byte, 32)
	b[0], b[1], b[2], b[3] = 3, 4, plen, flags
	binary.BigEndian.PutUint32(b[4:8], valid)
	binary.BigEndian.PutUint32(b[8:12], pref)
	a := netip.MustParseAddr(prefix).As16()
	copy(b[16:], a[:])
	return b
}

func raMsg(flags byte, lifetime uint16, opts ...[]byte) []byte {
	b := make([]byte, 16)
	b[0] = 134
	b[5] = flags
	binary.BigEndian.PutUint16(b[6:8], lifetime)
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}

const (
	hostMAC   = "5c:1e:9a:3b:21:aa"
	routerMAC = "00:11:22:33:44:55"
	hostLL    = "fe80::5e1e:9aff:fe3b:21aa"
	hostGUA   = "2001:db8::5c1e:9aff:fe3b:21aa"
	solNode   = "ff02::1:ff3b:21aa"
	allNodes  = "ff02::1"
	allRtrs   = "ff02::2"
)

func validFrames(t testing.TB) map[string][]byte {
	return map[string][]byte{
		"dad":     frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, "::", solNode, 255, ns(hostGUA)),
		"ns-slla": frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, hostLL, solNode, 255, ns(hostGUA, llopt(1, hostMAC)...)),
		"na-tlla": frame(t, hostMAC, "33:33:00:00:00:01", nil, hostLL, allNodes, 255, na(0x60, hostGUA, llopt(2, hostMAC)...)),
		"rs":      frame(t, hostMAC, "33:33:00:00:00:02", nil, hostLL, allRtrs, 255, append([]byte{133, 0, 0, 0, 0, 0, 0, 0}, llopt(1, hostMAC)...)),
		"ra":      frame(t, routerMAC, "33:33:00:00:00:01", nil, "fe80::211:22ff:fe33:4455", allNodes, 255, raMsg(0x80, 1800, pfxopt("2001:db8:10::", 64, 0xc0, 2592000, 604800), pfxopt("2001:db8:20::", 64, 0x80, 100, 50), llopt(1, routerMAC))),
		"vlan":    frame(t, hostMAC, "33:33:ff:3b:21:aa", []uint16{20}, "::", solNode, 255, ns(hostGUA)),
		"qinq":    frame(t, hostMAC, "33:33:ff:3b:21:aa", []uint16{100, 20}, "::", solNode, 255, ns(hostGUA)),
	}
}

func TestParseDADNS(t *testing.T) {
	p, err := Parse(validFrames(t)["dad"], 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeNS || p.Target != netip.MustParseAddr(hostGUA) {
		t.Fatalf("got %+v", p)
	}
	if p.LLAddr != nil {
		t.Fatalf("LLAddr = %v", p.LLAddr)
	}
	if p.SrcMAC.String() != hostMAC || p.DstMAC.String() != "33:33:ff:3b:21:aa" {
		t.Fatalf("macs %v %v", p.SrcMAC, p.DstMAC)
	}
	if p.Src != netip.IPv6Unspecified() || p.Dst != netip.MustParseAddr(solNode) || p.VLAN != 0 {
		t.Fatalf("got %+v", p)
	}
}

func TestParseNSWithSLLA(t *testing.T) {
	p, err := Parse(validFrames(t)["ns-slla"], 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeNS || p.LLAddr.String() != hostMAC || p.Src != netip.MustParseAddr(hostLL) {
		t.Fatalf("got %+v", p)
	}
}

func TestParseNAWithTLLA(t *testing.T) {
	p, err := Parse(validFrames(t)["na-tlla"], 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeNA || p.NAFlags != 0x60 || p.LLAddr.String() != hostMAC || p.Target != netip.MustParseAddr(hostGUA) {
		t.Fatalf("got %+v", p)
	}
}

func TestParseRS(t *testing.T) {
	p, err := Parse(validFrames(t)["rs"], 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeRS || p.LLAddr.String() != hostMAC || p.RA != nil {
		t.Fatalf("got %+v", p)
	}
}

func TestParseRA(t *testing.T) {
	p, err := Parse(validFrames(t)["ra"], 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeRA || p.RA == nil {
		t.Fatalf("got %+v", p)
	}
	if !p.RA.Managed || p.RA.Other || p.RA.RouterLifetime != 1800 {
		t.Fatalf("ra %+v", p.RA)
	}
	if p.LLAddr.String() != routerMAC {
		t.Fatalf("lladdr %v", p.LLAddr)
	}
	want := []Prefix{
		{Prefix: netip.MustParsePrefix("2001:db8:10::/64"), OnLink: true, Autonomous: true, Valid: 2592000, Preferred: 604800},
		{Prefix: netip.MustParsePrefix("2001:db8:20::/64"), OnLink: true, Valid: 100, Preferred: 50},
	}
	if len(p.RA.Prefixes) != 2 || p.RA.Prefixes[0] != want[0] || p.RA.Prefixes[1] != want[1] {
		t.Fatalf("prefixes %+v", p.RA.Prefixes)
	}
}

func TestParseRAPrefixMasked(t *testing.T) {
	f := frame(t, routerMAC, "33:33:00:00:00:01", nil, "fe80::1", allNodes, 255,
		raMsg(0x40, 0, pfxopt("2001:db8:10:0:1::5", 64, 0x40, 1, 1)))
	p, err := Parse(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.RA.Prefixes[0].Prefix.String(); got != "2001:db8:10::/64" {
		t.Fatalf("got %s", got)
	}
	if !p.RA.Other || p.RA.Managed || !p.RA.Prefixes[0].Autonomous || p.RA.Prefixes[0].OnLink {
		t.Fatalf("flags %+v", p.RA)
	}
}

func TestParseVLAN(t *testing.T) {
	fr := validFrames(t)
	tests := []struct {
		name string
		f    []byte
		aux  uint16
		want uint16
	}{
		{"in-frame", fr["vlan"], 0, 20},
		{"aux", fr["dad"], 30, 30},
		{"qinq", fr["qinq"], 0, 100},
		{"aux wins", fr["vlan"], 7, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse(tt.f, tt.aux)
			if err != nil {
				t.Fatal(err)
			}
			if p.VLAN != tt.want {
				t.Fatalf("VLAN = %d, want %d", p.VLAN, tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	good := ns(hostGUA)
	mut := func(b []byte, f func(b []byte)) []byte {
		b = append([]byte(nil), b...)
		f(b)
		return b
	}
	mk := func(icmp []byte) []byte {
		return frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, hostLL, solNode, 255, icmp)
	}

	badSum := mk(good)
	badSum[14+40+2] ^= 0xff
	longLen := mk(good)
	binary.BigEndian.PutUint16(longLen[14+4:], 500)
	nh0 := mk(good)
	nh0[14+6] = 0
	v4 := mk(good)
	binary.BigEndian.PutUint16(v4[12:], 0x0800)
	ver := mk(good)
	ver[14] = 0x40

	tests := []struct {
		name string
		f    []byte
		want error
	}{
		{"hop limit 64", frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, hostLL, solNode, 64, good), ErrMalformed},
		{"bad checksum", badSum, ErrMalformed},
		{"code 1", mk(mut(good, func(b []byte) { b[1] = 1 })), ErrMalformed},
		{"option length 0", mk(append(append([]byte(nil), good...), 1, 0, 0, 0, 0, 0, 0, 0)), ErrMalformed},
		{"option overrun", mk(append(append([]byte(nil), good...), 1, 2, 0, 0, 0, 0, 0, 0)), ErrMalformed},
		{"multicast target NS", mk(ns("ff02::1")), ErrMalformed},
		{"multicast target NA", mk(na(0x20, "ff02::1")), ErrMalformed},
		{"DAD NS to all-nodes", frame(t, hostMAC, "33:33:00:00:00:01", nil, "::", allNodes, 255, good), ErrMalformed},
		{"DAD NS with SLLA", frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, "::", solNode, 255, ns(hostGUA, llopt(1, hostMAC)...)), ErrMalformed},
		{"echo request", mk([]byte{128, 0, 0, 0, 0, 1, 0, 1}), ErrNotND},
		{"ipv4", v4, ErrNotND},
		{"three vlan tags", frame(t, hostMAC, "33:33:ff:3b:21:aa", []uint16{1, 2, 3}, hostLL, solNode, 255, good), ErrNotND},
		{"payload length beyond frame", longLen, ErrMalformed},
		{"next header 0", nh0, ErrNotND},
		{"bad ip version", ver, ErrMalformed},
		{"short ethernet", []byte{1, 2, 3}, ErrMalformed},
		{"short ns body", mk([]byte{135, 0, 0, 0, 0, 0, 0, 0}), ErrMalformed},
		{"short ra body", frame(t, routerMAC, "33:33:00:00:00:01", nil, "fe80::1", allNodes, 255, []byte{134, 0, 0, 0, 0, 0, 0, 0}), ErrMalformed},
		{"prefix option wrong length", frame(t, routerMAC, "33:33:00:00:00:01", nil, "fe80::1", allNodes, 255, raMsg(0, 0, append([]byte{3, 2}, make([]byte, 14)...))), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.f, 0)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseAllowsEthernetPadding(t *testing.T) {
	f := append(validFrames(t)["dad"], make([]byte, 20)...)
	p, err := Parse(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeNS {
		t.Fatalf("got %+v", p)
	}
}

func TestIsSolicitedNode(t *testing.T) {
	for a, want := range map[string]bool{
		"ff02::1:ff3b:21aa": true,
		"ff02::1:ff00:0":    true,
		"ff02::1":           false,
		"ff05::1:ff3b:21aa": false,
		"ff02::2:ff3b:21aa": false,
		"fe80::1":           false,
		"2001:db8::1":       false,
	} {
		if got := IsSolicitedNode(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s = %v, want %v", a, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, b := range validFrames(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b, 0)
	})
}
