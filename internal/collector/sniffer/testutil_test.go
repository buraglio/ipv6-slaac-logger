package sniffer

import (
	"encoding/binary"
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

func raMsg() []byte {
	b := make([]byte, 16)
	b[0] = 134
	return b
}

func rsMsg(opts ...byte) []byte {
	b := make([]byte, 8)
	b[0] = 133
	return append(b, opts...)
}

const (
	hostMAC = "5c:1e:9a:3b:21:aa"
	hostLL  = "fe80::5e1e:9aff:fe3b:21aa"
	hostGUA = "2001:db8::5c1e:9aff:fe3b:21aa"
)

// arpFrame builds an Ethernet ARP frame (op=2 reply by default) with the given
// VLAN tags, sender MAC, and sender IP. Target fields are zeroed.
func arpFrame(t testing.TB, vlans []uint16, senderMAC, senderIP string) []byte {
	t.Helper()
	return arpFrameRaw(t, vlans, 1, 0x0800, 2, senderMAC, senderIP)
}

// arpFrameRaw builds a raw ARP Ethernet frame with explicit hardware type,
// protocol type, and operation. Use hwType=1,protoType=0x0800 for normal IPv4-over-Ethernet ARP.
func arpFrameRaw(t testing.TB, vlans []uint16, hwType, protoType, op uint16, senderMAC, senderIP string) []byte {
	t.Helper()
	var f []byte
	f = append(f, mustMAC(t, "ff:ff:ff:ff:ff:ff")...) // dst
	f = append(f, mustMAC(t, senderMAC)...)            // src
	for i, v := range vlans {
		tpid := uint16(0x8100)
		if i == 0 && len(vlans) == 2 {
			tpid = 0x88a8
		}
		f = binary.BigEndian.AppendUint16(f, tpid)
		f = binary.BigEndian.AppendUint16(f, v)
	}
	f = binary.BigEndian.AppendUint16(f, 0x0806) // ethertype ARP
	// ARP payload (28 bytes for IPv4-over-Ethernet)
	f = binary.BigEndian.AppendUint16(f, hwType)    // hardware type
	f = binary.BigEndian.AppendUint16(f, protoType) // protocol type
	f = append(f, 6, 4)                             // hlen=6, plen=4
	f = binary.BigEndian.AppendUint16(f, op)        // operation
	smac, _ := net.ParseMAC(senderMAC)
	if smac == nil {
		smac = make(net.HardwareAddr, 6)
	}
	f = append(f, smac...)    // sender MAC
	ip := net.ParseIP(senderIP).To4()
	if ip == nil {
		ip = make([]byte, 4)
	}
	f = append(f, ip...)            // sender IP
	f = append(f, make([]byte, 10)...) // target MAC (6) + target IP (4)
	return f
}
