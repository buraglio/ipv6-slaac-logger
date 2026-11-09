package sniffer

import (
	"net"
	"net/netip"

	"github.com/buraglio/ipv6-ra-logger/internal/nd"
)

// Observation kinds.
const (
	KindDAD = "dad"
	KindNS  = "ns"
	KindNA  = "na"
	KindRS  = "rs"
)

// Observation is one MAC to address binding seen on the wire.
type Observation struct {
	MAC  net.HardwareAddr
	Addr netip.Addr
	Link string // interface name
	VLAN uint16
	Kind string
}

// Observations maps one ND packet to MAC/address observations per spec §5.5.
func Observations(p nd.Packet, link string) []Observation {
	var mac net.HardwareAddr
	var addr netip.Addr
	var kind string
	switch p.Type {
	case nd.TypeNS:
		if p.Src.IsUnspecified() {
			mac, addr, kind = p.SrcMAC, p.Target, KindDAD
		} else if len(p.LLAddr) > 0 {
			mac, addr, kind = p.LLAddr, p.Src, KindNS
		}
	case nd.TypeNA:
		mac, addr, kind = p.LLAddr, p.Target, KindNA
		if len(mac) == 0 {
			mac = p.SrcMAC
		}
	case nd.TypeRS:
		if !p.Src.IsUnspecified() && len(p.LLAddr) > 0 {
			mac, addr, kind = p.LLAddr, p.Src, KindRS
		}
	}
	if kind == "" || !validAddr(addr) || !validMAC(mac) {
		return nil
	}
	return []Observation{{MAC: mac, Addr: addr, Link: link, VLAN: p.VLAN, Kind: kind}}
}

func validAddr(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
}

func validMAC(m net.HardwareAddr) bool {
	if len(m) != 6 || m[0]&1 != 0 {
		return false
	}
	for _, b := range m {
		if b != 0 {
			return true
		}
	}
	return false
}
