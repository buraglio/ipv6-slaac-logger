package sniffer

import (
	"net"
	"net/netip"
)

// ARPObservations parses an Ethernet ARP frame and returns at most one
// Observation (sender MAC → sender IP). It drops ARP probes (sender IP
// 0.0.0.0) and non-IPv4-over-Ethernet ARP (hardware type ≠ 1, protocol
// type ≠ 0x0800). The vlan argument is passed through from the socket
// auxdata; the frame itself may or may not carry a VLAN tag.
func ARPObservations(frame []byte, vlan uint16, link string) []Observation {
	// Minimum untagged ARP frame: 14 (Ethernet header) + 28 (ARP IPv4) = 42.
	// Tagged adds 4 bytes per tag. We detect the tag depth from the ethertype.
	if len(frame) < 42 {
		return nil
	}

	// Skip past any VLAN tags to find the ARP payload start.
	offset := 14 // start of payload for untagged frame
	et := uint16(frame[12])<<8 | uint16(frame[13])
	for et == 0x8100 || et == 0x88a8 {
		offset += 4
		if len(frame) < offset+28 {
			return nil
		}
		et = uint16(frame[offset-2])<<8 | uint16(frame[offset-1])
	}
	if et != 0x0806 {
		return nil
	}

	p := frame[offset:]
	if len(p) < 28 {
		return nil
	}

	hwType := uint16(p[0])<<8 | uint16(p[1])
	protoType := uint16(p[2])<<8 | uint16(p[3])
	if hwType != 1 || protoType != 0x0800 {
		return nil
	}

	op := uint16(p[6])<<8 | uint16(p[7])
	senderMAC := make(net.HardwareAddr, 6)
	copy(senderMAC, p[8:14])
	senderIP := netip.AddrFrom4([4]byte(p[14:18]))
	targetIP := netip.AddrFrom4([4]byte(p[24:28]))

	if senderIP.IsUnspecified() { // ARP probe
		return nil
	}

	var kind string
	switch {
	case senderIP == targetIP:
		kind = KindGARP
	case op == 2:
		kind = KindARPReply
	default:
		kind = KindARPRequest
	}

	return []Observation{{MAC: senderMAC, Addr: senderIP, Link: link, VLAN: vlan, Kind: kind}}
}
