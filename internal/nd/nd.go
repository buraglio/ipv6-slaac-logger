// Package nd decodes IPv6 Neighbor Discovery (RFC 4861) frames: Router
// Solicitation, Router Advertisement, Neighbor Solicitation and Neighbor
// Advertisement. It is portable pure Go with no OS-specific code.
package nd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// ICMPv6 message types.
const (
	TypeRS uint8 = 133
	TypeRA uint8 = 134
	TypeNS uint8 = 135
	TypeNA uint8 = 136
)

// Neighbor Advertisement flags.
const (
	NAFlagRouter    uint8 = 0x80
	NAFlagSolicited uint8 = 0x40
	NAFlagOverride  uint8 = 0x20
)

// Prefix is one Prefix Information option of a Router Advertisement.
type Prefix struct {
	Prefix           netip.Prefix
	OnLink           bool
	Autonomous       bool
	Valid, Preferred uint32
}

// RA holds the Router Advertisement specific fields.
type RA struct {
	Managed, Other bool
	RouterLifetime uint16
	Prefixes       []Prefix
}

// Packet is a decoded Neighbor Discovery frame.
type Packet struct {
	SrcMAC, DstMAC net.HardwareAddr
	VLAN           uint16 // 0 = untagged
	Src, Dst       netip.Addr
	Type           uint8
	Target         netip.Addr       // NS/NA only
	LLAddr         net.HardwareAddr // SLLA (RS/RA/NS) or TLLA (NA); nil when absent
	NAFlags        uint8            // R=0x80 S=0x40 O=0x20 (NA only)
	RA             *RA              // RA only
}

var (
	ErrNotND     = errors.New("nd: not a neighbor discovery packet")
	ErrMalformed = errors.New("nd: malformed")
)

const (
	etherIPv6  = 0x86dd
	etherVLAN  = 0x8100
	etherQinQ  = 0x88a8
	protoICMP6 = 58
)

// Parse decodes an Ethernet frame. auxVLAN is the tag from PACKET_AUXDATA (0 if
// none); when nonzero it wins over an in-frame tag.
func Parse(frame []byte, auxVLAN uint16) (Packet, error) {
	var p Packet
	if len(frame) < 14 {
		return p, ErrMalformed
	}
	p.DstMAC = net.HardwareAddr(bytes.Clone(frame[0:6]))
	p.SrcMAC = net.HardwareAddr(bytes.Clone(frame[6:12]))
	off := 12
	et := binary.BigEndian.Uint16(frame[off:])
	off += 2
	var inFrame uint16
	for tags := 0; et == etherVLAN || et == etherQinQ; tags++ {
		if tags == 2 {
			return p, ErrNotND
		}
		if len(frame) < off+4 {
			return p, ErrMalformed
		}
		if tags == 0 {
			inFrame = binary.BigEndian.Uint16(frame[off:]) & 0x0fff
		}
		et = binary.BigEndian.Uint16(frame[off+2:])
		off += 4
	}
	if et != etherIPv6 {
		return p, ErrNotND
	}
	p.VLAN = inFrame
	if auxVLAN != 0 {
		p.VLAN = auxVLAN
	}

	ip := frame[off:]
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return p, ErrMalformed
	}
	plen := int(binary.BigEndian.Uint16(ip[4:6]))
	if plen > len(ip)-40 {
		return p, ErrMalformed
	}
	if ip[6] != protoICMP6 {
		return p, ErrNotND
	}
	if ip[7] != 255 {
		return p, ErrMalformed
	}
	p.Src = netip.AddrFrom16([16]byte(ip[8:24]))
	p.Dst = netip.AddrFrom16([16]byte(ip[24:40]))
	msg := ip[40 : 40+plen]

	if len(msg) < 4 {
		return p, ErrNotND
	}
	p.Type = msg[0]
	if p.Type < TypeRS || p.Type > TypeNA {
		return p, ErrNotND
	}
	if msg[1] != 0 {
		return p, ErrMalformed
	}
	if checksum(ip[8:24], ip[24:40], msg) != 0 {
		return p, ErrMalformed
	}

	var optOff int
	switch p.Type {
	case TypeRS:
		optOff = 8
	case TypeRA:
		optOff = 16
	default:
		optOff = 24
	}
	if len(msg) < optOff {
		return p, ErrMalformed
	}

	switch p.Type {
	case TypeRA:
		p.RA = &RA{
			Managed:        msg[5]&0x80 != 0,
			Other:          msg[5]&0x40 != 0,
			RouterLifetime: binary.BigEndian.Uint16(msg[6:8]),
		}
	case TypeNS, TypeNA:
		p.Target = netip.AddrFrom16([16]byte(msg[8:24]))
		if p.Target.IsMulticast() {
			return p, ErrMalformed
		}
		if p.Type == TypeNA {
			p.NAFlags = msg[4] & 0xe0
		}
	}

	if err := parseOptions(&p, msg[optOff:]); err != nil {
		return p, err
	}

	if p.Type == TypeNS && p.Src.IsUnspecified() {
		if !IsSolicitedNode(p.Dst) || p.LLAddr != nil {
			return p, ErrMalformed
		}
	}
	return p, nil
}

func parseOptions(p *Packet, b []byte) error {
	llType := byte(1) // SLLA
	if p.Type == TypeNA {
		llType = 2 // TLLA
	}
	for len(b) > 0 {
		if len(b) < 2 || b[1] == 0 {
			return ErrMalformed
		}
		n := int(b[1]) * 8
		if n > len(b) {
			return ErrMalformed
		}
		o := b[:n]
		switch o[0] {
		case 1, 2:
			if o[1] != 1 {
				return ErrMalformed
			}
			if o[0] == llType && p.LLAddr == nil {
				p.LLAddr = net.HardwareAddr(bytes.Clone(o[2:8]))
			}
		case 3:
			if o[1] != 4 {
				return ErrMalformed
			}
			if p.Type != TypeRA {
				break
			}
			bits := int(o[2])
			addr := netip.AddrFrom16([16]byte(o[16:32]))
			pfx, err := addr.Prefix(bits)
			if err != nil {
				return ErrMalformed
			}
			p.RA.Prefixes = append(p.RA.Prefixes, Prefix{
				Prefix:     pfx,
				OnLink:     o[3]&0x80 != 0,
				Autonomous: o[3]&0x40 != 0,
				Valid:      binary.BigEndian.Uint32(o[4:8]),
				Preferred:  binary.BigEndian.Uint32(o[8:12]),
			})
		}
		b = b[n:]
	}
	return nil
}

// checksum returns the ones-complement sum over the IPv6 pseudo-header and msg
// (including its checksum field); a valid message yields 0.
func checksum(src, dst, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	sum += uint32(len(msg)>>16) + uint32(len(msg)&0xffff)
	sum += protoICMP6
	add(msg)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// IsSolicitedNode reports whether a is a solicited-node multicast address
// (ff02::1:ffXX:XXXX).
func IsSolicitedNode(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() {
		return false
	}
	b := a.As16()
	return bytes.Equal(b[:13], []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff})
}
