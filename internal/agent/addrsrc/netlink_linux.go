//go:build linux

package addrsrc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
	"golang.org/x/sys/unix"
)

// ifaProto is IFA_PROTO from <linux/if_addr.h> (not in x/sys/unix).
const ifaProto = 11

var errTruncated = errors.New("addrsrc: truncated netlink message")

func nlAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

// parseAddrMsgs parses a stream of netlink messages and returns the IPv6
// addresses carried by its RTM_NEWADDR messages. Parsing stops at NLMSG_DONE.
// names maps an interface index to its name.
func parseAddrMsgs(b []byte, now time.Time, names func(int) string) ([]Addr, error) {
	var out []Addr
	for len(b) > 0 {
		if len(b) < unix.SizeofNlMsghdr {
			return nil, errTruncated
		}
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		typ := binary.NativeEndian.Uint16(b[4:6])
		if l < unix.SizeofNlMsghdr || l > len(b) {
			return nil, errTruncated
		}
		body := b[unix.SizeofNlMsghdr:l]
		b = b[min(nlAlign(l), len(b)):]
		switch typ {
		case unix.NLMSG_DONE:
			return out, nil
		case unix.NLMSG_ERROR:
			if len(body) < 4 {
				return nil, errTruncated
			}
			if e := int32(binary.NativeEndian.Uint32(body)); e != 0 {
				return nil, fmt.Errorf("addrsrc: netlink: %w", syscall.Errno(-e))
			}
			continue
		case unix.RTM_NEWADDR:
		default:
			continue
		}
		a, ok, err := parseAddrMsg(body, now, names)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// parseAddrMsg parses one RTM_NEWADDR body (ifaddrmsg + attributes). ok is
// false for non-IPv6 messages and messages without an address.
func parseAddrMsg(body []byte, now time.Time, names func(int) string) (a Addr, ok bool, err error) {
	if len(body) < unix.SizeofIfAddrmsg {
		return Addr{}, false, errTruncated
	}
	family, plen, flags := body[0], body[1], uint32(body[2])
	index := int(binary.NativeEndian.Uint32(body[4:8]))
	var (
		address, local []byte
		proto          uint8
		pref, valid    = dhcp6.Infinity, dhcp6.Infinity
	)
	attrs := body[unix.SizeofIfAddrmsg:]
	for len(attrs) > 0 {
		if len(attrs) < unix.SizeofRtAttr {
			return Addr{}, false, errTruncated
		}
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		typ := binary.NativeEndian.Uint16(attrs[2:4]) &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)
		if l < unix.SizeofRtAttr || l > len(attrs) {
			return Addr{}, false, errTruncated
		}
		data := attrs[unix.SizeofRtAttr:l]
		attrs = attrs[min(nlAlign(l), len(attrs)):]
		switch typ {
		case unix.IFA_ADDRESS:
			if len(data) == 16 {
				address = data
			}
		case unix.IFA_LOCAL:
			if len(data) == 16 {
				local = data
			}
		case unix.IFA_FLAGS:
			if len(data) >= 4 {
				flags = binary.NativeEndian.Uint32(data)
			}
		case unix.IFA_CACHEINFO:
			if len(data) >= 8 {
				pref = binary.NativeEndian.Uint32(data[0:4])
				valid = binary.NativeEndian.Uint32(data[4:8])
			}
		case ifaProto:
			if len(data) >= 1 {
				proto = data[0]
			}
		}
	}
	if family != unix.AF_INET6 {
		return Addr{}, false, nil
	}
	if local != nil {
		address = local
	}
	if address == nil {
		return Addr{}, false, nil
	}
	origin, state := ClassifyLinux(flags, proto, plen, valid)
	return Addr{
		Addr:       netip.AddrFrom16([16]byte(address)),
		IfName:     names(index),
		IfIndex:    index,
		Origin:     origin,
		Preferred:  pref,
		Valid:      valid,
		State:      state,
		ObservedAt: now,
	}, true, nil
}
