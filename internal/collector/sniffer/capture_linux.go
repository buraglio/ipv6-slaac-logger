//go:build linux

package sniffer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type afPacket struct {
	fd int
}

// htons converts a host-order uint16 to network order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Open opens a promiscuous AF_PACKET socket on ifname with the ND BPF filter attached.
func Open(ifname string) (FrameSource, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	raw, err := Filter()
	if err != nil {
		return nil, err
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}

	proto := htons(unix.ETH_P_ALL)
	// Protocol 0 at socket(): a nonzero protocol makes the socket receive from
	// every interface immediately, before the filter is attached and before bind.
	// With 0 nothing is received until bind supplies the protocol and interface.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("sniffer: socket: %w", err)
	}
	fail := func(what string, err error) (FrameSource, error) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("sniffer: %s: %w", what, err)
	}
	// Attach the filter before bind so no unfiltered frames are queued.
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fail("attach filter", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		return fail("auxdata", err)
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
		&unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_PROMISC}); err != nil {
		return fail("promisc", err)
	}
	tv := unix.NsecToTimeval(int64(1e9))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("rcvtimeo", err)
	}
	return &afPacket{fd: fd}, nil
}

func (a *afPacket) ReadFrame(buf []byte) (int, uint16, error) {
	oob := make([]byte, 64)
	for {
		n, oobn, _, _, err := unix.Recvmsg(a.fd, buf, oob, 0)
		switch {
		case err == nil:
			return n, parseAuxVLAN(oob[:oobn]), nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return 0, 0, os.ErrDeadlineExceeded
		default:
			return 0, 0, err
		}
	}
}

func (a *afPacket) Close() error { return unix.Close(a.fd) }

// parseAuxVLAN returns the VLAN ID from a PACKET_AUXDATA control message, or 0
// unless TP_STATUS_VLAN_VALID is set.
func parseAuxVLAN(oob []byte) uint16 {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_PACKET || m.Header.Type != unix.PACKET_AUXDATA {
			continue
		}
		if len(m.Data) < int(unsafe.Sizeof(unix.TpacketAuxdata{})) {
			continue
		}
		aux := (*unix.TpacketAuxdata)(unsafe.Pointer(&m.Data[0]))
		if aux.Status&unix.TP_STATUS_VLAN_VALID == 0 {
			return 0
		}
		return aux.Vlan_tci & 0x0fff
	}
	return 0
}
