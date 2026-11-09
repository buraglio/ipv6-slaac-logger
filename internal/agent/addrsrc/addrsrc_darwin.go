//go:build darwin

package addrsrc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// <netinet6/in6_var.h>, verified against the macOS 26 SDK.
const (
	siocGIFAFlagIn6     = 0xc1206949 // SIOCGIFAFLAG_IN6
	siocGIFALifetimeIn6 = 0xc1206951 // SIOCGIFALIFETIME_IN6
)

// in6Ifreq is struct in6_ifreq (288 bytes): the interface name followed by a
// union that holds a sockaddr_in6 on input and the flags or lifetimes on output.
type in6Ifreq struct {
	name [unix.IFNAMSIZ]byte
	ifru [272]byte
}

var _ [288]byte = [unsafe.Sizeof(in6Ifreq{})]byte{}

type darwinSource struct{}

// New returns the platform address source (in6 ioctls + PF_ROUTE).
func New() Source { return darwinSource{} }

// List enumerates IPv6 addresses with net.Interfaces and reads each one's
// flags and lifetimes with SIOCGIFAFLAG_IN6 / SIOCGIFALIFETIME_IN6.
func (darwinSource) List() ([]Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("addrsrc: interfaces: %w", err)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("addrsrc: socket: %w", err)
	}
	unix.CloseOnExec(fd)
	defer unix.Close(fd)
	var out []Addr
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue // interface vanished
		}
		for _, ia := range addrs {
			ipn, ok := ia.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !ip.Is6() {
				continue
			}
			ip = ip.WithZone("")
			now := time.Now()
			r := newIn6Ifreq(ifi, ip)
			if ioctl(fd, siocGIFAFlagIn6, &r) != nil {
				continue // address went away between the listing and the ioctl
			}
			flags := binary.NativeEndian.Uint32(r.ifru[0:4])
			r = newIn6Ifreq(ifi, ip)
			if ioctl(fd, siocGIFALifetimeIn6, &r) != nil {
				continue
			}
			expire := int64(binary.NativeEndian.Uint64(r.ifru[0:8]))
			preferred := int64(binary.NativeEndian.Uint64(r.ifru[8:16]))
			origin, state := ClassifyDarwin(flags)
			out = append(out, Addr{
				Addr:       ip,
				IfName:     ifi.Name,
				IfIndex:    ifi.Index,
				Origin:     origin,
				Preferred:  DarwinRemaining(preferred, now),
				Valid:      DarwinRemaining(expire, now),
				State:      state,
				ObservedAt: now,
			})
		}
	}
	return out, nil
}

// newIn6Ifreq builds a request naming ifi and carrying ip as a sockaddr_in6.
func newIn6Ifreq(ifi net.Interface, ip netip.Addr) in6Ifreq {
	var r in6Ifreq
	copy(r.name[:unix.IFNAMSIZ-1], ifi.Name)
	r.ifru[0] = unix.SizeofSockaddrInet6 // sin6_len
	r.ifru[1] = unix.AF_INET6            // sin6_family
	a := ip.As16()
	copy(r.ifru[8:24], a[:]) // sin6_addr
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		binary.NativeEndian.PutUint32(r.ifru[24:28], uint32(ifi.Index)) // sin6_scope_id
	}
	return r
}

func ioctl(fd int, req uintptr, r *in6Ifreq) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(r))); e != 0 {
		return e
	}
	return nil
}

// Watch reads the PF_ROUTE socket and signals on RTM_NEWADDR / RTM_DELADDR.
func (darwinSource) Watch(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("addrsrc: route socket: %w", err)
	}
	unix.CloseOnExec(fd)
	tv := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("addrsrc: SO_RCVTIMEO: %w", err)
	}
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		defer unix.Close(fd)
		buf := make([]byte, 2048)
		for ctx.Err() == nil {
			n, err := unix.Read(fd, buf)
			switch {
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
				continue // timeout: re-check ctx
			case err != nil:
				return
			case n >= 4 && (buf[3] == unix.RTM_NEWADDR || buf[3] == unix.RTM_DELADDR):
				signal(ch)
			}
		}
	}()
	return ch, nil
}
