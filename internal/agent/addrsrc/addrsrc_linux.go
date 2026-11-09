//go:build linux

package addrsrc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type netlinkSource struct{}

// New returns the platform address source (rtnetlink).
func New() Source { return netlinkSource{} }

// List dumps the kernel's IPv6 addresses with RTM_GETADDR.
func (netlinkSource) List() ([]Addr, error) {
	// x/sys/unix has no RIB dump helper; the frozen syscall package does.
	rib, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_INET6)
	if err != nil {
		return nil, fmt.Errorf("addrsrc: RTM_GETADDR: %w", err)
	}
	names := map[int]string{}
	return parseAddrMsgs(rib, time.Now(), func(idx int) string {
		n, ok := names[idx]
		if !ok {
			if ifi, err := net.InterfaceByIndex(idx); err == nil {
				n = ifi.Name
			}
			names[idx] = n
		}
		return n
	})
}

// Watch subscribes to RTMGRP_IPV6_IFADDR and signals once per datagram.
func (netlinkSource) Watch(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("addrsrc: netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_IPV6_IFADDR}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("addrsrc: netlink bind: %w", err)
	}
	tv := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("addrsrc: SO_RCVTIMEO: %w", err)
	}
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		defer unix.Close(fd)
		buf := make([]byte, 64<<10)
		for ctx.Err() == nil {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			switch {
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR), errors.Is(err, unix.ENOBUFS):
				// Timeout, interrupt or overrun; an overrun still means a change.
				if errors.Is(err, unix.ENOBUFS) {
					signal(ch)
				}
				continue
			case err != nil:
				return
			case n > 0:
				signal(ch)
			}
		}
	}()
	return ch, nil
}
