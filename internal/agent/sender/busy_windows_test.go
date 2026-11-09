//go:build windows

package sender

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (~SO_REUSEADDR), absent from x/sys/windows.
const soExclusiveAddrUse = -5

// listenBusy binds addr with SO_EXCLUSIVEADDRUSE so SO_REUSEADDR binds fail.
func listenBusy(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp6", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
