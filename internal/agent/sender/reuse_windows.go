//go:build windows

package sender

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// reuse sets SO_REUSEADDR so several sockets can share the client port.
func reuse(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func isAddrNotAvail(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
