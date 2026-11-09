//go:build !windows

package sender

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// reuse sets SO_REUSEADDR and SO_REUSEPORT so several sockets can share the
// client port on different addresses.
func reuse(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func isAddrNotAvail(err error) bool { return errors.Is(err, syscall.EADDRNOTAVAIL) }
