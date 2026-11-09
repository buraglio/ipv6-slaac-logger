//go:build !windows

package sender

import "net"

// listenBusy binds addr without any reuse option, making the port busy for a
// later SO_REUSEPORT bind.
func listenBusy(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp6", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp6", a)
}
