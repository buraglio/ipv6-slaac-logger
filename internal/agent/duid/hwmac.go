package duid

import (
	"errors"
	"net"
	"sort"
)

// FirstHardwareMAC returns the MAC of the lowest-index non-loopback interface
// that has a 6-byte hardware address.
func FirstHardwareMAC() (net.HardwareAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Index < ifs[j].Index })
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 || len(ifi.HardwareAddr) != 6 {
			continue
		}
		return append(net.HardwareAddr(nil), ifi.HardwareAddr...), nil
	}
	return nil, errors.New("duid: no interface with a 6-byte hardware address")
}
