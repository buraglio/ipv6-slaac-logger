//go:build windows

package duid

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// OSDUID reads the DHCPv6 DUID Windows stores in the Tcpip6 parameters key.
func OSDUID() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("Dhcpv6DUID")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}
