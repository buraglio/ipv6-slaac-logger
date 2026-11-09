//go:build darwin

package duid

import (
	"errors"
	"os"

	"howett.net/plist"
)

const darwinDUIDPlist = "/var/db/dhcpclient/DUID_IA.plist"

// OSDUID reads the macOS DHCPv6 client DUID property list.
func OSDUID() ([]byte, error) {
	b, err := os.ReadFile(darwinDUIDPlist)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var v struct {
		DUID []byte `plist:"DUID"`
	}
	if _, err := plist.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if len(v.DUID) == 0 {
		return nil, ErrNotFound
	}
	return v.DUID, nil
}
