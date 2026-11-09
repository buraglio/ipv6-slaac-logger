//go:build linux

package duid

import "os"

var dhclientLeaseFiles = []string{
	"/var/lib/dhcp/dhclient6.leases",
	"/var/lib/dhclient/dhclient6.leases",
}

// OSDUID reads dhclient's default-duid from its DHCPv6 leases file.
func OSDUID() ([]byte, error) {
	var permErr error
	for _, p := range dhclientLeaseFiles {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsPermission(err) {
				permErr = err
			}
			continue
		}
		return ParseDhclientDUID(string(b))
	}
	if permErr != nil {
		return nil, permErr
	}
	return nil, ErrNotFound
}
