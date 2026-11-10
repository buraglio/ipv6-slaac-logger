// Package serverid persists the collector's DHCPv6 Server Identifier.
package serverid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

const fileName = "server-duid"

// LoadOrCreate returns the DUID stored in dir, creating a random DUID-UUID on
// first use. A corrupt file is an error rather than being silently replaced.
func LoadOrCreate(dir string) ([]byte, error) {
	path := filepath.Join(dir, fileName)
	b, err := os.ReadFile(path)
	if err == nil {
		d, perr := dhcp6.ParseHex(strings.TrimSpace(string(b)))
		if perr != nil || len(d) < 2 {
			return nil, fmt.Errorf("serverid: %s is corrupt; remove it to generate a new server DUID", path)
		}
		return d, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("serverid: %w", err)
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return nil, err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // UUID version 4
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	d := dhcp6.NewDUIDUUID(u)
	tmp, err := os.CreateTemp(dir, ".server-duid-*")
	if err != nil {
		return nil, fmt.Errorf("serverid: %w", err)
	}
	if _, err := tmp.WriteString(dhcp6.FormatHex(d) + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("serverid: %w", err)
	}
	return d, nil
}
