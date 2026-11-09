package duid

import (
	"errors"
	"fmt"
	"strings"
)

// ParseDhclientDUID returns the DUID from the last `default-duid "...";` line
// in a dhclient leases file, decoding \NNN octal, \\ and \" escapes.
func ParseDhclientDUID(leases string) ([]byte, error) {
	var last string
	found := false
	for _, line := range strings.Split(leases, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "default-duid")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, `"`) {
			continue
		}
		last, found = rest[1:], true
	}
	if !found {
		return nil, ErrNotFound
	}
	var out []byte
	for i := 0; i < len(last); i++ {
		c := last[i]
		switch {
		case c == '"':
			return out, nil
		case c == '\\':
			i++
			if i >= len(last) {
				return nil, errors.New("duid: dhclient: truncated escape")
			}
			e := last[i]
			if e >= '0' && e <= '7' {
				if i+2 >= len(last) {
					return nil, errors.New("duid: dhclient: truncated octal escape")
				}
				v := 0
				for k := 0; k < 3; k++ {
					d := last[i+k]
					if d < '0' || d > '7' {
						return nil, fmt.Errorf("duid: dhclient: bad octal escape %q", last[i:i+3])
					}
					v = v*8 + int(d-'0')
				}
				if v > 255 {
					return nil, fmt.Errorf("duid: dhclient: octal escape out of range %q", last[i:i+3])
				}
				out = append(out, byte(v))
				i += 2
			} else if e == '\\' || e == '"' {
				out = append(out, e)
			} else {
				return nil, fmt.Errorf("duid: dhclient: unknown escape \\%c", e)
			}
		case c >= 0x20 && c < 0x7f:
			out = append(out, c)
		default:
			return nil, fmt.Errorf("duid: dhclient: unexpected byte 0x%02x", c)
		}
	}
	return nil, errors.New("duid: dhclient: unterminated string")
}
