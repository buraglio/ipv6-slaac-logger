package dhcp6

import (
	"errors"
	"strings"
)

// FQDNFlagN asks the server not to perform DNS updates (RFC 4704).
const FQDNFlagN uint8 = 0x04

// ErrBadFQDN is returned for malformed or unsafe Client FQDN payloads.
var ErrBadFQDN = errors.New("dhcp6: malformed FQDN")

// ParseFQDN decodes an OPTION_CLIENT_FQDN (39) payload. Labels must be printable
// ASCII (0x21-0x7e) so names can never inject control characters into logs.
func ParseFQDN(data []byte) (uint8, string, error) {
	if len(data) < 1 {
		return 0, "", ErrTruncated
	}
	flags := data[0]
	b := data[1:]
	var labels []string
	total := 0
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 {
			if len(b) != 1 {
				return 0, "", ErrBadFQDN
			}
			break
		}
		if n > 63 || len(b) < 1+n {
			return 0, "", ErrBadFQDN
		}
		label := b[1 : 1+n]
		if !printable(label) {
			return 0, "", ErrBadFQDN
		}
		total += n + 1
		if total > 255 {
			return 0, "", ErrBadFQDN
		}
		labels = append(labels, string(label))
		b = b[1+n:]
	}
	return flags, strings.Join(labels, "."), nil
}

// EncodeFQDN encodes flags and a fully qualified name.
func EncodeFQDN(flags uint8, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	b := []byte{flags}
	if name == "" {
		return b, nil
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 || !printable([]byte(l)) {
			return nil, ErrBadFQDN
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	if len(b)-1 > 255 {
		return nil, ErrBadFQDN
	}
	return b, nil
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
