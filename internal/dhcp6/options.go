package dhcp6

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrTruncated is returned when input ends before a declared length.
var ErrTruncated = errors.New("dhcp6: truncated")

// Option is one DHCPv6 option. Data excludes the 4-byte code/length header.
type Option struct {
	Code uint16
	Data []byte
}

// Options is an ordered option list. Duplicates are preserved.
type Options []Option

// ParseOptions decodes a sequence of options. Option data is copied, so the
// result never aliases b.
func ParseOptions(b []byte) (Options, error) {
	var opts Options
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, ErrTruncated
		}
		code := binary.BigEndian.Uint16(b[0:2])
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+n {
			return nil, ErrTruncated
		}
		data := make([]byte, n)
		copy(data, b[4:4+n])
		opts = append(opts, Option{Code: code, Data: data})
		b = b[4+n:]
	}
	return opts, nil
}

// AppendTo appends the wire encoding of o to dst.
func (o Options) AppendTo(dst []byte) ([]byte, error) {
	for _, opt := range o {
		if len(opt.Data) > 0xffff {
			return nil, fmt.Errorf("dhcp6: option %d too long (%d bytes)", opt.Code, len(opt.Data))
		}
		dst = binary.BigEndian.AppendUint16(dst, opt.Code)
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(opt.Data)))
		dst = append(dst, opt.Data...)
	}
	return dst, nil
}

// Get returns the first option with the given code.
func (o Options) Get(code uint16) (Option, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt, true
		}
	}
	return Option{}, false
}

// Count returns how many options have the given code.
func (o Options) Count(code uint16) int {
	n := 0
	for _, opt := range o {
		if opt.Code == code {
			n++
		}
	}
	return n
}
