package dhcp6

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Infinity is the "infinite" lifetime value (RFC 8415 §7.7).
const Infinity uint32 = 0xffffffff

// IAAddress is the payload of OPTION_IAADDR (5).
type IAAddress struct {
	Addr      netip.Addr
	Preferred uint32
	Valid     uint32
	Options   Options
}

// ParseIAAddress decodes an IA Address option payload.
func ParseIAAddress(data []byte) (IAAddress, error) {
	if len(data) < 24 {
		return IAAddress{}, ErrTruncated
	}
	opts, err := ParseOptions(data[24:])
	if err != nil {
		return IAAddress{}, err
	}
	return IAAddress{
		Addr:      netip.AddrFrom16([16]byte(data[0:16])),
		Preferred: binary.BigEndian.Uint32(data[16:20]),
		Valid:     binary.BigEndian.Uint32(data[20:24]),
		Options:   opts,
	}, nil
}

// Marshal encodes the IA Address payload.
func (a IAAddress) Marshal() ([]byte, error) {
	if !a.Addr.Is6() {
		return nil, fmt.Errorf("dhcp6: IA address %v is not IPv6", a.Addr)
	}
	x := a.Addr.As16()
	b := make([]byte, 0, 24)
	b = append(b, x[:]...)
	b = binary.BigEndian.AppendUint32(b, a.Preferred)
	b = binary.BigEndian.AppendUint32(b, a.Valid)
	return a.Options.AppendTo(b)
}
