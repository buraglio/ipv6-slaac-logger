package dhcp6

import (
	"encoding/binary"
	"fmt"
)

// VendorClass is the payload of OPTION_VENDOR_CLASS (16).
type VendorClass struct {
	Enterprise uint32
	Data       [][]byte
}

// ParseVendorClass decodes a Vendor Class option payload.
func ParseVendorClass(data []byte) (VendorClass, error) {
	if len(data) < 4 {
		return VendorClass{}, ErrTruncated
	}
	vc := VendorClass{Enterprise: binary.BigEndian.Uint32(data[0:4])}
	b := data[4:]
	for len(b) > 0 {
		if len(b) < 2 {
			return VendorClass{}, ErrTruncated
		}
		n := int(binary.BigEndian.Uint16(b[0:2]))
		if len(b) < 2+n {
			return VendorClass{}, ErrTruncated
		}
		d := make([]byte, n)
		copy(d, b[2:2+n])
		vc.Data = append(vc.Data, d)
		b = b[2+n:]
	}
	return vc, nil
}

// Marshal encodes the Vendor Class payload.
func (vc VendorClass) Marshal() ([]byte, error) {
	b := binary.BigEndian.AppendUint32(nil, vc.Enterprise)
	for _, d := range vc.Data {
		if len(d) > 0xffff {
			return nil, fmt.Errorf("dhcp6: vendor class data too long (%d bytes)", len(d))
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(d)))
		b = append(b, d...)
	}
	return b, nil
}
