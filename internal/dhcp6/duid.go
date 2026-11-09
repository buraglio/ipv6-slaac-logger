package dhcp6

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DUID types (RFC 8415 §11, RFC 6355).
const (
	DUIDTypeLLT  uint16 = 1
	DUIDTypeEN   uint16 = 2
	DUIDTypeLL   uint16 = 3
	DUIDTypeUUID uint16 = 4

	HWTypeEthernet uint16 = 1
)

// DUIDTypeName returns "LLT", "EN", "LL", "UUID" or "unknown".
func DUIDTypeName(d []byte) string {
	if len(d) < 2 {
		return "unknown"
	}
	switch binary.BigEndian.Uint16(d[0:2]) {
	case DUIDTypeLLT:
		return "LLT"
	case DUIDTypeEN:
		return "EN"
	case DUIDTypeLL:
		return "LL"
	case DUIDTypeUUID:
		return "UUID"
	}
	return "unknown"
}

// MACFromDUID extracts the Ethernet MAC from a DUID-LLT or DUID-LL.
func MACFromDUID(d []byte) (net.HardwareAddr, bool) {
	if len(d) < 4 || binary.BigEndian.Uint16(d[2:4]) != HWTypeEthernet {
		return nil, false
	}
	switch binary.BigEndian.Uint16(d[0:2]) {
	case DUIDTypeLLT:
		if len(d) == 14 {
			return net.HardwareAddr(bytes.Clone(d[8:14])), true
		}
	case DUIDTypeLL:
		if len(d) == 10 {
			return net.HardwareAddr(bytes.Clone(d[4:10])), true
		}
	}
	return nil, false
}

// ParseCLLAO extracts an Ethernet MAC from OPTION_CLIENT_LINKLAYER_ADDR (79).
func ParseCLLAO(data []byte) (net.HardwareAddr, bool) {
	if len(data) != 8 || binary.BigEndian.Uint16(data[0:2]) != HWTypeEthernet {
		return nil, false
	}
	return net.HardwareAddr(bytes.Clone(data[2:8])), true
}

// FormatHex renders bytes as colon-separated lowercase hex ("00:03:ab").
func FormatHex(b []byte) string { return net.HardwareAddr(b).String() }

// ParseHex accepts colon-separated or plain hex.
func ParseHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dhcp6: bad hex %q: %w", s, err)
	}
	return b, nil
}

// NewDUIDLL builds a DUID-LL for an Ethernet MAC.
func NewDUIDLL(mac net.HardwareAddr) []byte {
	return append([]byte{0, 3, 0, 1}, mac...)
}

// NewDUIDUUID builds a DUID-UUID (RFC 6355).
func NewDUIDUUID(u [16]byte) []byte {
	return append([]byte{0, 4}, u[:]...)
}

// NewDUIDLLT builds a DUID-LLT for an Ethernet MAC; the time field is
// seconds since 2000-01-01T00:00:00Z modulo 2^32 (RFC 8415 §11.2).
func NewDUIDLLT(mac net.HardwareAddr, t time.Time) []byte {
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	d := make([]byte, 8, 8+len(mac))
	binary.BigEndian.PutUint16(d[0:2], DUIDTypeLLT)
	binary.BigEndian.PutUint16(d[2:4], HWTypeEthernet)
	binary.BigEndian.PutUint32(d[4:8], uint32(int64(t.Sub(epoch)/time.Second)))
	return append(d, mac...)
}
