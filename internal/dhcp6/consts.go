// Package dhcp6 encodes and decodes the subset of DHCPv6 (RFC 8415) and
// RFC 9686 (address registration) used by ipv6-ra-logger.
package dhcp6

import "net/netip"

// Message types.
const (
	MsgReply              uint8 = 7
	MsgInformationRequest uint8 = 11
	MsgRelayForw          uint8 = 12
	MsgRelayRepl          uint8 = 13
	MsgAddrRegInform      uint8 = 36 // RFC 9686
	MsgAddrRegReply       uint8 = 37 // RFC 9686
)

// Option codes.
const (
	OptClientID            uint16 = 1
	OptServerID            uint16 = 2
	OptIAAddr              uint16 = 5
	OptORO                 uint16 = 6
	OptElapsedTime         uint16 = 8
	OptRelayMsg            uint16 = 9
	OptUserClass           uint16 = 15
	OptVendorClass         uint16 = 16
	OptInterfaceID         uint16 = 18
	OptClientFQDN          uint16 = 39  // RFC 4704
	OptClientLinkLayerAddr uint16 = 79  // RFC 6939
	OptAddrRegEnable       uint16 = 148 // RFC 9686
)

// UDP ports (RFC 8415 §7.2).
const (
	ClientPort = 546
	ServerPort = 547
)

// AllRelayAgentsAndServers is ff02::1:2.
var AllRelayAgentsAndServers = netip.MustParseAddr("ff02::1:2")
