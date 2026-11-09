// Package registrar implements the RFC 9686 server side: it validates
// ADDR-REG-INFORM messages, maintains bindings, and builds ADDR-REG-REPLY.
package registrar

import (
	"net"
	"net/netip"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// How a registration reached the collector.
const (
	ViaMulticast = "multicast"
	ViaUnicast   = "unicast"
	ViaRelay     = "relay"
)

// RelayInfo is taken from the innermost Relay-Forward.
type RelayInfo struct {
	LinkAddr    netip.Addr
	PeerAddr    netip.Addr
	InterfaceID []byte
	CLLAO       net.HardwareAddr
}

// Request is one decoded ADDR-REG-INFORM plus how it arrived.
type Request struct {
	Msg    *dhcp6.Message
	Src    netip.AddrPort // UDP source of the packet (relay agent when Via == ViaRelay)
	IfName string
	Via    string
	Relay  *RelayInfo
}
