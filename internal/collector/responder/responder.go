// Package responder answers DHCPv6 Information-Request with OPTION_ADDR_REG_ENABLE
// (148) on links that have no other DHCPv6 server, so RFC 9686 clients start registering.
package responder

import (
	"bytes"
	"encoding/binary"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// Responder builds Reply messages for Information-Request.
type Responder struct {
	ServerID []byte
}

// Handle returns a Reply, or nil when the request should be ignored: wrong
// type, addressed to another server, or not requesting option 148.
func (r *Responder) Handle(m *dhcp6.Message) *dhcp6.Message {
	if m == nil || m.Type != dhcp6.MsgInformationRequest {
		return nil
	}
	if s, ok := m.Options.Get(dhcp6.OptServerID); ok && !bytes.Equal(s.Data, r.ServerID) {
		return nil
	}
	oro, ok := m.Options.Get(dhcp6.OptORO)
	if !ok || !oroHas(oro.Data, dhcp6.OptAddrRegEnable) {
		return nil
	}
	opts := dhcp6.Options{{Code: dhcp6.OptServerID, Data: r.ServerID}}
	if c, ok := m.Options.Get(dhcp6.OptClientID); ok {
		opts = append(opts, c)
	}
	opts = append(opts, dhcp6.Option{Code: dhcp6.OptAddrRegEnable})
	return &dhcp6.Message{Type: dhcp6.MsgReply, XID: m.XID, Options: opts}
}

func oroHas(data []byte, code uint16) bool {
	for i := 0; i+1 < len(data); i += 2 {
		if binary.BigEndian.Uint16(data[i:]) == code {
			return true
		}
	}
	return false
}
