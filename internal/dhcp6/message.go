package dhcp6

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrRelay is returned by ParseMessage when given a relay message.
var ErrRelay = errors.New("dhcp6: relay message")

// Message is a client/server DHCPv6 message.
type Message struct {
	Type    uint8
	XID     [3]byte
	Options Options
}

// IsRelayType reports whether t is Relay-Forward or Relay-Reply.
func IsRelayType(t uint8) bool { return t == MsgRelayForw || t == MsgRelayRepl }

// ParseMessage decodes a client/server message.
func ParseMessage(b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, ErrTruncated
	}
	if IsRelayType(b[0]) {
		return nil, ErrRelay
	}
	opts, err := ParseOptions(b[4:])
	if err != nil {
		return nil, err
	}
	m := &Message{Type: b[0], Options: opts}
	copy(m.XID[:], b[1:4])
	return m, nil
}

// Marshal encodes m.
func (m *Message) Marshal() ([]byte, error) {
	return m.Options.AppendTo([]byte{m.Type, m.XID[0], m.XID[1], m.XID[2]})
}

// RelayMessage is a Relay-Forward or Relay-Reply message.
type RelayMessage struct {
	Type     uint8
	HopCount uint8
	LinkAddr netip.Addr
	PeerAddr netip.Addr
	Options  Options
}

// ParseRelay decodes a relay message.
func ParseRelay(b []byte) (*RelayMessage, error) {
	if len(b) < 34 {
		return nil, ErrTruncated
	}
	if !IsRelayType(b[0]) {
		return nil, fmt.Errorf("dhcp6: type %d is not a relay message", b[0])
	}
	opts, err := ParseOptions(b[34:])
	if err != nil {
		return nil, err
	}
	return &RelayMessage{
		Type:     b[0],
		HopCount: b[1],
		LinkAddr: netip.AddrFrom16([16]byte(b[2:18])),
		PeerAddr: netip.AddrFrom16([16]byte(b[18:34])),
		Options:  opts,
	}, nil
}

// Marshal encodes r.
func (r *RelayMessage) Marshal() ([]byte, error) {
	if !r.LinkAddr.Is6() || !r.PeerAddr.Is6() {
		return nil, fmt.Errorf("dhcp6: relay addresses must be IPv6 (link %v, peer %v)", r.LinkAddr, r.PeerAddr)
	}
	b := make([]byte, 0, 34)
	b = append(b, r.Type, r.HopCount)
	la, pa := r.LinkAddr.As16(), r.PeerAddr.As16()
	b = append(b, la[:]...)
	b = append(b, pa[:]...)
	return r.Options.AppendTo(b)
}
