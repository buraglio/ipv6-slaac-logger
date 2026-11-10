package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

type params struct {
	Addr, IAAddr     netip.Addr
	DUID             []byte
	Valid, Preferred uint32
	Host             string
	Agent            bool
	PEN              uint32
	IfName           string
	MAC              net.HardwareAddr
	Mutate           string
}

var mutations = []string{"no-client-id", "server-id", "oro", "two-ia", "truncate"}

// buildInform returns the encoded ADDR-REG-INFORM and its IA Address payload.
func buildInform(p params, xid [3]byte) ([]byte, []byte, error) {
	ia := dhcp6.IAAddress{Addr: p.IAAddr, Preferred: p.Preferred, Valid: p.Valid}
	iaData, err := ia.Marshal()
	if err != nil {
		return nil, nil, err
	}
	var extra []dhcp6.Option
	if p.Agent {
		data := [][]byte{[]byte("slaac-logger-agent/regsend"), []byte("os=" + runtime.GOOS), []byte("if=" + p.IfName)}
		if len(p.MAC) > 0 {
			data = append(data, []byte("mac="+p.MAC.String()))
		}
		vc, err := dhcp6.VendorClass{Enterprise: p.PEN, Data: data}.Marshal()
		if err != nil {
			return nil, nil, err
		}
		extra = append(extra, dhcp6.Option{Code: dhcp6.OptVendorClass, Data: vc})
	}
	if p.Host != "" {
		f, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, p.Host)
		if err != nil {
			return nil, nil, err
		}
		extra = append(extra, dhcp6.Option{Code: dhcp6.OptClientFQDN, Data: f})
	}
	m, err := dhcp6.NewAddrRegInform(xid, p.DUID, ia, extra...)
	if err != nil {
		return nil, nil, err
	}
	switch p.Mutate {
	case "", "truncate":
	case "no-client-id":
		m.Options = m.Options[1:] // Client ID is always first
	case "server-id":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 0xde, 0xad}})
	case "oro":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}})
	case "two-ia":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptIAAddr, Data: iaData})
	default:
		return nil, nil, fmt.Errorf("unknown -mutate %q (valid: %s)", p.Mutate, strings.Join(mutations, ", "))
	}
	b, err := m.Marshal()
	if err != nil {
		return nil, nil, err
	}
	if p.Mutate == "truncate" {
		b = b[:len(b)-5]
	}
	return b, iaData, nil
}

// buildInfoRequest returns an Information-Request asking for option 148.
func buildInfoRequest(duid []byte, xid [3]byte) ([]byte, error) {
	m := &dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: xid, Options: dhcp6.Options{
		{Code: dhcp6.OptClientID, Data: duid},
		{Code: dhcp6.OptORO, Data: []byte{0, 0x94}},
	}}
	return m.Marshal()
}

// checkReply describes b and reports whether it is the expected reply.
func checkReply(b []byte, wantType uint8, xid [3]byte, iaData []byte) (string, bool) {
	m, err := dhcp6.ParseMessage(b)
	if err != nil {
		return fmt.Sprintf("unparseable reply: %v", err), false
	}
	desc := fmt.Sprintf("reply: type=%d xid=%x", m.Type, m.XID)
	ok := m.Type == wantType && m.XID == xid
	switch wantType {
	case dhcp6.MsgAddrRegReply:
		o, has := m.Options.Get(dhcp6.OptIAAddr)
		echo := has && bytes.Equal(o.Data, iaData)
		desc += fmt.Sprintf(" ia_echo=%t", echo)
		ok = ok && echo
	case dhcp6.MsgReply:
		_, has := m.Options.Get(dhcp6.OptAddrRegEnable)
		desc += fmt.Sprintf(" addr_reg_enable=%t", has)
		ok = ok && has
	}
	return desc, ok
}
