// Package sender builds and transmits RFC 9686 ADDR-REG-INFORM messages and
// probes for server support of OPTION_ADDR_REG_ENABLE.
package sender

import (
	"net"
	"runtime"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// Info identifies the agent in the Vendor Class and FQDN options.
type Info struct {
	Version  string
	Hostname string
	PEN      uint32
}

// BuildInform returns the encoded ADDR-REG-INFORM for a. mac may be nil, in
// which case no "mac=" string is included.
func BuildInform(xid [3]byte, duid []byte, a addrsrc.Addr, mac net.HardwareAddr, info Info) ([]byte, error) {
	data := [][]byte{
		[]byte("slaac-logger-agent/" + info.Version),
		[]byte("os=" + runtime.GOOS),
		[]byte("if=" + a.IfName),
	}
	if len(mac) == 6 {
		data = append(data, []byte("mac="+mac.String()))
	}
	vc, err := dhcp6.VendorClass{Enterprise: info.PEN, Data: data}.Marshal()
	if err != nil {
		return nil, err
	}
	extra := []dhcp6.Option{{Code: dhcp6.OptVendorClass, Data: vc}}
	if f, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, info.Hostname); err == nil {
		extra = append(extra, dhcp6.Option{Code: dhcp6.OptClientFQDN, Data: f})
	}
	ia := dhcp6.IAAddress{Addr: a.Addr, Preferred: a.Preferred, Valid: a.Valid}
	m, err := dhcp6.NewAddrRegInform(xid, duid, ia, extra...)
	if err != nil {
		return nil, err
	}
	return m.Marshal()
}
