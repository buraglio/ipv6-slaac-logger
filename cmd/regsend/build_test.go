package main

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

func baseParams() params {
	a := netip.MustParseAddr("2001:db8:10::100")
	return params{Addr: a, IAAddr: a, DUID: []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}, Valid: 86400, Preferred: 14400, PEN: 67611, IfName: "veth-h"}
}

func TestBuildInformDefault(t *testing.T) {
	pkt, ia, err := buildInform(baseParams(), [3]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	m, err := dhcp6.ParseMessage(pkt)
	if err != nil || m.Type != dhcp6.MsgAddrRegInform || m.Options.Count(dhcp6.OptClientID) != 1 || m.Options.Count(dhcp6.OptIAAddr) != 1 {
		t.Fatalf("message %+v %v", m, err)
	}
	o, _ := m.Options.Get(dhcp6.OptIAAddr)
	if !bytes.Equal(o.Data, ia) {
		t.Fatal("returned iaData does not match the message")
	}
}

func TestBuildInformAgentAndHost(t *testing.T) {
	p := baseParams()
	p.Agent, p.Host, p.MAC = true, "h1.example.com", net.HardwareAddr{2, 0, 0, 0, 0, 1}
	pkt, _, err := buildInform(p, [3]byte{})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dhcp6.ParseMessage(pkt)
	vo, ok := m.Options.Get(dhcp6.OptVendorClass)
	if !ok {
		t.Fatal("vendor class missing")
	}
	vc, _ := dhcp6.ParseVendorClass(vo.Data)
	if vc.Enterprise != 67611 || !strings.HasPrefix(string(vc.Data[0]), "slaac-logger-agent/") || string(vc.Data[len(vc.Data)-1]) != "mac=02:00:00:00:00:01" {
		t.Fatalf("vendor class %+v", vc)
	}
	if _, ok := m.Options.Get(dhcp6.OptClientFQDN); !ok {
		t.Fatal("fqdn missing")
	}
}

func TestMutations(t *testing.T) {
	check := map[string]func(*dhcp6.Message, error) bool{
		"no-client-id": func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptClientID) == 0 },
		"server-id":    func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptServerID) == 1 },
		"oro":          func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptORO) == 1 },
		"two-ia":       func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptIAAddr) == 2 },
		"truncate":     func(m *dhcp6.Message, err error) bool { return err != nil },
	}
	for name, ok := range check {
		p := baseParams()
		p.Mutate = name
		pkt, _, err := buildInform(p, [3]byte{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ok(dhcp6.ParseMessage(pkt)) {
			t.Errorf("%s: mutation not applied", name)
		}
	}
	p := baseParams()
	p.Mutate = "explode"
	if _, _, err := buildInform(p, [3]byte{}); err == nil {
		t.Error("unknown mutation accepted")
	}
}

func TestCheckReply(t *testing.T) {
	ia := []byte{1, 2, 3}
	good, _ := (&dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: [3]byte{1, 1, 1}, Options: dhcp6.Options{{Code: dhcp6.OptIAAddr, Data: ia}}}).Marshal()
	if desc, ok := checkReply(good, dhcp6.MsgAddrRegReply, [3]byte{1, 1, 1}, ia); !ok || !strings.Contains(desc, "type=37") {
		t.Fatalf("good reply: %s %v", desc, ok)
	}
	if _, ok := checkReply(good, dhcp6.MsgAddrRegReply, [3]byte{9, 9, 9}, ia); ok {
		t.Fatal("xid mismatch accepted")
	}
	info, _ := (&dhcp6.Message{Type: dhcp6.MsgReply, Options: dhcp6.Options{{Code: dhcp6.OptAddrRegEnable}}}).Marshal()
	if desc, ok := checkReply(info, dhcp6.MsgReply, [3]byte{}, nil); !ok || !strings.Contains(desc, "addr_reg_enable=true") {
		t.Fatalf("info reply: %s %v", desc, ok)
	}
	if _, ok := checkReply([]byte{1}, dhcp6.MsgReply, [3]byte{}, nil); ok {
		t.Fatal("garbage accepted")
	}
}
