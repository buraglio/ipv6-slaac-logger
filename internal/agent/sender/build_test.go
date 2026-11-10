package sender

import (
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

func codes(m *dhcp6.Message) []uint16 {
	var c []uint16
	for _, o := range m.Options {
		c = append(c, o.Code)
	}
	return c
}

func testAddr() addrsrc.Addr {
	return addrsrc.Addr{Addr: netip.MustParseAddr("2001:db8::10"), IfName: "en0", Preferred: 1800, Valid: 3600}
}

func TestBuildInformShape(t *testing.T) {
	mac, _ := net.ParseMAC("5c:1e:9a:3b:21:aa")
	a := testAddr()
	b, err := BuildInform([3]byte{1, 2, 3}, []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}, a, mac, Info{Version: "test", Hostname: "host1", PEN: 67611})
	if err != nil {
		t.Fatal(err)
	}
	m, err := dhcp6.ParseMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != 36 {
		t.Fatalf("type %d", m.Type)
	}
	if got, want := codes(m), []uint16{1, 5, 16, 39}; !reflect.DeepEqual(got, want) {
		t.Fatalf("codes %v want %v", got, want)
	}
	o, _ := m.Options.Get(dhcp6.OptIAAddr)
	ia, err := dhcp6.ParseIAAddress(o.Data)
	if err != nil || ia.Addr != a.Addr || ia.Preferred != 1800 || ia.Valid != 3600 {
		t.Fatalf("ia %+v err %v", ia, err)
	}
	o, _ = m.Options.Get(dhcp6.OptVendorClass)
	vc, err := dhcp6.ParseVendorClass(o.Data)
	if err != nil || vc.Enterprise != 67611 {
		t.Fatalf("vc %+v err %v", vc, err)
	}
	var got []string
	for _, d := range vc.Data {
		got = append(got, string(d))
	}
	want := []string{"slaac-logger-agent/test", "os=" + runtime.GOOS, "if=en0", "mac=5c:1e:9a:3b:21:aa"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vendor data %q want %q", got, want)
	}
}

func TestBuildInformNoMAC(t *testing.T) {
	b, err := BuildInform([3]byte{}, []byte{1}, testAddr(), nil, Info{Version: "t", Hostname: "h", PEN: 67611})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dhcp6.ParseMessage(b)
	o, _ := m.Options.Get(dhcp6.OptVendorClass)
	vc, _ := dhcp6.ParseVendorClass(o.Data)
	if len(vc.Data) != 3 {
		t.Fatalf("vendor data %q", vc.Data)
	}
}

func TestBuildInformBadHostnameOmitsFQDN(t *testing.T) {
	b, err := BuildInform([3]byte{}, []byte{1}, testAddr(), nil, Info{Version: "t", Hostname: "bad host\n", PEN: 67611})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dhcp6.ParseMessage(b)
	if got, want := codes(m), []uint16{1, 5, 16}; !reflect.DeepEqual(got, want) {
		t.Fatalf("codes %v want %v", got, want)
	}
}
