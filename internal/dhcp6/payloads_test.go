package dhcp6

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

var testMAC = net.HardwareAddr{0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa}

func TestIAAddressRoundTrip(t *testing.T) {
	ia := IAAddress{Addr: netip.MustParseAddr("2001:db8:10::5"), Preferred: 3600, Valid: 7200}
	b, err := ia.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 24 {
		t.Fatalf("len = %d, want 24", len(b))
	}
	got, err := ParseIAAddress(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != ia.Addr || got.Preferred != 3600 || got.Valid != 7200 || len(got.Options) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseIAAddressTruncated(t *testing.T) {
	if _, err := ParseIAAddress(make([]byte, 23)); !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
}

func TestIAAddressMarshalRejectsIPv4(t *testing.T) {
	if _, err := (IAAddress{Addr: netip.MustParseAddr("192.0.2.1")}).Marshal(); err == nil {
		t.Fatal("expected error")
	}
}

func TestVendorClassRoundTrip(t *testing.T) {
	vc := VendorClass{Enterprise: 32473, Data: [][]byte{[]byte("ra-logger-agent/0.1"), []byte("os=linux")}}
	b, err := vc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseVendorClass(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enterprise != 32473 || len(got.Data) != 2 || string(got.Data[1]) != "os=linux" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseVendorClassTruncated(t *testing.T) {
	for _, in := range [][]byte{{0, 0, 0x7e}, {0, 0, 0x7e, 0xd9, 0, 5, 'a'}} {
		if _, err := ParseVendorClass(in); !errors.Is(err, ErrTruncated) {
			t.Errorf("%x: err = %v", in, err)
		}
	}
}

func TestFQDNRoundTrip(t *testing.T) {
	b, err := EncodeFQDN(FQDNFlagN, "host.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	flags, name, err := ParseFQDN(b)
	if err != nil {
		t.Fatal(err)
	}
	if flags != FQDNFlagN || name != "host.example.com" {
		t.Fatalf("got %x %q", flags, name)
	}
}

func TestFQDNRejectsHostileInput(t *testing.T) {
	cases := map[string][]byte{
		"newline in label": {0, 3, 'a', '\n', 'b', 0},
		"label too long":   append([]byte{0, 64}, bytes.Repeat([]byte{'a'}, 64)...),
		"trailing bytes":   {0, 1, 'a', 0, 1},
		"short label":      {0, 5, 'a'},
	}
	for name, in := range cases {
		if _, _, err := ParseFQDN(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := EncodeFQDN(0, "bad\nname"); err == nil {
		t.Error("EncodeFQDN accepted a control character")
	}
	if _, err := EncodeFQDN(0, strings.Repeat("a", 64)); err == nil {
		t.Error("EncodeFQDN accepted a 64-byte label")
	}
}

func TestMACFromDUID(t *testing.T) {
	ll := NewDUIDLL(testMAC)
	if mac, ok := MACFromDUID(ll); !ok || mac.String() != testMAC.String() {
		t.Errorf("LL: %v %v", mac, ok)
	}
	llt := append([]byte{0, 1, 0, 1, 0x2e, 0x5b, 0x11, 0x22}, testMAC...)
	if mac, ok := MACFromDUID(llt); !ok || mac.String() != testMAC.String() {
		t.Errorf("LLT: %v %v", mac, ok)
	}
	en := []byte{0, 2, 0, 0, 0x7e, 0xd9, 1, 2, 3}
	if _, ok := MACFromDUID(en); ok {
		t.Error("EN: should not yield a MAC")
	}
	nonEther := append([]byte{0, 3, 0, 6}, testMAC...)
	if _, ok := MACFromDUID(nonEther); ok {
		t.Error("non-Ethernet hwtype should not yield a MAC")
	}
	if DUIDTypeName(ll) != "LL" || DUIDTypeName(llt) != "LLT" || DUIDTypeName(en) != "EN" || DUIDTypeName([]byte{1}) != "unknown" {
		t.Error("DUIDTypeName mismatch")
	}
}

func TestParseCLLAO(t *testing.T) {
	if mac, ok := ParseCLLAO(append([]byte{0, 1}, testMAC...)); !ok || mac.String() != testMAC.String() {
		t.Errorf("got %v %v", mac, ok)
	}
	if _, ok := ParseCLLAO([]byte{0, 1, 2}); ok {
		t.Error("short CLLAO accepted")
	}
}

func TestHex(t *testing.T) {
	if s := FormatHex([]byte{0, 3, 0xab}); s != "00:03:ab" {
		t.Errorf("FormatHex = %q", s)
	}
	for _, in := range []string{"00:03:ab", "0003ab", " 00:03:AB "} {
		b, err := ParseHex(in)
		if err != nil || !bytes.Equal(b, []byte{0, 3, 0xab}) {
			t.Errorf("ParseHex(%q) = %x, %v", in, b, err)
		}
	}
	if _, err := ParseHex("zz"); err == nil {
		t.Error("ParseHex accepted non-hex")
	}
}

func TestNewAddrRegInformGolden(t *testing.T) {
	ia := IAAddress{Addr: netip.MustParseAddr("2001:db8:10::5"), Preferred: 3600, Valid: 7200}
	m, err := NewAddrRegInform([3]byte{1, 2, 3}, NewDUIDLL(testMAC), ia)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x24, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa,
		0x00, 0x05, 0x00, 0x18,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x1c, 0x20,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func FuzzParseIAAddress(f *testing.F) {
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		ia, err := ParseIAAddress(b)
		if err != nil {
			return
		}
		out, err := ia.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x %v", out, err)
		}
	})
}

func FuzzParseVendorClass(f *testing.F) {
	f.Add([]byte{0, 0, 0x7e, 0xd9, 0, 1, 'a'})
	f.Fuzz(func(t *testing.T, b []byte) {
		vc, err := ParseVendorClass(b)
		if err != nil {
			return
		}
		out, err := vc.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x %v", out, err)
		}
	})
}

func FuzzParseFQDN(f *testing.F) {
	f.Add([]byte{0, 4, 'h', 'o', 's', 't', 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, name, err := ParseFQDN(b)
		if err != nil {
			return
		}
		for _, c := range []byte(name) {
			if c < 0x21 || c > 0x7e {
				t.Fatalf("non-printable byte %#x in accepted name %q", c, name)
			}
		}
	})
}

func TestNewDUIDLLT(t *testing.T) {
	mac, _ := net.ParseMAC("5c:1e:9a:3b:21:aa")
	d := NewDUIDLLT(mac, time.Date(2000, 1, 1, 0, 1, 40, 0, time.UTC)) // 100 s after epoch
	want := []byte{0, 1, 0, 1, 0, 0, 0, 100, 0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa}
	if !bytes.Equal(d, want) {
		t.Fatalf("got % x", d)
	}
	if got, ok := MACFromDUID(d); !ok || got.String() != mac.String() {
		t.Fatal("MACFromDUID round trip")
	}
	if DUIDTypeName(d) != "LLT" {
		t.Fatal("type name")
	}
}

func TestNewInformationRequest(t *testing.T) {
	duid := NewDUIDLL(net.HardwareAddr{2, 0, 0, 0, 0, 1})
	m := NewInformationRequest([3]byte{1, 2, 3}, duid)
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != MsgInformationRequest || p.XID != [3]byte{1, 2, 3} {
		t.Fatalf("%+v", p)
	}
	codes := []uint16{}
	for _, o := range p.Options {
		codes = append(codes, o.Code)
	}
	if !slices.Equal(codes, []uint16{OptClientID, OptORO, OptElapsedTime}) {
		t.Fatalf("codes %v", codes)
	}
	if o, _ := p.Options.Get(OptORO); !bytes.Equal(o.Data, []byte{0, 0x94}) {
		t.Fatal("ORO")
	}
}
