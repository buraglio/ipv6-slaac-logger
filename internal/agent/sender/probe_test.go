package sender

import (
	"net"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func mkMsg(t testing.TB, typ uint8, xid [3]byte, opts ...dhcp6.Option) []byte {
	t.Helper()
	b, err := (&dhcp6.Message{Type: typ, XID: xid, Options: opts}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReplyEnables(t *testing.T) {
	xid := [3]byte{9, 8, 7}
	en := dhcp6.Option{Code: dhcp6.OptAddrRegEnable}
	srv := dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 1}}
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"enabled", mkMsg(t, dhcp6.MsgReply, xid, srv, en), true},
		{"no 148", mkMsg(t, dhcp6.MsgReply, xid, srv), false},
		{"wrong xid", mkMsg(t, dhcp6.MsgReply, [3]byte{1, 1, 1}, srv, en), false},
		{"wrong type", mkMsg(t, dhcp6.MsgAddrRegReply, xid, en), false},
		{"garbage", []byte{7, 9, 8, 7, 0, 148, 0xff}, false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		if got := replyEnables(tc.b, xid); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func FuzzReplyEnables(f *testing.F) {
	f.Add(mkMsg(f, dhcp6.MsgReply, [3]byte{1, 2, 3}, dhcp6.Option{Code: dhcp6.OptAddrRegEnable}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { replyEnables(b, [3]byte{1, 2, 3}) })
}

func TestLinkLocal(t *testing.T) {
	v4 := &net.IPNet{IP: net.ParseIP("169.254.1.1"), Mask: net.CIDRMask(16, 32)} // 16-byte form
	v6 := &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}
	got, err := linkLocal([]net.Addr{v4, v6}, "en0")
	if err != nil || got.String() != "fe80::1%en0" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := linkLocal([]net.Addr{v4}, "en0"); err == nil {
		t.Fatal("want error for v4-only")
	}
}
