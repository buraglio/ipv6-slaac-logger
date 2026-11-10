//go:build !windows

package listener

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

func TestServeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := Listen(ctx, "[::1]:0", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	reg := &fakeReg{reply: true}
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, &Dispatcher{Reg: reg}) }()

	cl, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	m, _ := dhcp6.NewAddrRegInform([3]byte{7, 7, 7}, []byte{0, 4, 1}, dhcp6.IAAddress{Addr: netip.MustParseAddr("::1"), Valid: 60})
	b, _ := m.Marshal()
	if _, err := cl.WriteTo(b, c.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cl.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	reply, err := dhcp6.ParseMessage(buf[:n])
	if err != nil || reply.Type != dhcp6.MsgAddrRegReply || reply.XID != [3]byte{7, 7, 7} {
		t.Fatalf("reply = %+v %v", reply, err)
	}
	if r := reg.last(); r.Via != registrar.ViaUnicast || r.Src.Addr() != netip.MustParseAddr("::1") {
		t.Fatalf("req = %+v", r)
	}
	if r := reg.last(); r.IfName == "" {
		t.Fatal("IfName empty: PKTINFO not working")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestReplyControl(t *testing.T) {
	uni := Packet{Dst: netip.MustParseAddr("2001:db8::1"), IfIndex: 4}
	if cm := replyControl(uni, netip.MustParseAddr("2001:db8::9")); cm.IfIndex != 0 || !cm.Src.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unicast: %+v", cm)
	}
	mc := Packet{Dst: dhcp6.AllRelayAgentsAndServers, IfIndex: 4}
	if cm := replyControl(mc, netip.MustParseAddr("fe80::9")); cm.IfIndex != 4 || cm.Src != nil {
		t.Fatalf("multicast: %+v", cm)
	}
	if cm := replyControl(uni, netip.MustParseAddr("fe80::9")); cm.IfIndex != 4 {
		t.Fatalf("link-local: %+v", cm)
	}
}
