package sender

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

var lo = netip.MustParseAddr("::1")

func startServer(t *testing.T) *net.UDPConn {
	t.Helper()
	s, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func srvAddr(s *net.UDPConn) netip.AddrPort { return s.LocalAddr().(*net.UDPAddr).AddrPort() }

func iaOpt(t *testing.T, a netip.Addr) dhcp6.Option {
	t.Helper()
	d, err := dhcp6.IAAddress{Addr: a, Preferred: 1, Valid: 2}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return dhcp6.Option{Code: dhcp6.OptIAAddr, Data: d}
}

func TestTransportSendAndReply(t *testing.T) {
	srv := startServer(t)
	tr := NewTransport(0, nil)
	defer tr.Close()
	xid := [3]byte{4, 5, 6}
	if err := tr.Send(addrsrc.Addr{Addr: lo}, UnicastDest(srvAddr(srv)), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := srv.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("server read %q %v", buf[:n], err)
	}
	if from.Addr() != lo {
		t.Fatalf("source %v", from.Addr())
	}
	// A reply for a different address is ignored.
	other := mkMsg(t, dhcp6.MsgAddrRegReply, xid, iaOpt(t, netip.MustParseAddr("2001:db8::99")))
	srv.WriteToUDPAddrPort(other, from)
	select {
	case r := <-tr.Replies():
		t.Fatalf("unexpected reply %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
	good := mkMsg(t, dhcp6.MsgAddrRegReply, xid, iaOpt(t, lo))
	srv.WriteToUDPAddrPort(good, from)
	select {
	case r := <-tr.Replies():
		if r != (Reply{Local: lo, From: lo, XID: xid}) {
			t.Fatalf("reply %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reply")
	}
}

func TestTransportFallsBackWhenPortBusy(t *testing.T) {
	busy, err := listenBusy("[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer busy.Close()
	p := busy.LocalAddr().(*net.UDPAddr).Port
	srv := startServer(t)
	tr := NewTransport(p, nil)
	defer tr.Close()
	if err := tr.Send(addrsrc.Addr{Addr: lo}, UnicastDest(srvAddr(srv)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := tr.BoundPort(lo); got == 0 || got == p {
		t.Fatalf("BoundPort %d, busy port %d", got, p)
	}
}

func TestTransportDropClosesSocket(t *testing.T) {
	srv := startServer(t)
	tr := NewTransport(0, nil)
	defer tr.Close()
	if err := tr.Send(addrsrc.Addr{Addr: lo}, UnicastDest(srvAddr(srv)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	tr.Drop(lo)
	if tr.BoundPort(lo) != 0 {
		t.Fatal("socket still tracked")
	}
}

func TestSendAddrGone(t *testing.T) {
	srv := startServer(t)
	tr := NewTransport(0, nil)
	defer tr.Close()
	err := tr.Send(addrsrc.Addr{Addr: netip.MustParseAddr("2001:db8:ffff::1")}, UnicastDest(srvAddr(srv)), []byte("x"))
	if !errors.Is(err, ErrAddrGone) {
		t.Fatalf("err %v", err)
	}
}

func TestMulticastDest(t *testing.T) {
	d := MulticastDest("en0")
	if d.Name != DestMulticast || d.To.String() != "[ff02::1:2%en0]:547" {
		t.Fatalf("%+v", d)
	}
}
