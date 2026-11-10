package sender

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// Probe sends Information-Request(ORO 148) from the interface's link-local
// address to ff02::1:2%ifname:serverPort, up to 3 tries (1s, 2s, 4s), and
// reports whether a Reply carrying option 148 arrived.
func Probe(ctx context.Context, ifname string, duid []byte, serverPort int) (bool, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return false, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, err
	}
	ll, err := linkLocal(addrs, ifname)
	if err != nil {
		return false, err
	}
	xid, err := dhcp6.RandomXID()
	if err != nil {
		return false, err
	}
	req, err := dhcp6.NewInformationRequest(xid, duid).Marshal()
	if err != nil {
		return false, err
	}

	lc := net.ListenConfig{Control: reuse}
	pc, err := lc.ListenPacket(ctx, "udp6", netip.AddrPortFrom(ll, dhcp6.ClientPort).String())
	if err != nil {
		if pc, err = lc.ListenPacket(ctx, "udp6", netip.AddrPortFrom(ll, 0).String()); err != nil {
			return false, err
		}
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()

	dst := netip.AddrPortFrom(dhcp6.AllRelayAgentsAndServers.WithZone(ifname), uint16(serverPort))
	buf := make([]byte, 2048)
	timeout := time.Second
	for try := 0; try < 3; try++ {
		if _, err := conn.WriteToUDPAddrPort(req, dst); err != nil {
			return false, err
		}
		dl := time.Now().Add(timeout)
		if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
			dl = cd
		}
		conn.SetReadDeadline(dl)
		if err := ctx.Err(); err != nil {
			return false, err
		}
		for {
			n, _, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return false, err
			}
			if replyEnables(buf[:n], xid) {
				return true, nil
			}
		}
		timeout *= 2
	}
	return false, nil
}

// linkLocal returns the first IPv6 link-local unicast address in addrs (not
// an IPv4 address in 16-byte form), with ifname as its zone.
func linkLocal(addrs []net.Addr, ifname string) (netip.Addr, error) {
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Is6() && !ip.Is4In6() && ip.IsLinkLocalUnicast() {
			return ip.WithZone(ifname), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("sender: no link-local address on %s", ifname)
}

// replyEnables reports whether b is a Reply for xid carrying option 148.
func replyEnables(b []byte, xid [3]byte) bool {
	m, err := dhcp6.ParseMessage(b)
	if err != nil || m.Type != dhcp6.MsgReply || m.XID != xid {
		return false
	}
	_, ok := m.Options.Get(dhcp6.OptAddrRegEnable)
	return ok
}
