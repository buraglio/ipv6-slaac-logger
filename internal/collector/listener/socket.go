//go:build !windows

package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv6"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// Conn is the collector's UDP 547 socket.
type Conn struct {
	pc    net.PacketConn
	p     *ipv6.PacketConn
	log   *slog.Logger
	mu    sync.Mutex
	names map[int]string
}

// Listen binds addr (e.g. "[::]:547") and joins ff02::1:2 on each interface.
func Listen(ctx context.Context, addr string, ifaces []string, log *slog.Logger) (*Conn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp6", addr)
	if err != nil {
		return nil, fmt.Errorf("listener: %w", err)
	}
	p := ipv6.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		pc.Close()
		return nil, fmt.Errorf("listener: enable control messages: %w", err)
	}
	group := &net.UDPAddr{IP: net.IP(dhcp6.AllRelayAgentsAndServers.AsSlice())}
	for _, name := range ifaces {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("listener: %w", err)
		}
		if err := p.JoinGroup(ifi, group); err != nil {
			pc.Close()
			return nil, fmt.Errorf("listener: join ff02::1:2 on %s: %w", name, err)
		}
	}
	return &Conn{pc: pc, p: p, log: log, names: map[int]string{}}, nil
}

// LocalAddr returns the bound address.
func (c *Conn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

// Close closes the socket.
func (c *Conn) Close() error { return c.pc.Close() }

// Serve reads packets until ctx is cancelled, dispatching each and sending replies.
func (c *Conn) Serve(ctx context.Context, d *Dispatcher) error {
	stop := context.AfterFunc(ctx, func() { c.pc.Close() })
	defer stop()
	buf := make([]byte, 65535)
	for {
		n, cm, src, err := c.p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			c.log.Warn("listener: read", "err", err)
			continue
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		pkt := Packet{Data: buf[:n], Src: netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())}
		if cm != nil {
			pkt.IfIndex = cm.IfIndex
			if dst, ok := netip.AddrFromSlice(cm.Dst); ok {
				pkt.Dst = dst.Unmap()
			}
			pkt.IfName = c.ifName(cm.IfIndex)
		}
		out := d.Dispatch(ctx, pkt)
		if out == nil {
			continue
		}
		if _, err := c.p.WriteTo(out, replyControl(pkt, pkt.Src.Addr()), ua); err != nil {
			c.log.Debug("listener: write reply", "dst", ua, "err", err)
		}
	}
}

func (c *Conn) ifName(idx int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.names[idx]; ok {
		return n
	}
	ifi, err := net.InterfaceByIndex(idx)
	if err != nil {
		return ""
	}
	c.names[idx] = ifi.Name
	return ifi.Name
}

// replyControl builds the write control message: the reply leaves from the
// address the request was sent to, and is pinned to the ingress interface only
// when the request was multicast or the destination is link-local.
func replyControl(pkt Packet, dst netip.Addr) *ipv6.ControlMessage {
	cm := &ipv6.ControlMessage{}
	multicast := pkt.Dst.IsValid() && pkt.Dst.IsMulticast()
	if pkt.Dst.IsValid() && !multicast {
		cm.Src = net.IP(pkt.Dst.AsSlice())
	}
	if multicast || dst.IsLinkLocalUnicast() {
		cm.IfIndex = pkt.IfIndex
	}
	return cm
}
