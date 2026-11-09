// Package listener receives DHCPv6 packets on UDP 547 and routes them to the
// registrar or responder, unwrapping and re-wrapping relay messages.
package listener

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// MaxRelayDepth is HOP_COUNT_LIMIT from RFC 8415 §7.6.
const MaxRelayDepth = 8

// Packet is one received datagram.
type Packet struct {
	Data    []byte
	Src     netip.AddrPort
	Dst     netip.Addr
	IfIndex int
	IfName  string
}

// RegHandler is satisfied by *registrar.Registrar.
type RegHandler interface {
	Handle(ctx context.Context, req *registrar.Request) *dhcp6.Message
}

// InfoHandler is satisfied by *responder.Responder.
type InfoHandler interface {
	Handle(m *dhcp6.Message) *dhcp6.Message
}

// Dispatcher routes packets. Resp may be nil to disable the responder.
type Dispatcher struct {
	Reg             RegHandler
	Resp            InfoHandler
	ResponderIfaces map[int]bool
	Log             *slog.Logger
	Dropped         atomic.Uint64
}

// Dispatch returns the bytes to send back to pkt.Src, or nil.
func (d *Dispatcher) Dispatch(ctx context.Context, pkt Packet) []byte {
	if len(pkt.Data) == 0 {
		return d.drop()
	}
	switch pkt.Data[0] {
	case dhcp6.MsgAddrRegInform:
		m, err := dhcp6.ParseMessage(pkt.Data)
		if err != nil {
			return d.drop()
		}
		via := registrar.ViaUnicast
		if pkt.Dst == dhcp6.AllRelayAgentsAndServers {
			via = registrar.ViaMulticast
		}
		return marshal(d.Reg.Handle(ctx, &registrar.Request{Msg: m, Src: pkt.Src, IfName: pkt.IfName, Via: via}))
	case dhcp6.MsgInformationRequest:
		if d.Resp == nil || !d.ResponderIfaces[pkt.IfIndex] || pkt.Dst != dhcp6.AllRelayAgentsAndServers {
			return d.drop()
		}
		m, err := dhcp6.ParseMessage(pkt.Data)
		if err != nil {
			return d.drop()
		}
		reply := d.Resp.Handle(m)
		if reply != nil && d.Log != nil {
			d.Log.Debug("responder: info.reply", "src", pkt.Src, "iface", pkt.IfName)
		}
		return marshal(reply)
	case dhcp6.MsgRelayForw:
		return d.relay(ctx, pkt)
	}
	return d.drop()
}

func (d *Dispatcher) relay(ctx context.Context, pkt Packet) []byte {
	var chain []*dhcp6.RelayMessage
	data := pkt.Data
	for len(data) > 0 && data[0] == dhcp6.MsgRelayForw {
		if len(chain) == MaxRelayDepth {
			return d.drop()
		}
		rm, err := dhcp6.ParseRelay(data)
		if err != nil {
			return d.drop()
		}
		inner, ok := rm.Options.Get(dhcp6.OptRelayMsg)
		if !ok {
			return d.drop()
		}
		chain = append(chain, rm)
		data = inner.Data
	}
	if len(data) == 0 || data[0] != dhcp6.MsgAddrRegInform {
		return d.drop()
	}
	m, err := dhcp6.ParseMessage(data)
	if err != nil {
		return d.drop()
	}
	in := chain[len(chain)-1]
	ri := &registrar.RelayInfo{LinkAddr: in.LinkAddr, PeerAddr: in.PeerAddr}
	if o, ok := in.Options.Get(dhcp6.OptInterfaceID); ok {
		ri.InterfaceID = o.Data
	}
	if o, ok := in.Options.Get(dhcp6.OptClientLinkLayerAddr); ok {
		if mac, ok := dhcp6.ParseCLLAO(o.Data); ok {
			ri.CLLAO = mac
		}
	}
	reply := d.Reg.Handle(ctx, &registrar.Request{Msg: m, Src: pkt.Src, IfName: pkt.IfName, Via: registrar.ViaRelay, Relay: ri})
	out := marshal(reply)
	if out == nil {
		return nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		rf := chain[i]
		var opts dhcp6.Options
		if o, ok := rf.Options.Get(dhcp6.OptInterfaceID); ok {
			opts = append(opts, o)
		}
		opts = append(opts, dhcp6.Option{Code: dhcp6.OptRelayMsg, Data: out})
		rr := &dhcp6.RelayMessage{Type: dhcp6.MsgRelayRepl, HopCount: rf.HopCount, LinkAddr: rf.LinkAddr, PeerAddr: rf.PeerAddr, Options: opts}
		if out, err = rr.Marshal(); err != nil {
			return d.drop()
		}
	}
	return out
}

func (d *Dispatcher) drop() []byte {
	d.Dropped.Add(1)
	return nil
}

func marshal(m *dhcp6.Message) []byte {
	if m == nil {
		return nil
	}
	b, err := m.Marshal()
	if err != nil {
		return nil
	}
	return b
}
