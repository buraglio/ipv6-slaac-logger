package listener

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

var ctx = context.Background()

type fakeReg struct {
	mu    sync.Mutex
	reqs  []*registrar.Request
	reply bool
}

func (f *fakeReg) Handle(_ context.Context, r *registrar.Request) *dhcp6.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	if !f.reply {
		return nil
	}
	return &dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: r.Msg.XID}
}

func (f *fakeReg) last() *registrar.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		return nil
	}
	return f.reqs[len(f.reqs)-1]
}

type fakeResp struct{}

func (fakeResp) Handle(m *dhcp6.Message) *dhcp6.Message {
	return &dhcp6.Message{Type: dhcp6.MsgReply, XID: m.XID}
}

var (
	client = netip.MustParseAddr("2001:db8:10::5")
	linkA  = netip.MustParseAddr("2001:db8:10::1")
)

func informBytes(t *testing.T) []byte {
	t.Helper()
	m, err := dhcp6.NewAddrRegInform([3]byte{1, 2, 3}, []byte{0, 4, 1}, dhcp6.IAAddress{Addr: client, Valid: 60})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func relayForw(t *testing.T, inner []byte, link, peer netip.Addr, opts ...dhcp6.Option) []byte {
	t.Helper()
	rm := &dhcp6.RelayMessage{Type: dhcp6.MsgRelayForw, LinkAddr: link, PeerAddr: peer,
		Options: append(dhcp6.Options(opts), dhcp6.Option{Code: dhcp6.OptRelayMsg, Data: inner})}
	b, err := rm.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pkt(data []byte, dst netip.Addr) Packet {
	return Packet{Data: data, Src: netip.AddrPortFrom(client, 546), Dst: dst, IfIndex: 2, IfName: "eth0"}
}

func TestDispatchMulticastAndUnicast(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg, ListenIfaces: map[int]bool{2: true}}
	out := d.Dispatch(ctx, pkt(informBytes(t), dhcp6.AllRelayAgentsAndServers))
	if len(out) == 0 || out[0] != dhcp6.MsgAddrRegReply {
		t.Fatalf("out = %x", out)
	}
	if r := reg.last(); r.Via != registrar.ViaMulticast || r.IfName != "eth0" || r.Src.Addr() != client {
		t.Fatalf("req = %+v", r)
	}
	d.Dispatch(ctx, pkt(informBytes(t), linkA))
	if r := reg.last(); r.Via != registrar.ViaUnicast {
		t.Fatalf("via = %s", r.Via)
	}
}

func TestDispatchInfoRequest(t *testing.T) {
	ir, _ := (&dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: [3]byte{4, 4, 4}}).Marshal()
	d := &Dispatcher{Reg: &fakeReg{}, Resp: fakeResp{}, ResponderIfaces: map[int]bool{2: true}}
	if out := d.Dispatch(ctx, pkt(ir, dhcp6.AllRelayAgentsAndServers)); len(out) == 0 || out[0] != dhcp6.MsgReply {
		t.Fatalf("responder iface: out = %x", out)
	}
	other := pkt(ir, dhcp6.AllRelayAgentsAndServers)
	other.IfIndex = 3
	if out := d.Dispatch(ctx, other); out != nil {
		t.Fatal("replied on a non-responder interface")
	}
	if out := d.Dispatch(ctx, pkt(ir, linkA)); out != nil {
		t.Fatal("replied to a unicast Information-Request")
	}
	if out := (&Dispatcher{Reg: &fakeReg{}}).Dispatch(ctx, pkt(ir, dhcp6.AllRelayAgentsAndServers)); out != nil {
		t.Fatal("replied with responder disabled")
	}
}

func TestDispatchRelayUnwrapAndWrap(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg, TrustedRelays: []netip.Prefix{netip.MustParsePrefix("2001:db8:ffff::/64")}}
	ifid := dhcp6.Option{Code: dhcp6.OptInterfaceID, Data: []byte("eth7")}
	cllao := dhcp6.Option{Code: dhcp6.OptClientLinkLayerAddr, Data: []byte{0, 1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}}
	inner := relayForw(t, informBytes(t), linkA, client, ifid, cllao)
	outer := relayForw(t, inner, netip.MustParseAddr("2001:db8:20::1"), netip.MustParseAddr("2001:db8:ffff::2"))
	p := pkt(outer, netip.MustParseAddr("2001:db8:ffff::9"))
	p.Src = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:ffff::2"), 547)

	out := d.Dispatch(ctx, p)
	r := reg.last()
	if r == nil || r.Via != registrar.ViaRelay || r.Relay.PeerAddr != client || r.Relay.LinkAddr != linkA ||
		string(r.Relay.InterfaceID) != "eth7" || r.Relay.CLLAO.String() != "02:aa:bb:cc:dd:ee" {
		t.Fatalf("req = %+v relay=%+v", r, r.Relay)
	}
	o, err := dhcp6.ParseRelay(out)
	if err != nil || o.Type != dhcp6.MsgRelayRepl || o.PeerAddr != netip.MustParseAddr("2001:db8:ffff::2") {
		t.Fatalf("outer reply %+v %v", o, err)
	}
	im, _ := o.Options.Get(dhcp6.OptRelayMsg)
	in, err := dhcp6.ParseRelay(im.Data)
	if err != nil || in.PeerAddr != client || in.LinkAddr != linkA {
		t.Fatalf("inner reply %+v %v", in, err)
	}
	if id, ok := in.Options.Get(dhcp6.OptInterfaceID); !ok || string(id.Data) != "eth7" {
		t.Fatal("interface-id not echoed")
	}
	cm, _ := in.Options.Get(dhcp6.OptRelayMsg)
	if len(cm.Data) == 0 || cm.Data[0] != dhcp6.MsgAddrRegReply {
		t.Fatalf("client reply = %x", cm.Data)
	}

	n := len(reg.reqs)
	before := d.Dropped.Load()
	bad := p
	bad.Src = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:eeee::2"), 547)
	if d.Dispatch(ctx, bad) != nil || d.Dropped.Load() != before+1 {
		t.Fatal("untrusted relay not dropped")
	}
	mc := p
	mc.Dst = dhcp6.AllRelayAgentsAndServers
	if d.Dispatch(ctx, mc) != nil || d.Dropped.Load() != before+2 {
		t.Fatal("multicast relay not dropped")
	}
	if len(reg.reqs) != n {
		t.Fatal("registrar called for untrusted relay")
	}
}

func TestDispatchDropsHostileInput(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg, TrustedRelays: []netip.Prefix{netip.MustParsePrefix("2001:db8:10::/64")}}
	deep := informBytes(t)
	for i := 0; i < MaxRelayDepth+1; i++ {
		deep = relayForw(t, deep, linkA, client)
	}
	sol, _ := (&dhcp6.Message{Type: 1}).Marshal()
	cases := map[string][]byte{
		"empty":             {},
		"garbage type":      {0xff, 1, 2, 3},
		"truncated inform":  {dhcp6.MsgAddrRegInform, 1},
		"bad option length": {dhcp6.MsgAddrRegInform, 1, 2, 3, 0, 1, 0xff, 0xff},
		"too deep":          deep,
		"relay of solicit":  relayForw(t, sol, linkA, client),
		"relay no msg": func() []byte {
			b, _ := (&dhcp6.RelayMessage{Type: dhcp6.MsgRelayForw, LinkAddr: linkA, PeerAddr: client}).Marshal()
			return b
		}(),
	}
	for name, data := range cases {
		before := d.Dropped.Load()
		if out := d.Dispatch(ctx, pkt(data, linkA)); out != nil {
			t.Errorf("%s: produced a reply", name)
		}
		if d.Dropped.Load() != before+1 {
			t.Errorf("%s: not counted as dropped", name)
		}
	}
	if len(reg.reqs) != 0 {
		t.Fatalf("registrar called for hostile input: %d", len(reg.reqs))
	}
}

func FuzzDispatch(f *testing.F) {
	f.Add([]byte{dhcp6.MsgAddrRegInform, 1, 2, 3})
	f.Add([]byte{dhcp6.MsgRelayForw})
	d := &Dispatcher{Reg: &fakeReg{reply: true}, Resp: fakeResp{}, ResponderIfaces: map[int]bool{2: true}, ListenIfaces: map[int]bool{2: true}, TrustedRelays: []netip.Prefix{netip.MustParsePrefix("::/0")}}
	f.Fuzz(func(t *testing.T, b []byte) {
		d.Dispatch(ctx, pkt(b, dhcp6.AllRelayAgentsAndServers))
		d.Dispatch(ctx, pkt(b, linkA))
	})
}

func TestDispatchLDRAUsesOuterLinkAddr(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg, TrustedRelays: []netip.Prefix{netip.MustParsePrefix("2001:db8:ffff::/64")}}
	cllao := dhcp6.Option{Code: dhcp6.OptClientLinkLayerAddr, Data: []byte{0, 1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}}
	ifid := dhcp6.Option{Code: dhcp6.OptInterfaceID, Data: []byte("port3")}
	// RFC 6221 LDRA: link-address is unspecified; the L3 relay above it supplies the link.
	ldra := relayForw(t, informBytes(t), netip.IPv6Unspecified(), client, ifid, cllao)
	outer := relayForw(t, ldra, linkA, netip.MustParseAddr("fe80::1"))
	p := pkt(outer, netip.MustParseAddr("2001:db8:ffff::9"))
	p.Src = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:ffff::2"), 547)
	if d.Dispatch(ctx, p) == nil {
		t.Fatal("no reply through LDRA")
	}
	r := reg.last()
	if r.Relay.LinkAddr != linkA || r.Relay.PeerAddr != client || r.Relay.CLLAO.String() != "02:aa:bb:cc:dd:ee" ||
		string(r.Relay.InterfaceID) != "port3" {
		t.Fatalf("relay = %+v", r.Relay)
	}

	// Every link-address unspecified: LinkAddr stays ::.
	allUnspec := relayForw(t, ldra, netip.IPv6Unspecified(), netip.MustParseAddr("fe80::1"))
	p.Data = allUnspec
	d.Dispatch(ctx, p)
	if r := reg.last(); r.Relay.LinkAddr != netip.IPv6Unspecified() {
		t.Fatalf("LinkAddr = %v, want ::", r.Relay.LinkAddr)
	}
}

func TestDispatchMulticastOnlyOnListenIfaces(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg, ListenIfaces: map[int]bool{2: true}}
	p := pkt(informBytes(t), dhcp6.AllRelayAgentsAndServers)
	p.IfIndex, p.IfName = 3, "eth1"
	if out := d.Dispatch(ctx, p); out != nil || d.Dropped.Load() != 1 || len(reg.reqs) != 0 {
		t.Fatalf("multicast on a non-listen interface: out=%x dropped=%d reqs=%d", out, d.Dropped.Load(), len(reg.reqs))
	}
	// Unicast on any interface is still accepted (policy decides).
	p.Dst = linkA
	if d.Dispatch(ctx, p) == nil || len(reg.reqs) != 1 {
		t.Fatal("unicast on a non-listen interface dropped")
	}
}
