package registrar

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var ctx = context.Background()

type commitRecorder struct{ st *store.Store }

func (c commitRecorder) Record(ctx context.Context, ch store.Change) error {
	return c.st.Commit(ctx, ch)
}

type env struct {
	t   *testing.T
	st  *store.Store
	r   *Registrar
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, now: t0}
	e.r = New(st, commitRecorder{st}, testPolicy(), []byte{0, 4, 1, 2, 3, 4}, 32473)
	e.r.Now = func() time.Time { return e.now }
	return e
}

func (e *env) events() []event.Event {
	e.t.Helper()
	evs, err := e.st.EventsAfter(ctx, 0, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]event.Event, len(evs))
	for i, se := range evs {
		out[i] = se.Event
	}
	return out
}

func (e *env) types() []string {
	var out []string
	for _, ev := range e.events() {
		out = append(out, ev.Type)
	}
	return out
}

func (e *env) binding(a netip.Addr) (store.Binding, bool) {
	b, ok, err := e.st.GetBinding(ctx, a)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, ok
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAddRepliesAndRecords(t *testing.T) {
	e := newEnv(t)
	req := mcastReq(inform(t, testAddr, testDUID, 7200), testAddr)
	reply := e.r.Handle(ctx, req)
	if reply == nil || reply.Type != dhcp6.MsgAddrRegReply || reply.XID != [3]byte{1, 2, 3} {
		t.Fatalf("reply = %+v", reply)
	}
	inIA, _ := req.Msg.Options.Get(dhcp6.OptIAAddr)
	outIA, _ := reply.Options.Get(dhcp6.OptIAAddr)
	if !bytes.Equal(inIA.Data, outIA.Data) {
		t.Fatal("IA Address not echoed verbatim")
	}
	if cid, ok := reply.Options.Get(dhcp6.OptClientID); !ok || !bytes.Equal(cid.Data, testDUID) {
		t.Fatal("Client ID not echoed")
	}
	if sid, ok := reply.Options.Get(dhcp6.OptServerID); !ok || !bytes.Equal(sid.Data, []byte{0, 4, 1, 2, 3, 4}) {
		t.Fatal("Server ID missing")
	}
	evs := e.events()
	if len(evs) != 1 {
		t.Fatalf("events = %v", e.types())
	}
	ev := evs[0]
	if ev.Type != event.RegAdd || ev.MAC != testMAC.String() || ev.MACSrc != MACSrcDUID || ev.Origin != OriginNative ||
		ev.Via != ViaMulticast || ev.Link != "eth0" || ev.DUIDType != "LL" || ev.Valid == nil || *ev.Valid != 7200 || ev.XID != "010203" {
		t.Fatalf("event = %+v", ev)
	}
	b, ok := e.binding(testAddr)
	if !ok || !b.ExpiresAt.Equal(t0.Add(7200*time.Second)) {
		t.Fatalf("binding = %+v %v", b, ok)
	}
}

func TestRefreshIsSilent(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.now = t0.Add(time.Hour)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	if got := e.types(); !equal(got, []string{event.RegAdd}) {
		t.Fatalf("events = %v", got)
	}
	b, _ := e.binding(testAddr)
	if !b.FirstSeen.Equal(t0) || !b.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("first=%v last=%v", b.FirstSeen, b.LastSeen)
	}
}

func TestMulticastAndUnicastCopiesDoNotChurn(t *testing.T) {
	e := newEnv(t)
	m := inform(t, testAddr, testDUID, 7200)
	e.r.Handle(ctx, mcastReq(m, testAddr))
	uni := mcastReq(m, testAddr)
	uni.Via = ViaUnicast
	if e.r.Handle(ctx, uni) == nil {
		t.Fatal("unicast copy got no reply")
	}
	if got := e.types(); !equal(got, []string{event.RegAdd}) {
		t.Fatalf("events = %v", got)
	}
}

func TestConflict(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, otherDUID, 7200), testAddr))
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegConflict || evs[1].PrevDUID != dhcp6.FormatHex(testDUID) {
		t.Fatalf("events = %+v", evs)
	}
	b, _ := e.binding(testAddr)
	if b.DUID != dhcp6.FormatHex(otherDUID) {
		t.Fatalf("binding DUID = %s", b.DUID)
	}
}

func TestShortenedLifetimeIsChange(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 86400), testAddr))
	e.now = t0.Add(time.Minute)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 600), testAddr))
	if got := e.types(); !equal(got, []string{event.RegAdd, event.RegChange}) {
		t.Fatalf("events = %v", got)
	}
}

func TestDereg(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.now = t0.Add(time.Minute)
	if e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 0), testAddr)) == nil {
		t.Fatal("dereg got no reply")
	}
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegDereg || evs[1].FirstSeen == nil || !evs[1].FirstSeen.Equal(t0) {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); ok {
		t.Fatal("binding survived dereg")
	}
}

func TestDeregForeignDUIDRejected(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, otherDUID, 0), testAddr))
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegReject || evs[1].Reason != ReasonDeregForeign {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); !ok {
		t.Fatal("foreign dereg removed the binding")
	}
}

func agentOpts(t *testing.T, pen uint32, mac string) []dhcp6.Option {
	t.Helper()
	vc, err := dhcp6.VendorClass{Enterprise: pen, Data: [][]byte{
		[]byte("ra-logger-agent/0.1"), []byte("os=darwin"), []byte("if=en0"), []byte("mac=" + mac),
	}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fqdn, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, "lab-mbp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return []dhcp6.Option{{Code: dhcp6.OptVendorClass, Data: vc}, {Code: dhcp6.OptClientFQDN, Data: fqdn}}
}

func TestAgentVendorAndFQDN(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 32473, "02:00:00:00:00:01")...), testAddr))
	ev := e.events()[0]
	if ev.Origin != OriginAgent || ev.MAC != "02:00:00:00:00:01" || ev.MACSrc != MACSrcVendor || ev.Host != "lab-mbp.example.com" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestWrongPENIsNative(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 9, "02:00:00:00:00:01")...), testAddr))
	ev := e.events()[0]
	if ev.Origin != OriginNative || ev.MACSrc != MACSrcDUID {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRelayCLLAOWins(t *testing.T) {
	e := newEnv(t)
	req := relayReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 32473, "02:00:00:00:00:01")...), testAddr)
	req.Relay.CLLAO = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	if e.r.Handle(ctx, req) == nil {
		t.Fatal("relayed registration dropped")
	}
	ev := e.events()[0]
	if ev.MAC != "02:aa:bb:cc:dd:ee" || ev.MACSrc != MACSrcCLLAO || ev.Link != "relay/"+relayLink.String() || ev.Via != ViaRelay {
		t.Fatalf("event = %+v", ev)
	}
}

func TestInvalidIsRejectedWithoutReply(t *testing.T) {
	e := newEnv(t)
	m := with(inform(t, testAddr, testDUID, 7200), dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 9}})
	if e.r.Handle(ctx, mcastReq(m, testAddr)) != nil {
		t.Fatal("invalid message got a reply")
	}
	evs := e.events()
	if len(evs) != 1 || evs[0].Type != event.RegReject || evs[0].Reason != ReasonServerID || evs[0].Addr != testAddr.String() {
		t.Fatalf("events = %+v", evs)
	}
	if e.r.Stats.Rejected.Load() != 1 {
		t.Fatal("Rejected counter not incremented")
	}
}

func TestRejectFloodIsBounded(t *testing.T) {
	e := newEnv(t)
	m := with(inform(t, testAddr, testDUID, 7200), dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}})
	for i := 0; i < 100; i++ {
		e.r.Handle(ctx, mcastReq(m, testAddr))
	}
	if n := len(e.events()); n != 20 {
		t.Fatalf("individual reject events = %d, want 20", n)
	}
	e.r.Sweep(ctx)
	evs := e.events()
	last := evs[len(evs)-1]
	if len(evs) != 21 || last.Reason != ReasonSuppressed || last.Count != 80 {
		t.Fatalf("summary = %+v (total %d)", last, len(evs))
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.r.Limits = NewLimiter(Limits{Global: Rate{1000, 1000}, PerPrefix: Rate{0.001, 2}, PerDUID: Rate{1000, 1000}})
	replies := 0
	for i := 0; i < 5; i++ {
		if e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr)) != nil {
			replies++
		}
	}
	if replies != 2 || e.r.Stats.RateLimited.Load() != 3 {
		t.Fatalf("replies=%d limited=%d", replies, e.r.Stats.RateLimited.Load())
	}
	e.r.Sweep(ctx)
	evs := e.events()
	last := evs[len(evs)-1]
	if last.Reason != ReasonRateLimited || last.Count != 3 {
		t.Fatalf("summary = %+v", last)
	}
}

func TestSweepExpires(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 10), testAddr))
	e.now = t0.Add(11 * time.Second)
	e.r.Sweep(ctx)
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegExpire || evs[1].LastSeen == nil || !evs[1].LastSeen.Equal(t0) {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); ok {
		t.Fatal("expired binding not removed")
	}
}

func TestInfiniteLifetime(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, dhcp6.Infinity), testAddr))
	b, _ := e.binding(testAddr)
	if !b.ExpiresAt.Equal(t0.Add(InfiniteTTL)) {
		t.Fatalf("ExpiresAt = %v", b.ExpiresAt)
	}
}
