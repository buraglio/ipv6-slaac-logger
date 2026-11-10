package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/agent/sched"
	"github.com/buraglio/ipv6-slaac-logger/internal/agent/sender"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type fakeSrc struct {
	mu       sync.Mutex
	list     []addrsrc.Addr
	lists    int
	watch    chan struct{}
	watchErr error
}

func (s *fakeSrc) List() ([]addrsrc.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	return append([]addrsrc.Addr(nil), s.list...), nil
}

func (s *fakeSrc) Watch(ctx context.Context) (<-chan struct{}, error) {
	if s.watchErr != nil {
		return nil, s.watchErr
	}
	return s.watch, nil
}

func (s *fakeSrc) listCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists
}

type sent struct {
	Addr addrsrc.Addr
	Dest string
}

type fakeTx struct {
	mu      sync.Mutex
	sends   []sent
	drops   []netip.Addr
	err     error
	replies chan sender.Reply
}

func newTx() *fakeTx { return &fakeTx{replies: make(chan sender.Reply, 8)} }

func (t *fakeTx) Send(a addrsrc.Addr, d sender.Dest, _ []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sends = append(t.sends, sent{a, d.Name})
	return t.err
}
func (t *fakeTx) Replies() <-chan sender.Reply { return t.replies }
func (t *fakeTx) Drop(a netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drops = append(t.drops, a)
}
func (t *fakeTx) snapshot() []sent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]sent(nil), t.sends...)
}
func (t *fakeTx) dests() []string {
	var out []string
	for _, s := range t.snapshot() {
		out = append(out, s.Dest)
	}
	return out
}

func slaac(ip string, idx int) addrsrc.Addr {
	return addrsrc.Addr{
		Addr: netip.MustParseAddr(ip), IfName: "eth0", IfIndex: idx, Origin: addrsrc.OriginSLAAC,
		Preferred: 14400, Valid: 86400, ObservedAt: t0,
	}
}

var coll = netip.MustParseAddrPort("[2001:db8::53]:547")

const collName = "unicast:[2001:db8::53]:547"

func newAgent(src *fakeSrc, tx *fakeTx) *Agent {
	var n byte
	a := &Agent{
		Src:        src,
		DUID:       []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6},
		Info:       sender.Info{Version: "test", Hostname: "host.example.com", PEN: 1},
		Collectors: []netip.AddrPort{coll},
		Multicast:  "always",
		Tx:         tx,
		MAC:        func(string) net.HardwareAddr { return nil },
		Sched: sched.New(sched.Params{
			Heartbeat: time.Hour, StaticRefresh: 4 * time.Hour, InitialRT: time.Second,
			MaxTries: 3, MinRefresh: 10 * time.Second, Rand: func() float64 { return 0.5 },
			NewXID: func() [3]byte { n++; return [3]byte{0, 0, n} },
		}),
		Rescan: time.Hour,
		Poll:   20 * time.Millisecond,
		Now:    func() time.Time { return t0 },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.init(context.Background())
	return a
}

func TestRunnerRegistersEligibleOnly(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{
		slaac("2001:db8::1", 2),
		{Addr: netip.MustParseAddr("fe80::1"), IfName: "eth0", IfIndex: 2, Origin: addrsrc.OriginSLAAC, Valid: 100},
		{Addr: netip.MustParseAddr("fd00::2"), IfName: "eth0", IfIndex: 2, Origin: addrsrc.OriginDHCPv6, Valid: 100},
	}}
	tx := newTx()
	a := newAgent(src, tx)
	a.onRescan(t0)
	a.step(t0)
	got := tx.snapshot()
	if len(got) != 2 {
		t.Fatalf("sends = %v", got)
	}
	for _, s := range got {
		if s.Addr.Addr != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("unexpected addr %v", s.Addr.Addr)
		}
	}
	if got[0].Dest != "multicast" || got[1].Dest != collName {
		t.Errorf("dests = %v", tx.dests())
	}
}

func TestRunnerMulticastNeedsProbe(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	a := newAgent(src, tx)
	a.Multicast = "auto"
	result := make(chan bool, 2)
	a.Probe = func(context.Context, string) bool { return <-result }

	a.onRescan(t0)
	a.step(t0)
	if d := tx.dests(); len(d) != 1 || d[0] != collName {
		t.Fatalf("first cycle dests = %v", d)
	}
	// Probe reports true; the next cycle adds multicast.
	result <- true
	result <- true // the heartbeat refresh probe
	pr := <-a.probeCh
	a.onProbeResult(pr.ifname, pr.ok, t0)

	later := t0.Add(2 * time.Hour)
	a.Sched.Update(later, nil) // force a fresh entry due now
	a.onRescan(later)
	a.step(later)
	d := tx.dests()
	if len(d) != 3 || d[1] != "multicast" || d[2] != collName {
		t.Fatalf("second cycle dests = %v", d)
	}
}

func TestRunnerAckStopsRetransmit(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	a := newAgent(src, tx)
	a.onRescan(t0)
	a.step(t0)
	if n := len(tx.snapshot()); n != 2 {
		t.Fatalf("sends = %d", n)
	}
	xid := [3]byte{0, 0, 1}
	local := netip.MustParseAddr("2001:db8::1")
	a.onReply(sender.Reply{Local: local, From: coll.Addr(), XID: xid})
	a.onReply(sender.Reply{Local: local, From: netip.MustParseAddr("fe80::9"), XID: xid})
	a.step(t0.Add(5 * time.Second))
	if n := len(tx.snapshot()); n != 2 {
		t.Fatalf("sends after ack = %d, want 2", n)
	}
}

func TestRunnerDropsAddressOnAddrNotAvail(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	tx.err = sender.ErrAddrGone
	a := newAgent(src, tx)
	a.onRescan(t0)
	a.step(t0)
	if n := len(tx.snapshot()); n != 1 {
		t.Fatalf("sends = %d, want 1 (remaining dests skipped)", n)
	}
	if len(tx.drops) != 1 || a.Sched.Len() != 0 {
		t.Fatalf("drops=%v len=%d", tx.drops, a.Sched.Len())
	}
	a.step(t0.Add(time.Minute))
	if n := len(tx.snapshot()); n != 1 {
		t.Fatalf("sends after drop = %d", n)
	}
	for _, s := range tx.snapshot() {
		if s.Addr.Valid == 0 {
			t.Error("deregistration (valid 0) sent")
		}
	}
}

func TestRunnerClosedSocketIsTransient(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	tx.err = net.ErrClosed
	a := newAgent(src, tx)
	a.onRescan(t0)
	a.step(t0)
	if n := len(tx.snapshot()); n != 2 || a.Sched.Len() != 1 || len(tx.drops) != 0 {
		t.Fatalf("sends=%d len=%d drops=%v", n, a.Sched.Len(), tx.drops)
	}
	tx.err = nil
	a.step(t0.Add(time.Second))
	if n := len(tx.snapshot()); n != 4 {
		t.Fatalf("retry sends = %d, want 4", n)
	}
}

func TestRunnerWarnsOncePerCycle(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	tx.err = errors.New("boom")
	a := newAgent(src, tx)
	var buf syncBuf
	a.Log = slog.New(slog.NewTextHandler(&buf, nil))
	a.onRescan(t0)
	a.step(t0)
	a.step(t0.Add(time.Second))
	if n := buf.count("send failed"); n != 1 {
		t.Fatalf("warns = %d, want 1", n)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *syncBuf) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, str := 0, string(s.b)
	for i := 0; i+len(sub) <= len(str); i++ {
		if str[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}

func TestRunnerCoalescesWatchBursts(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	a := newAgent(src, tx)
	a.onRescan(t0)
	a.step(t0)
	base := src.listCount()
	for range 50 {
		a.onWatch()
	}
	if a.debounce == nil {
		t.Fatal("debounce timer not armed")
	}
	select {
	case <-a.debounce.C:
	case <-time.After(3 * time.Second):
		t.Fatal("debounce did not fire")
	}
	a.debounce = nil
	a.onRescan(t0.Add(time.Second))
	if got := src.listCount() - base; got != 1 {
		t.Fatalf("list calls = %d, want 1", got)
	}
	// Unchanged lifetimes keep the in-flight XID: a retransmit reuses it.
	a.step(t0.Add(time.Second))
	got := tx.snapshot()
	if len(got) != 4 {
		t.Fatalf("sends = %d", len(got))
	}
}

func runAgent(t *testing.T, a *Agent) (cancel func(), done chan error) {
	t.Helper()
	ctx, c := context.WithCancel(context.Background())
	done = make(chan error, 1)
	stopped := make(chan struct{})
	go func() { done <- a.Run(ctx); close(stopped) }()
	t.Cleanup(func() { c(); <-stopped })
	return c, done
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunnerFallsBackToPollingWhenWatchFails(t *testing.T) {
	src := &fakeSrc{watchErr: errors.New("no netlink")}
	a := newAgent(src, newTx())
	a.Now = time.Now
	runAgent(t, a)
	waitFor(t, "polled rescans", func() bool { return src.listCount() >= 3 })
}

func TestRunnerFallsBackWhenWatchChannelCloses(t *testing.T) {
	src := &fakeSrc{watch: make(chan struct{})}
	a := newAgent(src, newTx())
	a.Now = time.Now
	runAgent(t, a)
	waitFor(t, "initial list", func() bool { return src.listCount() >= 1 })
	time.Sleep(60 * time.Millisecond)
	if n := src.listCount(); n != 1 {
		t.Fatalf("lists before close = %d, want 1", n)
	}
	close(src.watch)
	waitFor(t, "polled rescans", func() bool { return src.listCount() >= 3 })
}

func TestRunnerShutdownSendsNothing(t *testing.T) {
	live := slaac("2001:db8::1", 2)
	live.ObservedAt = time.Now()
	src := &fakeSrc{list: []addrsrc.Addr{live}, watch: make(chan struct{})}
	tx := newTx()
	a := newAgent(src, tx)
	a.Now = time.Now
	cancel, done := runAgent(t, a)
	waitFor(t, "first sends", func() bool { return len(tx.snapshot()) >= 2 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	n := len(tx.snapshot())
	time.Sleep(50 * time.Millisecond)
	got := tx.snapshot()
	if len(got) != n {
		t.Fatalf("sends after cancel: %d -> %d", n, len(got))
	}
	for _, s := range got {
		if s.Addr.Valid == 0 {
			t.Error("valid 0 sent")
		}
	}
}

func TestRunnerProbeSuccessRegistersImmediately(t *testing.T) {
	src := &fakeSrc{list: []addrsrc.Addr{slaac("2001:db8::1", 2)}}
	tx := newTx()
	a := newAgent(src, tx)
	a.Multicast = "auto"
	a.Collectors = nil
	result := make(chan bool, 1)
	a.Probe = func(context.Context, string) bool { return <-result }

	a.onRescan(t0)
	a.step(t0)
	if n := len(tx.snapshot()); n != 0 {
		t.Fatalf("sends before probe = %d", n)
	}
	result <- true
	pr := <-a.probeCh
	a.onProbeResult(pr.ifname, pr.ok, t0)
	a.step(t0) // same instant: no refresh interval elapsed
	if d := tx.dests(); len(d) != 1 || d[0] != "multicast" {
		t.Fatalf("dests = %v, want [multicast]", d)
	}
}
