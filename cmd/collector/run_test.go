//go:build !windows

package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/sniffer"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

func readFrame(r *bufio.Reader) (string, error) {
	n, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func TestRunRecordsAndForwards(t *testing.T) {
	// Skip only when the host has no IPv6 loopback; any later failure of run
	// is a real failure.
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frames := make(chan string, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			f, err := readFrame(r)
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	dir := t.TempDir()
	cfg := &config.Config{
		StateDir: dir, ListenAddr: "[::1]:0", RetentionDays: 400,
		Vendor: config.Vendor{EnterpriseNumber: 32473},
		Log:    config.Log{Facility: "local5", Outputs: []config.Output{{Type: "tcp", Address: ln.Addr().String()}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a net.Addr) { ready <- a })
	}()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("collector failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not become ready")
	}

	// ::1 is not a global address, so this must be rejected with reason "scope".
	cl, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	m, _ := dhcp6.NewAddrRegInform([3]byte{5, 5, 5}, []byte{0, 4, 1, 2}, dhcp6.IAAddress{Addr: netip.MustParseAddr("::1"), Valid: 60})
	b, _ := m.Marshal()
	if _, err := cl.WriteTo(b, addr); err != nil {
		t.Fatal(err)
	}

	select {
	case f := <-frames:
		if !strings.Contains(f, `"event":"reg.reject"`) || !strings.Contains(f, `"reason":"scope"`) || !strings.Contains(f, " ra-logger ") {
			t.Fatalf("forwarded frame = %s", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event forwarded to the TCP syslog sink")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	ro, err := store.OpenReadOnly(filepath.Join(dir, "ra-logger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	evs, err := ro.EventsAfter(context.Background(), 0, 10)
	if err != nil || len(evs) == 0 || evs[0].Event.Type != event.RegReject {
		t.Fatalf("stored events = %+v %v", evs, err)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A sniff interface that does not exist (or cannot be opened, as off Linux)
// must not stop the collector: it starts, warns once, and shuts down cleanly.
func TestRunSniffersRetriesMissingInterface(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()

	cfg := &config.Config{
		StateDir: t.TempDir(), ListenAddr: "[::1]:0", RetentionDays: 400,
		Vendor:     config.Vendor{EnterpriseNumber: 32473},
		Interfaces: []config.Interface{{Name: "does-not-exist0", Roles: []string{config.RoleSniff}}},
		Sniffer:    config.Sniffer{IdleTimeout: "24h", ProxyThreshold: 32, MaxEntries: 100000, MaxRouters: 1000},
		Log:        config.Log{Facility: "local5", Outputs: []config.Output{{Type: "stdout"}}},
	}
	logs := &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, slog.New(slog.NewTextHandler(logs, nil)), func(a net.Addr) { ready <- a })
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("collector failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not become ready")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "sniffer capture failed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	out := logs.String()
	if n := strings.Count(out, "sniffer capture failed"); n != 1 || !strings.Contains(out, "does-not-exist0") || !strings.Contains(out, "level=WARN") {
		t.Fatalf("want exactly one sniffer open warning naming the interface, got %d in:\n%s", n, out)
	}
}

// Every counter in the stats event must have one owner: a name shared by two
// components would silently overwrite the other's value.
func TestStatsCounterNamesAreUnique(t *testing.T) {
	var reg registrar.Stats
	tr := sniffer.NewTracker(sniffer.DefaultTrackerConfig(), nil, time.Now, slog.Default())
	ra := sniffer.NewRAMonitor(sniffer.DefaultRAMonitorConfig(), nil, time.Now, slog.Default())
	sn := &sniffer.Sniffer{Link: "eth0"}
	sn2 := &sniffer.Sniffer{Link: "eth1"}
	merged, dup := mergeCounters(reg.Snapshot(), map[string]uint64{"dropped": 0},
		tr.Counters(), ra.Counters(), sumCounters(sn.Counters(), sn2.Counters()))
	if len(dup) > 0 {
		t.Fatalf("counter names claimed by more than one component: %v", dup)
	}
	for _, name := range []string{"received", "dropped", "sniff_overflow", "nd_suppressed", "nd_sightings",
		"nd_invalid", "ra_seen_total", "ra_overflow", "ra_suppressed", "frames", "nd_malformed", "nd_not_nd"} {
		if _, ok := merged[name]; !ok {
			t.Errorf("stats counter %q missing", name)
		}
	}
	if _, dup := mergeCounters(map[string]uint64{"x": 1}, map[string]uint64{"x": 2}); len(dup) != 1 {
		t.Fatal("mergeCounters did not report a collision")
	}
}
