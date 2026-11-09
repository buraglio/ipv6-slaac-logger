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
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
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
		t.Skipf("collector could not start (no IPv6 loopback?): %v", err)
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
