package sniffer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	frames [][]byte
	i      int
}

func (f *fakeSource) ReadFrame(buf []byte) (int, uint16, error) {
	if f.i < len(f.frames) {
		n := copy(buf, f.frames[f.i])
		f.i++
		return n, 0, nil
	}
	time.Sleep(time.Millisecond)
	return 0, 0, os.ErrDeadlineExceeded
}
func (f *fakeSource) Close() error { return nil }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
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

func newSniffer(t *testing.T, open func(string) (FrameSource, error)) (*Sniffer, *fakeRec, *fakeRec, *syncBuf) {
	t.Helper()
	trec, rrec := &fakeRec{}, &fakeRec{}
	buf := &syncBuf{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	return &Sniffer{
		Link:    "eth0",
		Open:    open,
		Tracker: NewTracker(DefaultTrackerConfig(), trec, time.Now, log),
		RA:      NewRAMonitor(DefaultRAMonitorConfig(), rrec, time.Now, log),
		Log:     log,
		backoff: func(int) time.Duration { return time.Millisecond },
	}, trec, rrec, buf
}

func runFor(t *testing.T, s *Sniffer, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func (f *fakeRec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestSnifferDispatches(t *testing.T) {
	dad := frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, "::", "ff02::1:ff3b:21aa", 255, ns(hostLL))
	ra := frame(t, "02:00:00:00:00:01", "33:33:00:00:00:01", nil, "fe80::1", "ff02::1", 255,
		append(raMsg(), llopt(1, "02:00:00:00:00:01")...))
	src := &fakeSource{frames: [][]byte{dad, ra}}
	s, trec, rrec, _ := newSniffer(t, func(string) (FrameSource, error) { return src, nil })
	runFor(t, s, func() bool { return trec.count() > 0 && rrec.count() > 0 })
	if trec.count() == 0 {
		t.Error("tracker saw nothing")
	}
	if rrec.count() == 0 {
		t.Error("RA monitor saw nothing")
	}
	if got := s.Counters()["frames"]; got != 2 {
		t.Errorf("frames = %d, want 2", got)
	}
}

func TestSnifferCountsMalformed(t *testing.T) {
	bad := frame(t, hostMAC, "33:33:ff:3b:21:aa", nil, "::", "ff02::1:ff3b:21aa", 255, ns(hostLL))
	bad[len(bad)-1] ^= 0xff // corrupt checksum coverage
	src := &fakeSource{frames: [][]byte{bad}}
	s, trec, rrec, _ := newSniffer(t, func(string) (FrameSource, error) { return src, nil })
	runFor(t, s, func() bool { return s.Counters()["nd_malformed"] > 0 })
	if got := s.Counters()["nd_malformed"]; got != 1 {
		t.Errorf("nd_malformed = %d, want 1", got)
	}
	if trec.count() != 0 || rrec.count() != 0 {
		t.Error("unexpected event for malformed frame")
	}
}

func TestSnifferReopensAfterError(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	open := func(string) (FrameSource, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls <= 2 {
			return nil, os.ErrPermission
		}
		return &fakeSource{}, nil
	}
	s, _, _, buf := newSniffer(t, open)
	runFor(t, s, func() bool { return strings.Contains(buf.String(), "recovered") })
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Errorf("Warn count = %d, want 1\n%s", n, out)
	}
	if !strings.Contains(out, "recovered") {
		t.Errorf("no recovery log\n%s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("open calls = %d, want 3", calls)
	}
}

type errSource struct{}

func (errSource) ReadFrame([]byte) (int, uint16, error) { return 0, 0, os.ErrInvalid }
func (errSource) Close() error                          { return nil }

func TestSnifferReopensAfterReadError(t *testing.T) {
	const n = 3
	var mu sync.Mutex
	calls := 0
	open := func(string) (FrameSource, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls <= n {
			return errSource{}, nil
		}
		return &fakeSource{}, nil
	}
	s, _, _, buf := newSniffer(t, open)
	runFor(t, s, func() bool { return strings.Contains(buf.String(), "recovered") })
	out := buf.String()
	if c := strings.Count(out, "level=WARN"); c != 1 {
		t.Errorf("Warn count = %d, want 1\n%s", c, out)
	}
	if c := strings.Count(out, "recovered"); c != 1 {
		t.Errorf("recovered count = %d, want 1\n%s", c, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != n+1 {
		t.Errorf("open calls = %d, want %d", calls, n+1)
	}
}

func TestSnifferLogsCapturing(t *testing.T) {
	s, _, _, buf := newSniffer(t, func(string) (FrameSource, error) { return &fakeSource{}, nil })
	runFor(t, s, func() bool { return strings.Contains(buf.String(), "sniffer capturing") })
	out := buf.String()
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, `msg="sniffer capturing" link=eth0`) {
		t.Fatalf("no capture-start log:\n%s", out)
	}
}

// Off Linux, Open reports errors.ErrUnsupported: Run logs that once and
// returns instead of retrying forever.
func TestSnifferUnsupportedStops(t *testing.T) {
	calls := 0
	s, _, _, buf := newSniffer(t, func(string) (FrameSource, error) {
		calls++
		return nil, errors.ErrUnsupported
	})
	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying an unsupported capture")
	}
	out := buf.String()
	if calls != 1 || strings.Count(out, "sniffing unsupported on this OS") != 1 || strings.Contains(out, "retrying") {
		t.Fatalf("calls=%d log:\n%s", calls, out)
	}
}
