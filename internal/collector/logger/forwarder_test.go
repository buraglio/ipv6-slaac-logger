package logger

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/store"
	"github.com/buraglio/ipv6-slaac-logger/internal/event"
)

type flakySink struct {
	mu     sync.Mutex
	failAt map[int]bool
	calls  int
	got    []string
}

func (s *flakySink) Name() string { return "flaky" }
func (s *flakySink) Close() error { return nil }
func (s *flakySink) Send(e event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failAt[s.calls] {
		return errors.New("down")
	}
	s.got = append(s.got, e.Reason)
	return nil
}

func storeWith(t *testing.T, reasons ...string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	addEvents(t, st, reasons...)
	return st
}

func addEvents(t *testing.T, st *store.Store, reasons ...string) {
	t.Helper()
	for _, r := range reasons {
		e := event.New(event.RegReject, time.Now())
		e.Reason = r
		if err := st.Commit(context.Background(), store.Change{Events: []event.Event{e}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestForwarderAtLeastOnce(t *testing.T) {
	ctx := context.Background()
	st := storeWith(t, "a", "b", "c")
	sink := &flakySink{failAt: map[int]bool{2: true}}
	f := &Forwarder{Name: "out", Src: st, Sink: sink}

	n, err := f.RunOnce(ctx)
	if n != 1 || err == nil {
		t.Fatalf("first run: n=%d err=%v", n, err)
	}
	if cur, _ := st.Cursor(ctx, "out"); cur != 1 {
		t.Fatalf("cursor after partial failure = %d, want 1", cur)
	}
	if n, err = f.RunOnce(ctx); n != 2 || err != nil {
		t.Fatalf("second run: n=%d err=%v", n, err)
	}
	if n, err = f.RunOnce(ctx); n != 0 || err != nil {
		t.Fatalf("third run: n=%d err=%v", n, err)
	}
	if got := sink.got; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("delivered %v", got)
	}
}

func TestForwarderResumesAfterRestart(t *testing.T) {
	ctx := context.Background()
	st := storeWith(t, "a", "b")
	first := &flakySink{}
	if _, err := (&Forwarder{Name: "out", Src: st, Sink: first}).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	addEvents(t, st, "c")
	second := &flakySink{}
	if _, err := (&Forwarder{Name: "out", Src: st, Sink: second}).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(second.got) != 1 || second.got[0] != "c" {
		t.Fatalf("restarted forwarder sent %v, want [c]", second.got)
	}
}

func TestForwarderBatch(t *testing.T) {
	st := storeWith(t, "a", "b", "c")
	f := &Forwarder{Name: "out", Src: st, Sink: &flakySink{}, Batch: 2}
	if n, _ := f.RunOnce(context.Background()); n != 2 {
		t.Fatalf("n = %d, want 2", n)
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 10: time.Minute, 100: time.Minute}
	for attempt, want := range cases {
		if got := Backoff(attempt, time.Minute); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}

func TestForwarderRunStopsOnCancel(t *testing.T) {
	st := storeWith(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Forwarder{Name: "out", Src: st, Sink: &flakySink{}, Poll: 10 * time.Millisecond}).Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
