package recorder

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

type fakeCommitter struct{ err error }

func (f fakeCommitter) Commit(context.Context, store.Change) error { return f.err }

func TestRecordFallsBackWhenStoreFails(t *testing.T) {
	var buf bytes.Buffer
	r := &Recorder{
		Store:    fakeCommitter{err: errors.New("disk full")},
		Fallback: []logger.Sink{logger.NewWriterSink("buf", &buf)},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e := event.New(event.RegAdd, time.Now())
	if err := r.Record(context.Background(), store.Change{Events: []event.Event{e}}); err == nil {
		t.Fatal("expected the store error to be returned")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"event":"reg.add"`) ||
		!strings.Contains(lines[1], `"event":"store.error"`) || !strings.Contains(lines[1], "disk full") {
		t.Fatalf("fallback output:\n%s", buf.String())
	}
}

func TestRecordSuccessSkipsFallback(t *testing.T) {
	var buf bytes.Buffer
	r := &Recorder{Store: fakeCommitter{}, Fallback: []logger.Sink{logger.NewWriterSink("buf", &buf)}}
	if err := r.Record(context.Background(), store.Change{Events: []event.Event{event.New(event.RegAdd, time.Now())}}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("fallback written on success: %s", buf.String())
	}
}

type failingSink struct{ name string }

func (f failingSink) Name() string           { return f.name }
func (f failingSink) Send(event.Event) error { return errors.New("sink down") }
func (f failingSink) Close() error           { return nil }

func TestRecordLogsFallbackSinkFailure(t *testing.T) {
	var logBuf bytes.Buffer
	r := &Recorder{
		Store:    fakeCommitter{err: errors.New("disk full")},
		Fallback: []logger.Sink{failingSink{name: "bad-sink"}},
		Log:      slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	if err := r.Record(context.Background(), store.Change{Events: []event.Event{event.New(event.RegAdd, time.Now())}}); err == nil {
		t.Fatal("expected the store error to be returned")
	}
	out := logBuf.String()
	if !strings.Contains(out, "fallback sink failed") || !strings.Contains(out, "bad-sink") {
		t.Fatalf("fallback sink failure not logged:\n%s", out)
	}
}

func TestStoreErrorIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	r := &Recorder{
		Store:    fakeCommitter{err: errors.New("disk full")},
		Fallback: []logger.Sink{logger.NewWriterSink("buf", &buf)},
		Now:      func() time.Time { return now },
	}
	record := func() {
		t.Helper()
		if err := r.Record(context.Background(), store.Change{Events: []event.Event{event.New(event.RegAdd, now)}}); err == nil {
			t.Fatal("expected the store error to be returned")
		}
	}
	countLines := func(typ string) []string {
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if strings.Contains(l, `"event":"`+typ+`"`) {
				out = append(out, l)
			}
		}
		return out
	}
	for i := 0; i < 5; i++ {
		record()
		now = now.Add(10 * time.Second)
	}
	if n := len(countLines(event.RegAdd)); n != 5 {
		t.Fatalf("reg.add lines = %d, want 5 (originals always forwarded)", n)
	}
	errs := countLines(event.StoreError)
	if len(errs) != 1 || !strings.Contains(errs[0], `"count":1`) {
		t.Fatalf("store.error lines = %v, want exactly 1 with count 1", errs)
	}
	now = now.Add(61 * time.Second)
	record()
	errs = countLines(event.StoreError)
	if len(errs) != 2 || !strings.Contains(errs[1], `"count":5`) {
		t.Fatalf("store.error lines = %v, want a second one with count 5", errs)
	}
}
