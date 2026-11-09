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
