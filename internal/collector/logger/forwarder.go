package logger

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/store"
)

// Source is the subset of *store.Store a Forwarder needs.
type Source interface {
	EventsAfter(ctx context.Context, afterID int64, limit int) ([]store.StoredEvent, error)
	Cursor(ctx context.Context, name string) (int64, error)
	SetCursor(ctx context.Context, name string, id int64) error
}

// Forwarder delivers stored events to one Sink, at least once, tracking
// progress in a named cursor so restarts resume where they left off.
type Forwarder struct {
	Name       string
	Src        Source
	Sink       Sink
	Poll       time.Duration // idle poll interval; default 1s
	Batch      int           // events per RunOnce; default 256
	MaxBackoff time.Duration // default 60s
	Log        *slog.Logger
}

func (f *Forwarder) batch() int {
	if f.Batch > 0 {
		return f.Batch
	}
	return 256
}

func (f *Forwarder) poll() time.Duration {
	if f.Poll > 0 {
		return f.Poll
	}
	return time.Second
}

func (f *Forwarder) maxBackoff() time.Duration {
	if f.MaxBackoff > 0 {
		return f.MaxBackoff
	}
	return time.Minute
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

// RunOnce sends up to one batch of pending events. On a send error it saves
// progress through the last delivered event and returns the error.
func (f *Forwarder) RunOnce(ctx context.Context) (int, error) {
	cur, err := f.Src.Cursor(ctx, f.Name)
	if err != nil {
		return 0, err
	}
	evs, err := f.Src.EventsAfter(ctx, cur, f.batch())
	if err != nil {
		return 0, err
	}
	sent, last := 0, cur
	for _, se := range evs {
		if err := f.Sink.Send(se.Event); err != nil {
			if last != cur {
				err = errors.Join(err, f.Src.SetCursor(ctx, f.Name, last))
			}
			return sent, err
		}
		last = se.ID
		sent++
	}
	if last != cur {
		if err := f.Src.SetCursor(ctx, f.Name, last); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// Run forwards until ctx is cancelled, backing off exponentially on errors.
func (f *Forwarder) Run(ctx context.Context) {
	attempt := 0
	for {
		n, err := f.RunOnce(ctx)
		var wait time.Duration
		switch {
		case err != nil:
			attempt++
			wait = Backoff(attempt, f.maxBackoff())
			f.log().Warn("forwarder: delivery failed", "sink", f.Sink.Name(), "attempt", attempt, "retry_in", wait, "err", err)
		case n == f.batch():
			attempt = 0 // more pending; loop immediately
		default:
			attempt = 0
			wait = f.poll()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Backoff returns 1s, 2s, 4s, ... capped at max.
func Backoff(attempt int, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Second << min(attempt-1, 16)
	if d > max || d <= 0 {
		return max
	}
	return d
}
