// Package recorder commits changes to the store and, if the store fails,
// writes the events straight to the log sinks so nothing is lost silently.
package recorder

import (
	"context"
	"log/slog"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Committer is the subset of *store.Store the Recorder needs.
type Committer interface {
	Commit(ctx context.Context, c store.Change) error
}

// Recorder is the single write path for collector components.
type Recorder struct {
	Store    Committer
	Fallback []logger.Sink
	Log      *slog.Logger
	Now      func() time.Time
}

// Record commits c. On failure it sends c's events plus a store.error event
// directly to every fallback sink and returns the store error.
func (r *Recorder) Record(ctx context.Context, c store.Change) error {
	err := r.Store.Commit(ctx, c)
	if err == nil {
		return nil
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	if r.Log != nil {
		r.Log.Error("recorder: store commit failed; writing events directly to sinks", "err", err)
	}
	se := event.New(event.StoreError, now())
	se.Reason = err.Error()
	for _, s := range r.Fallback {
		for _, e := range c.Events {
			_ = s.Send(e)
		}
		_ = s.Send(se)
	}
	return err
}
