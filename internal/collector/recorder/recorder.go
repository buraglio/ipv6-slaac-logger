// Package recorder commits changes to the store and, if the store fails,
// writes the events straight to the log sinks so nothing is lost silently.
package recorder

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-slaac-logger/internal/collector/store"
	"github.com/buraglio/ipv6-slaac-logger/internal/event"
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

	mu        sync.Mutex
	lastError time.Time // when the last store.error was sent
	failed    uint64    // failed commits since the last store.error was sent
}

// StoreErrorInterval is the minimum gap between store.error events.
const StoreErrorInterval = time.Minute

// Record commits c. On failure it sends c's events directly to every fallback
// sink and returns the store error. It also sends a store.error event, at most
// once per StoreErrorInterval; its count is the number of failed commits since
// the previous store.error was sent, including this one (so the first is 1).
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
	t := now()
	r.mu.Lock()
	r.failed++
	var se *event.Event
	if r.lastError.IsZero() || t.Sub(r.lastError) >= StoreErrorInterval {
		e := event.New(event.StoreError, t)
		e.Reason = err.Error()
		e.Count = r.failed
		se = &e
		r.failed = 0
		r.lastError = t
	}
	r.mu.Unlock()
	for _, s := range r.Fallback {
		for _, e := range c.Events {
			r.sendFallback(s, e)
		}
		if se != nil {
			r.sendFallback(s, *se)
		}
	}
	return err
}

// sendFallback delivers e to s, logging (not returning) any sink failure so
// the fallback path itself never loses an event silently.
func (r *Recorder) sendFallback(s logger.Sink, e event.Event) {
	if err := s.Send(e); err != nil && r.Log != nil {
		r.Log.Warn("recorder: fallback sink failed", "sink", s.Name(), "event", e.Type, "err", err)
	}
}
