package sniffer

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-slaac-logger/internal/nd"
)

const maxFrame = 65536

// FrameSource delivers raw Ethernet frames from one interface.
type FrameSource interface {
	// ReadFrame fills buf and returns the frame length and aux VLAN (0 if none).
	// It returns os.ErrDeadlineExceeded every ~1s when idle, so callers can observe ctx.
	ReadFrame(buf []byte) (n int, vlan uint16, err error)
	Close() error
}

// Sniffer captures ND traffic on one interface and feeds the Tracker and RAMonitor.
type Sniffer struct {
	Link    string
	Open    func(string) (FrameSource, error) // default Open
	Tracker *Tracker
	RA      *RAMonitor
	Log     *slog.Logger

	// backoff is a test hook; nil means logger.Backoff(n, 60s).
	backoff func(int) time.Duration

	frames, malformed, notND atomic.Uint64
}

// Counters returns cumulative frame counters.
func (s *Sniffer) Counters() map[string]uint64 {
	return map[string]uint64{
		"frames":       s.frames.Load(),
		"nd_malformed": s.malformed.Load(),
		"nd_not_nd":    s.notND.Load(),
	}
}

func (s *Sniffer) wait(ctx context.Context, attempt int) bool {
	d := logger.Backoff(attempt, 60*time.Second)
	if s.backoff != nil {
		d = s.backoff(attempt)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run opens the interface (retrying with backoff), reads and dispatches frames,
// and returns when ctx is done, or at once if capture is unsupported on this OS.
func (s *Sniffer) Run(ctx context.Context) {
	open := s.Open
	if open == nil {
		open = Open
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	buf := make([]byte, maxFrame)
	failures := 0 // consecutive failures in the current streak

	fail := func(err error) bool {
		if failures == 0 {
			log.Warn("sniffer capture failed; retrying", "link", s.Link, "err", err)
		}
		failures++
		return s.wait(ctx, failures)
	}

	for ctx.Err() == nil {
		src, err := open(s.Link)
		if errors.Is(err, errors.ErrUnsupported) {
			// Off Linux there is nothing to retry.
			log.Warn("sniffing unsupported on this OS", "link", s.Link)
			return
		}
		if err != nil {
			if !fail(err) {
				return
			}
			continue
		}
		log.Info("sniffer capturing", "link", s.Link)
		err = s.read(ctx, src, buf, func() {
			if failures > 0 {
				log.Info("sniffer capture recovered", "link", s.Link, "failures", failures)
				failures = 0
			}
		})
		_ = src.Close()
		if ctx.Err() != nil {
			return
		}
		if !fail(err) {
			return
		}
	}
}

// read loops until ctx is done (returns nil) or a non-timeout read error occurs.
func (s *Sniffer) read(ctx context.Context, src FrameSource, buf []byte, healthy func()) error {
	for ctx.Err() == nil {
		n, vlan, err := src.ReadFrame(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				healthy()
				continue
			}
			return err
		}
		healthy()
		s.frames.Add(1)
		s.dispatch(ctx, buf[:n], vlan)
	}
	return nil
}

func (s *Sniffer) dispatch(ctx context.Context, frame []byte, vlan uint16) {
	p, err := nd.Parse(frame, vlan)
	switch {
	case errors.Is(err, nd.ErrMalformed):
		s.malformed.Add(1)
		return
	case err != nil:
		// ErrNotND and anything unexpected.
		s.notND.Add(1)
		return
	}
	if p.Type == nd.TypeRA && s.RA != nil {
		s.RA.Observe(ctx, p, s.Link)
	}
	if s.Tracker != nil {
		for _, o := range Observations(p, s.Link) {
			s.Tracker.Observe(ctx, o)
		}
	}
}
