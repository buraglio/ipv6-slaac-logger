package main

import (
	"bytes"
	"context"
	"log/slog"
	"sync"

	"github.com/kardianos/service"
)

// svcHandler writes slog records to the OS service logger (Windows event log).
type svcHandler struct {
	inner slog.Handler
	buf   *bytes.Buffer
	mu    *sync.Mutex
	l     service.Logger
}

func newSvcHandler(l service.Logger, lvl slog.Level) *svcHandler {
	buf := &bytes.Buffer{}
	return &svcHandler{
		buf: buf, mu: &sync.Mutex{}, l: l,
		inner: slog.NewTextHandler(buf, &slog.HandlerOptions{Level: lvl, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey || a.Key == slog.LevelKey {
				return slog.Attr{}
			}
			return a
		}}),
	}
}

func (h *svcHandler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *svcHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	msg := string(bytes.TrimRight(h.buf.Bytes(), "\n"))
	switch {
	case r.Level >= slog.LevelError:
		return h.l.Error(msg)
	case r.Level >= slog.LevelWarn:
		return h.l.Warning(msg)
	}
	return h.l.Info(msg)
}

func (h *svcHandler) WithAttrs(a []slog.Attr) slog.Handler {
	c := *h
	c.inner = h.inner.WithAttrs(a)
	return &c
}

func (h *svcHandler) WithGroup(n string) slog.Handler {
	c := *h
	c.inner = h.inner.WithGroup(n)
	return &c
}
