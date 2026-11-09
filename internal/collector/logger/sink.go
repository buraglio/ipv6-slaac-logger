package logger

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Sink delivers one event. Implementations are safe for concurrent use.
type Sink interface {
	Name() string
	Send(e event.Event) error
	Close() error
}

// unixWriteTimeout bounds one datagram write to the local syslog socket.
const unixWriteTimeout = 2 * time.Second

// UnixSink writes to a local syslog datagram socket such as /dev/log.
type UnixSink struct {
	path string
	fac  Facility
	pid  int
	mu   sync.Mutex
	conn net.Conn
}

// NewUnixSink returns a sink for the unixgram socket at path.
func NewUnixSink(path string, f Facility) *UnixSink {
	return &UnixSink{path: path, fac: f, pid: os.Getpid()}
}

func (s *UnixSink) Name() string { return "unix:" + s.path }

func (s *UnixSink) Send(e event.Event) error {
	line, err := FormatLocal(e, s.fac, s.pid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := net.Dial("unixgram", s.path)
		if err != nil {
			return fmt.Errorf("logger: dial %s: %w", s.path, err)
		}
		s.conn = c
	}
	// A wedged syslog daemon must not stall the collector (or the recorder's
	// store-failure fallback) indefinitely.
	_ = s.conn.SetWriteDeadline(time.Now().Add(unixWriteTimeout))
	if _, err := s.conn.Write(line); err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("logger: write %s: %w", s.path, err)
	}
	return nil
}

func (s *UnixSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// StreamSink sends RFC 5424 messages with octet-counting framing over TCP or TLS,
// reconnecting lazily after errors.
type StreamSink struct {
	name     string
	dial     func() (net.Conn, error)
	fac      Facility
	hostname string
	pid      int
	mu       sync.Mutex
	conn     net.Conn
}

// NewTCPSink returns a plain-TCP syslog sink.
func NewTCPSink(addr string, f Facility, hostname string) *StreamSink {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &StreamSink{
		name: "tcp:" + addr, fac: f, hostname: hostname, pid: os.Getpid(),
		dial: func() (net.Conn, error) { return d.Dial("tcp", addr) },
	}
}

// NewTLSSink returns a TLS syslog sink (RFC 5425).
func NewTLSSink(addr string, conf *tls.Config, f Facility, hostname string) *StreamSink {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: conf}
	return &StreamSink{
		name: "tls:" + addr, fac: f, hostname: hostname, pid: os.Getpid(),
		dial: func() (net.Conn, error) { return d.Dial("tcp", addr) },
	}
}

func (s *StreamSink) Name() string { return s.name }

func (s *StreamSink) Send(e event.Event) error {
	msg, err := FormatRFC5424(e, s.fac, s.hostname, s.pid)
	if err != nil {
		return err
	}
	frame := OctetFrame(msg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := s.dial()
		if err != nil {
			return fmt.Errorf("logger: dial %s: %w", s.name, err)
		}
		s.conn = c
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(frame); err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("logger: write %s: %w", s.name, err)
	}
	return nil
}

func (s *StreamSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// WriterSink writes one JSON object per line (for stdout/journald/containers).
type WriterSink struct {
	name string
	mu   sync.Mutex
	w    io.Writer
}

// NewWriterSink returns a sink writing JSON lines to w.
func NewWriterSink(name string, w io.Writer) *WriterSink { return &WriterSink{name: name, w: w} }

func (s *WriterSink) Name() string { return s.name }

func (s *WriterSink) Send(e event.Event) error {
	j, err := e.JSON()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(j, '\n'))
	return err
}

func (s *WriterSink) Close() error { return nil }
