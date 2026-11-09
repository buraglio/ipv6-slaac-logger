package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

func TestStreamSinkReconnects(t *testing.T) {
	var mu sync.Mutex
	var got []string
	dials := 0
	s := &StreamSink{name: "test", fac: 21, hostname: "h", pid: 1}
	s.dial = func() (net.Conn, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("connection refused")
		}
		client, server := net.Pipe()
		go func() {
			buf := make([]byte, 4096)
			n, _ := server.Read(buf)
			mu.Lock()
			got = append(got, string(buf[:n]))
			mu.Unlock()
			server.Close()
		}()
		return client, nil
	}
	e := event.New(event.RegAdd, time.Now())
	if err := s.Send(e); err == nil {
		t.Fatal("first send should fail while the server is down")
	}
	if err := s.Send(e); err != nil {
		t.Fatalf("second send: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !regexp.MustCompile(`^\d+ <174>1 `).MatchString(got[0]) {
		t.Fatalf("frames = %q", got)
	}
}

func TestUnixSink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram sockets are not available on Windows")
	}
	dir, err := os.MkdirTemp("", "ral") // short path: macOS limits socket paths to 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "log.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := NewUnixSink(sock, 21)
	defer s.Close()
	if err := s.Send(event.New(event.RegAdd, time.Now())); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	line := string(buf[:n])
	if !strings.HasPrefix(line, "<174>") || !strings.Contains(line, "ra-logger[") || !strings.Contains(line, `"event":"reg.add"`) {
		t.Fatalf("line = %q", line)
	}
}

func TestWriterSink(t *testing.T) {
	var buf bytes.Buffer
	s := NewWriterSink("stdout", &buf)
	if err := s.Send(event.New(event.RegAdd, time.Now())); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("line = %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil || m["event"] != "reg.add" {
		t.Fatalf("not JSON: %q %v", line, err)
	}
}
