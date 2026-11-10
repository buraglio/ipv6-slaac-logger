package duid

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

var (
	fakeMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	fakeMAC2 = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	osDUID   = []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}
	cfgDUID  = []byte{0, 3, 0, 1, 9, 9, 9, 9, 9, 9}
	fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

func opts(dir string, os func() ([]byte, error), mac net.HardwareAddr) Options {
	return Options{
		StateDir:    dir,
		OSDUID:      os,
		HardwareMAC: func() (net.HardwareAddr, error) { return mac, nil },
		Now:         func() time.Time { return fixedNow },
		Log:         slog.New(slog.DiscardHandler),
	}
}

func hasOS() func() ([]byte, error) {
	return func() ([]byte, error) { return osDUID, nil }
}

func noOS() ([]byte, error) { return nil, ErrNotFound }

func stateDUID(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, `"duid":"`)
	if i < 0 {
		t.Fatalf("no duid in %s", s)
	}
	s = s[i+8:]
	d, err := dhcp6.ParseHex(s[:strings.Index(s, `"`)])
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestResolveOrder(t *testing.T) {
	t.Run("configured wins", func(t *testing.T) {
		o := opts(t.TempDir(), hasOS(), fakeMAC)
		o.Configured = cfgDUID
		r, err := Resolve(o)
		if err != nil || r.Source != SourceConfig || !bytes.Equal(r.DUID, cfgDUID) {
			t.Fatalf("got %+v, %v", r, err)
		}
	})
	t.Run("os wins over state", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := Resolve(opts(dir, noOS, fakeMAC)); err != nil {
			t.Fatal(err)
		}
		r, err := Resolve(opts(dir, hasOS(), fakeMAC))
		if err != nil || r.Source != SourceOS || !bytes.Equal(r.DUID, osDUID) {
			t.Fatalf("got %+v, %v", r, err)
		}
		if got := stateDUID(t, dir); !bytes.Equal(got, osDUID) {
			t.Fatalf("state holds %x", got)
		}
	})
	t.Run("state", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := Resolve(opts(dir, hasOS(), fakeMAC)); err != nil {
			t.Fatal(err)
		}
		r, err := Resolve(opts(dir, noOS, fakeMAC))
		if err != nil || r.Source != SourceState || !bytes.Equal(r.DUID, osDUID) {
			t.Fatalf("got %+v, %v", r, err)
		}
	})
	t.Run("generated", func(t *testing.T) {
		dir := t.TempDir()
		r, err := Resolve(opts(dir, noOS, fakeMAC))
		if err != nil || r.Source != SourceGenerated {
			t.Fatalf("got %+v, %v", r, err)
		}
		if dhcp6.DUIDTypeName(r.DUID) != "LLT" {
			t.Fatalf("type = %s", dhcp6.DUIDTypeName(r.DUID))
		}
		if mac, ok := dhcp6.MACFromDUID(r.DUID); !ok || !bytes.Equal(mac, fakeMAC) {
			t.Fatalf("mac = %v", mac)
		}
		if got := stateDUID(t, dir); !bytes.Equal(got, r.DUID) {
			t.Fatalf("state holds %x", got)
		}
		fi, err := os.Stat(filepath.Join(dir, StateFile))
		if err != nil {
			t.Fatal(err)
		}
		if runtimeUnix() && fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	})
	t.Run("no sources", func(t *testing.T) {
		o := opts(t.TempDir(), noOS, nil)
		o.HardwareMAC = func() (net.HardwareAddr, error) { return nil, errors.New("none") }
		if _, err := Resolve(o); err == nil {
			t.Fatal("expected error")
		}
	})
}

func runtimeUnix() bool { return os.PathSeparator == '/' }

func TestResolveKeepsSavedDUIDWhenOSDUIDGone(t *testing.T) {
	dir := t.TempDir()
	r1, err := Resolve(opts(dir, hasOS(), fakeMAC))
	if err != nil || r1.Source != SourceOS {
		t.Fatal(r1, err)
	}
	r2, err := Resolve(opts(dir, noOS, fakeMAC))
	if err != nil || r2.Source != SourceState || !bytes.Equal(r1.DUID, r2.DUID) {
		t.Fatalf("got %+v, %v", r2, err)
	}
}

func TestResolveCorruptStateBacksUp(t *testing.T) {
	dir := t.TempDir()
	orig := []byte(`{"duid":`)
	if err := os.WriteFile(filepath.Join(dir, StateFile), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	o := opts(dir, noOS, fakeMAC)
	o.Log = slog.New(slog.NewTextHandler(&buf, nil))
	r, err := Resolve(o)
	if err != nil || r.Source != SourceGenerated {
		t.Fatalf("got %+v, %v", r, err)
	}
	m, _ := filepath.Glob(filepath.Join(dir, StateFile+".corrupt-*"))
	if len(m) != 1 {
		t.Fatalf("backups = %v", m)
	}
	if b, _ := os.ReadFile(m[0]); !bytes.Equal(b, orig) {
		t.Fatalf("backup content %q", b)
	}
	log := buf.String()
	if !strings.Contains(log, "event=duid.regenerated") || !strings.Contains(log, "level=ERROR") || !strings.Contains(log, "backup=") {
		t.Fatalf("log = %s", log)
	}
	if got := stateDUID(t, dir); !bytes.Equal(got, r.DUID) {
		t.Fatalf("state holds %x", got)
	}
	// And the new state is usable.
	r2, err := Resolve(opts(dir, noOS, fakeMAC))
	if err != nil || r2.Source != SourceState {
		t.Fatalf("got %+v, %v", r2, err)
	}
}

func TestResolveStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	r1, err := Resolve(opts(dir, noOS, fakeMAC))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Resolve(opts(dir, noOS, fakeMAC2))
	if err != nil || !bytes.Equal(r1.DUID, r2.DUID) {
		t.Fatalf("got %x vs %x, %v", r1.DUID, r2.DUID, err)
	}
}

func TestResolveOSPermissionErrorSkipped(t *testing.T) {
	o := opts(t.TempDir(), func() ([]byte, error) { return nil, fs.ErrPermission }, fakeMAC)
	r, err := Resolve(o)
	if err != nil || r.Source != SourceGenerated {
		t.Fatalf("got %+v, %v", r, err)
	}
}

func TestOSDUIDLive(t *testing.T) {
	d, err := OSDUID()
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, fs.ErrPermission):
	case err != nil:
		t.Logf("OSDUID error (tolerated): %v", err)
	case len(d) < 4 || len(d) > 130:
		t.Fatalf("len = %d", len(d))
	}
}
