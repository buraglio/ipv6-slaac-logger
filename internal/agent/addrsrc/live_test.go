package addrsrc

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// supported reports whether this OS has a real address source (not _other).
func supported() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return true
	}
	return false
}

func TestListLive(t *testing.T) {
	all, err := New().List()
	if !supported() && errors.Is(err, errors.ErrUnsupported) {
		t.Skip("no address source on this OS")
	}
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	llPrefix := netip.MustParsePrefix("fe80::/10")
	for _, a := range all {
		t.Logf("all: %-8s idx=%-3d %-40s %-9s state=%d pref=%d valid=%d",
			a.IfName, a.IfIndex, a.Addr, a.Origin, a.State, a.Preferred, a.Valid)
		if a.Addr.Zone() != "" {
			t.Errorf("%v: Addr carries a zone", a.Addr)
		}
		if a.Addr == netip.IPv6Loopback() && Eligible(a) {
			t.Errorf("::1 must not be eligible")
		}
		if llPrefix.Contains(a.Addr) && Eligible(a) {
			t.Errorf("%v: link-local must not be eligible", a.Addr)
		}
		if a.IfName == "" || a.IfIndex <= 0 {
			t.Errorf("%v: IfName %q IfIndex %d", a.Addr, a.IfName, a.IfIndex)
		}
	}
	for _, a := range Select(all, IfFilter{}) {
		t.Logf("selected: %s %s %s pref=%d valid=%d", a.IfName, a.Addr, a.Origin, a.Preferred, a.Valid)
	}
}

func TestWatchClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := New().Watch(ctx)
	if errors.Is(err, errors.ErrUnsupported) {
		cancel()
		t.Skip("no watch on this OS")
	}
	if err != nil {
		cancel()
		t.Fatalf("Watch: %v", err)
	}
	cancel()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("watch channel not closed within 3s of cancel")
		}
	}
}
