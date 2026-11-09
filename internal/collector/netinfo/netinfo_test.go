package netinfo

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPrefixesMergeAndCache(t *testing.T) {
	static := map[string][]netip.Prefix{"eth0": {netip.MustParsePrefix("2001:db8:1::/64")}}
	p := NewPrefixes(static, 30*time.Second)
	calls := 0
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	p.lookup = func(string) ([]netip.Prefix, error) {
		calls++
		return []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/64")}, nil
	}
	if got := p.For("eth0"); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	p.For("eth0")
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1 within TTL", calls)
	}
	now = now.Add(31 * time.Second)
	p.For("eth0")
	if calls != 2 {
		t.Fatalf("lookup calls = %d, want 2 after TTL", calls)
	}
}

func TestPrefixesLookupErrorKeepsStatic(t *testing.T) {
	static := map[string][]netip.Prefix{"eth0": {netip.MustParsePrefix("2001:db8:1::/64")}}
	p := NewPrefixes(static, time.Second)
	p.lookup = func(string) ([]netip.Prefix, error) { return nil, errors.New("no such interface") }
	if got := p.For("eth0"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestInterfacePrefixesUnknown(t *testing.T) {
	if _, err := InterfacePrefixes("definitely-not-an-interface0"); err == nil {
		t.Fatal("expected error")
	}
}
