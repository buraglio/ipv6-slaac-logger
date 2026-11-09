// Package addrsrc enumerates and watches the host's IPv6 addresses.
package addrsrc

import (
	"cmp"
	"context"
	"net/netip"
	"path"
	"slices"
	"time"
)

// Origin describes how an address was configured.
type Origin string

const (
	OriginSLAAC     Origin = "slaac"
	OriginTemporary Origin = "temporary"
	OriginStatic    Origin = "static"
	OriginDHCPv6    Origin = "dhcpv6"
	OriginOther     Origin = "other"
)

// State is the usability of an address.
type State uint8

const (
	StateReady    State = iota
	StateNotReady       // tentative, optimistic or detached
	StateDuplicate
)

// Addr is one IPv6 address on a local interface.
type Addr struct {
	Addr       netip.Addr // no zone
	IfName     string
	IfIndex    int
	Origin     Origin
	Preferred  uint32 // remaining seconds at ObservedAt; dhcp6.Infinity = infinite
	Valid      uint32
	State      State
	ObservedAt time.Time
}

// Source lists and watches local addresses.
type Source interface {
	List() ([]Addr, error)
	// Watch returns a channel that receives (coalesced, non-blocking) whenever the OS
	// reports an address change. The channel closes when ctx is done.
	Watch(ctx context.Context) (<-chan struct{}, error)
}

// Eligible reports whether a is a ready, SLAAC/temporary/static global unicast
// (including ULA) address.
func Eligible(a Addr) bool {
	if a.State != StateReady {
		return false
	}
	switch a.Origin {
	case OriginSLAAC, OriginTemporary, OriginStatic:
	default:
		return false
	}
	ip := a.Addr
	return ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified()
}

// IfFilter selects interfaces by glob pattern.
type IfFilter struct{ Include, Exclude []string }

// Match reports whether ifname passes the filter. Empty Include matches all;
// Exclude wins over Include.
func (f IfFilter) Match(ifname string) bool {
	if slices.ContainsFunc(f.Exclude, func(p string) bool { ok, _ := path.Match(p, ifname); return ok }) {
		return false
	}
	if len(f.Include) == 0 {
		return true
	}
	return slices.ContainsFunc(f.Include, func(p string) bool { ok, _ := path.Match(p, ifname); return ok })
}

// Select returns the eligible addresses passing f, sorted by (IfIndex, Addr).
func Select(all []Addr, f IfFilter) []Addr {
	var out []Addr
	for _, a := range all {
		if Eligible(a) && f.Match(a.IfName) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(x, y Addr) int {
		if c := cmp.Compare(x.IfIndex, y.IfIndex); c != 0 {
			return c
		}
		return x.Addr.Compare(y.Addr)
	})
	return out
}
