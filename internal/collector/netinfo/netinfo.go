// Package netinfo reports the IPv6 prefixes configured on local interfaces.
package netinfo

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type cached struct {
	at  time.Time
	pfx []netip.Prefix
}

// Prefixes merges static per-interface prefixes with prefixes learned from
// the interface's addresses, refreshing learned ones after ttl.
type Prefixes struct {
	static map[string][]netip.Prefix
	ttl    time.Duration
	lookup func(string) ([]netip.Prefix, error)
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]cached
}

// NewPrefixes returns a Prefixes using InterfacePrefixes for learning.
func NewPrefixes(static map[string][]netip.Prefix, ttl time.Duration) *Prefixes {
	return &Prefixes{static: static, ttl: ttl, lookup: InterfacePrefixes, now: time.Now, cache: map[string]cached{}}
}

// For returns static plus learned prefixes for ifname.
func (p *Prefixes) For(ifname string) []netip.Prefix {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	c, ok := p.cache[ifname]
	if !ok || now.Sub(c.at) > p.ttl {
		learned, err := p.lookup(ifname)
		if err != nil {
			learned = nil
		}
		c = cached{at: now, pfx: learned}
		p.cache[ifname] = c
	}
	return append(slices.Clone(p.static[ifname]), c.pfx...)
}

// InterfacePrefixes returns the global/ULA IPv6 prefixes on interface name.
func InterfacePrefixes(name string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		ones, bits := ipn.Mask.Size()
		if !addr.Is6() || !addr.IsGlobalUnicast() || bits != 128 {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out, nil
}
