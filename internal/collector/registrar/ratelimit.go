package registrar

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate is a token-bucket rate.
type Rate struct {
	PerSecond float64
	Burst     int
}

// Limits configures the three registration limiters.
type Limits struct {
	Global    Rate
	PerPrefix Rate // keyed by the source /64; a LAN shares one /64, so keep this generous
	PerDUID   Rate
}

// DefaultLimits suit a few thousand hosts per collector.
var DefaultLimits = Limits{
	Global:    Rate{PerSecond: 500, Burst: 2000},
	PerPrefix: Rate{PerSecond: 50, Burst: 500},
	PerDUID:   Rate{PerSecond: 2, Burst: 64},
}

// Limiter applies global, per-/64 and per-DUID token buckets.
type Limiter struct {
	global *rate.Limiter
	prefix *keyed
	duid   *keyed
}

// NewLimiter builds a Limiter from l.
func NewLimiter(l Limits) *Limiter {
	return &Limiter{
		global: rate.NewLimiter(rate.Limit(l.Global.PerSecond), l.Global.Burst),
		prefix: newKeyed(rate.Limit(l.PerPrefix.PerSecond), l.PerPrefix.Burst),
		duid:   newKeyed(rate.Limit(l.PerDUID.PerSecond), l.PerDUID.Burst),
	}
}

// AllowSource checks the per-/64 bucket for src, then the global bucket. The
// per-/64 check runs first so a flooding prefix cannot drain the global bucket.
func (l *Limiter) AllowSource(src netip.Addr, now time.Time) bool {
	p, err := src.Unmap().WithZone("").Prefix(64)
	if err != nil {
		return false
	}
	if !l.prefix.Allow(p.String(), now) {
		return false
	}
	return l.global.AllowN(now, 1)
}

// AllowDUID checks the per-DUID bucket. Callers must call it only after Validate succeeds.
func (l *Limiter) AllowDUID(duid []byte, now time.Time) bool {
	return l.duid.Allow(string(duid), now)
}

const (
	keyedIdle       = 10 * time.Minute
	keyedMaxEntries = 100000
)

type keyedEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// keyed is a map of token buckets with idle eviction to bound memory.
type keyed struct {
	mu        sync.Mutex
	r         rate.Limit
	burst     int
	max       int
	m         map[string]*keyedEntry
	lastSweep time.Time
}

func newKeyed(r rate.Limit, burst int) *keyed {
	return &keyed{r: r, burst: burst, max: keyedMaxEntries, m: map[string]*keyedEntry{}}
}

// sweep evicts entries idle longer than keyedIdle.
func (k *keyed) sweep(now time.Time) {
	for key, e := range k.m {
		if now.Sub(e.seen) > keyedIdle {
			delete(k.m, key)
		}
	}
	k.lastSweep = now
}

// Allow reports whether key has a token at now. A new key is refused, without
// being inserted, while the map is full even after an idle sweep (fail closed).
func (k *keyed) Allow(key string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now.Sub(k.lastSweep) > time.Minute {
		k.sweep(now)
	}
	e, ok := k.m[key]
	if !ok {
		if len(k.m) >= k.max {
			k.sweep(now)
			if len(k.m) >= k.max {
				return false
			}
		}
		e = &keyedEntry{lim: rate.NewLimiter(k.r, k.burst)}
		k.m[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}
