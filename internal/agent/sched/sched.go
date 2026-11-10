// Package sched decides when each local address must be (re)registered.
//
// It is pure logic: it starts no goroutines and reads no clock. Every method
// takes the current time, so callers (and tests) fully control time.
package sched

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
)

// Key identifies one scheduled address.
type Key struct {
	Addr    netip.Addr
	IfIndex int
}

// Params tunes the scheduler.
type Params struct {
	Heartbeat     time.Duration  // upper bound on the refresh interval (1h)
	StaticRefresh time.Duration  // refresh for static/infinite addresses (4h)
	InitialRT     time.Duration  // first retransmit delay (1s), doubling
	MaxTries      int            // transmissions per cycle (3)
	MinRefresh    time.Duration  // floor on the refresh interval (10s)
	Rand          func() float64 // [0,1); default math/rand/v2.Float64
	NewXID        func() [3]byte // transaction ID source
}

// DefaultParams returns the standard parameters.
func DefaultParams() Params {
	var counter uint32
	return Params{
		Heartbeat:     time.Hour,
		StaticRefresh: 4 * time.Hour,
		InitialRT:     time.Second,
		MaxTries:      3,
		MinRefresh:    10 * time.Second,
		Rand:          rand.Float64,
		NewXID: func() [3]byte {
			if x, err := dhcp6.RandomXID(); err == nil {
				return x
			}
			counter++
			return [3]byte{byte(counter >> 16), byte(counter >> 8), byte(counter)}
		},
	}
}

// Send is one transmission the caller must perform.
type Send struct {
	Key   Key
	Addr  addrsrc.Addr // Preferred/Valid recomputed for "now"
	XID   [3]byte
	Try   int      // 1..MaxTries
	Dests []string // still-unacknowledged destination names
}

type entry struct {
	addr      addrsrc.Addr
	xid       [3]byte
	xidFresh  bool // xid was generated for a cycle that has not started yet
	active    bool // a cycle is in progress (try >= 1 sent)
	start     time.Time
	refreshAt time.Time
	try       int
	dests     []string // unacknowledged destinations
	nextAt    time.Time
}

// Scheduler tracks per-address registration state. It is not safe for
// concurrent use: the owner must call it from a single goroutine.
type Scheduler struct {
	p       Params
	entries map[Key]*entry
}

// New returns an empty Scheduler. Nil Rand or NewXID are defaulted.
func New(p Params) *Scheduler {
	d := DefaultParams()
	if p.Rand == nil {
		p.Rand = d.Rand
	}
	if p.NewXID == nil {
		p.NewXID = d.NewXID
	}
	return &Scheduler{p: p, entries: make(map[Key]*entry)}
}

func keyOf(a addrsrc.Addr) Key { return Key{Addr: a.Addr, IfIndex: a.IfIndex} }

func compareKey(a, b Key) int {
	if c := a.Addr.Compare(b.Addr); c != 0 {
		return c
	}
	return a.IfIndex - b.IfIndex
}

// remaining returns stored minus the whole seconds elapsed since observed,
// floored at zero. Infinity is preserved.
func remaining(stored uint32, observed, now time.Time) uint32 {
	if stored == dhcp6.Infinity {
		return stored
	}
	el := now.Sub(observed)
	if el <= 0 {
		return stored
	}
	secs := int64(el / time.Second)
	if secs >= int64(stored) {
		return 0
	}
	return stored - uint32(secs)
}

// at returns a with Preferred/Valid recomputed for now.
func at(a addrsrc.Addr, now time.Time) addrsrc.Addr {
	a.Preferred = remaining(a.Preferred, a.ObservedAt, now)
	a.Valid = remaining(a.Valid, a.ObservedAt, now)
	a.ObservedAt = now
	return a
}

// RefreshInterval is how long after a cycle starts the next one begins.
func (p Params) RefreshInterval(a addrsrc.Addr, now time.Time) time.Duration {
	valid := remaining(a.Valid, a.ObservedAt, now)
	var d time.Duration
	if a.Origin == addrsrc.OriginStatic || valid == dhcp6.Infinity {
		d = min(p.StaticRefresh, p.Heartbeat)
	} else {
		secs := 0.8 * float64(valid) * (0.9 + 0.2*p.Rand())
		d = min(time.Duration(secs*float64(time.Second)), p.Heartbeat)
	}
	return max(d, p.MinRefresh)
}

// lifetimeChanged reports whether the expiry implied by (oldObs, oldLife)
// differs from that of (newObs, newLife) by more than 1% of newLife.
func lifetimeChanged(oldLife uint32, oldObs time.Time, newLife uint32, newObs time.Time) bool {
	oldInf, newInf := oldLife == dhcp6.Infinity, newLife == dhcp6.Infinity
	if oldInf || newInf {
		return oldInf != newInf
	}
	oldExp := oldObs.Add(time.Duration(oldLife) * time.Second)
	newExp := newObs.Add(time.Duration(newLife) * time.Second)
	delta := newExp.Sub(oldExp)
	if delta < 0 {
		delta = -delta
	}
	return delta.Seconds() > 0.01*float64(newLife)
}

// Update reconciles with a fresh listing. New keys are due now. Keys absent
// from addrs are removed and returned. A >1% lifetime change makes a key due
// now with a new XID.
func (s *Scheduler) Update(now time.Time, addrs []addrsrc.Addr) (removed []Key) {
	seen := make(map[Key]struct{}, len(addrs))
	for _, a := range addrs {
		k := keyOf(a)
		seen[k] = struct{}{}
		e, ok := s.entries[k]
		if !ok {
			s.entries[k] = &entry{addr: a, xid: s.p.NewXID(), xidFresh: true, nextAt: now}
			continue
		}
		changed := lifetimeChanged(e.addr.Valid, e.addr.ObservedAt, a.Valid, a.ObservedAt) ||
			lifetimeChanged(e.addr.Preferred, e.addr.ObservedAt, a.Preferred, a.ObservedAt)
		e.addr = a
		if changed {
			e.xid = s.p.NewXID()
			e.xidFresh = true
			e.active = false
			e.dests = nil
			e.nextAt = now
		}
	}
	for k := range s.entries {
		if _, ok := seen[k]; !ok {
			removed = append(removed, k)
			delete(s.entries, k)
		}
	}
	slices.SortFunc(removed, compareKey)
	return removed
}

// Due returns sends whose time has come. A key starting a new cycle takes its
// destination set from dests(addr). Calling Due advances retransmit timers
// (the caller sends exactly these).
func (s *Scheduler) Due(now time.Time, dests func(addrsrc.Addr) []string) []Send {
	keys := make([]Key, 0, len(s.entries))
	for k, e := range s.entries {
		if !e.nextAt.After(now) {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, compareKey)

	var out []Send
	for _, k := range keys {
		e := s.entries[k]
		if !e.active || e.try >= s.p.MaxTries || len(e.dests) == 0 {
			// Waiting for the next cycle (which is now due) or starting the first.
			if !s.startCycle(e, now, dests) {
				continue
			}
		}
		e.try++
		out = append(out, Send{
			Key:   k,
			Addr:  at(e.addr, now),
			XID:   e.xid,
			Try:   e.try,
			Dests: slices.Clone(e.dests),
		})
		if e.try < s.p.MaxTries {
			e.nextAt = e.start.Add(s.p.InitialRT * time.Duration(1<<e.try-1))
		} else {
			end := e.start.Add(s.p.InitialRT * time.Duration(1<<s.p.MaxTries-1))
			e.nextAt = laterOf(end, e.refreshAt)
		}
	}
	return out
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// startCycle begins a new cycle at now. It returns false when there is
// nothing to send, in which case the next cycle is scheduled.
func (s *Scheduler) startCycle(e *entry, now time.Time, dests func(addrsrc.Addr) []string) bool {
	if !e.xidFresh {
		e.xid = s.p.NewXID()
	}
	e.xidFresh = false
	e.start = now
	e.refreshAt = now.Add(s.p.RefreshInterval(e.addr, now))
	e.try = 0
	e.dests = slices.Clone(dests(at(e.addr, now)))
	if len(e.dests) == 0 {
		e.active = false
		e.nextAt = e.refreshAt
		return false
	}
	e.active = true
	return true
}

// Ack records that dest acknowledged the current cycle. It is ignored if xid
// is not the current XID.
func (s *Scheduler) Ack(key Key, xid [3]byte, dest string) {
	e, ok := s.entries[key]
	if !ok || !e.active || e.xid != xid {
		return
	}
	if i := slices.Index(e.dests, dest); i >= 0 {
		e.dests = slices.Delete(e.dests, i, i+1)
	}
	if len(e.dests) == 0 {
		e.nextAt = e.refreshAt
	}
}

// Forget drops key without reporting it as removed.
func (s *Scheduler) Forget(key Key) { delete(s.entries, key) }

// Next returns the earliest pending deadline.
func (s *Scheduler) Next() (time.Time, bool) {
	var best time.Time
	found := false
	for _, e := range s.entries {
		if !found || e.nextAt.Before(best) {
			best, found = e.nextAt, true
		}
	}
	return best, found
}

// Len returns the number of tracked keys.
func (s *Scheduler) Len() int { return len(s.entries) }
