// Package query answers forensic questions from stored events.
package query

import (
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Holder is who held an address at a point in time.
type Holder struct {
	DUID     string
	MAC      string
	Host     string
	Since    time.Time
	Evidence []store.StoredEvent
}

// HolderAt reports who held one address's binding at time at. events must be
// ordered by time. Events after at are ignored, with one exception: the sweep
// stamps reg.expire at sweep time, not at the real expiry, so an expire event
// after at ends the holding if the binding's lifetime (LastSeen + Valid, with
// InfiniteTTL for an infinite lifetime) had already run out by at.
func HolderAt(events []store.StoredEvent, at time.Time) (Holder, bool) {
	var h Holder
	held := false
	var setTS time.Time // TS of the latest add, conflict or change applied to h
	for _, se := range events {
		e := se.Event
		if e.TS.After(at) {
			continue
		}
		switch e.Type {
		case event.RegAdd, event.RegConflict:
			h = Holder{DUID: e.DUID, MAC: e.MAC, Host: e.Host, Since: e.TS, Evidence: []store.StoredEvent{se}}
			held = true
			setTS = e.TS
		case event.RegChange:
			if held && e.DUID == h.DUID {
				h.MAC, h.Host = e.MAC, e.Host
				h.Evidence = append(h.Evidence, se)
				setTS = e.TS
			}
		case event.RegDereg, event.RegExpire:
			if held && e.DUID == h.DUID {
				h.Evidence = append(h.Evidence, se)
				held = false
			}
		}
	}
	if !held {
		return h, false
	}
	for _, se := range events {
		e := se.Event
		if e.Type != event.RegExpire || e.DUID != h.DUID || !e.TS.After(setTS) {
			continue
		}
		if !expiryOf(e).After(at) {
			h.Evidence = append(h.Evidence, se)
			return h, false
		}
		break
	}
	return h, true
}

// expiryOf is when a reg.expire's binding really ran out: LastSeen plus the
// valid lifetime. It falls back to the event time when either is missing.
func expiryOf(e event.Event) time.Time {
	if e.LastSeen == nil || e.Valid == nil {
		return e.TS
	}
	if *e.Valid == dhcp6.Infinity {
		return e.LastSeen.Add(registrar.InfiniteTTL)
	}
	return e.LastSeen.Add(time.Duration(*e.Valid) * time.Second)
}
