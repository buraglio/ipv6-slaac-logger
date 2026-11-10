// Package query answers forensic questions from stored events.
package query

import (
	"slices"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-slaac-logger/internal/collector/store"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-slaac-logger/internal/event"
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

// SightedAt returns the MACs the sniffer saw using the queried address at time
// at, sorted and deduplicated. A MAC counts when an nd.new/nd.conflict ->
// nd.expire window from events covers at (the window ends at the expire's
// LastSeen, the last real sighting, not at the sweep time that stamped the
// event), or when a stored sighting's [FirstSeen, LastSeen] covers at (expired
// rows included). events must be ordered by time. MACs with a proxy-suspect
// sighting are excluded.
func SightedAt(events []store.StoredEvent, current []store.Sighting, at time.Time) []string {
	suspect := map[string]bool{}
	set := map[string]bool{}
	for _, s := range current {
		if s.ProxySuspect {
			suspect[s.MAC] = true
			continue
		}
		// Expired rows count too: their [first_seen, last_seen] is accurate,
		// and their nd.expire may never have been logged.
		if !s.FirstSeen.After(at) && !s.LastSeen.Before(at) {
			set[s.MAC] = true
		}
	}
	open := map[string]time.Time{} // MAC -> start of its open window
	for _, se := range events {
		e := se.Event
		switch e.Type {
		case event.NDNew, event.NDConflict:
			if _, ok := open[e.MAC]; !ok {
				open[e.MAC] = e.TS
			}
		case event.NDExpire:
			start, ok := open[e.MAC]
			if !ok {
				continue
			}
			delete(open, e.MAC)
			end := e.TS
			if e.LastSeen != nil {
				end = *e.LastSeen
			}
			if !start.After(at) && !end.Before(at) {
				set[e.MAC] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		if !suspect[m] {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}
