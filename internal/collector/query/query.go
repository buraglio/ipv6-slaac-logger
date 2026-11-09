// Package query answers forensic questions from stored events.
package query

import (
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
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

// HolderAt replays one address's events (ordered by time) up to at.
func HolderAt(events []store.StoredEvent, at time.Time) (Holder, bool) {
	var h Holder
	held := false
	for _, se := range events {
		e := se.Event
		if e.TS.After(at) {
			break
		}
		switch e.Type {
		case event.RegAdd, event.RegConflict:
			h = Holder{DUID: e.DUID, MAC: e.MAC, Host: e.Host, Since: e.TS, Evidence: []store.StoredEvent{se}}
			held = true
		case event.RegChange:
			if held && e.DUID == h.DUID {
				h.MAC, h.Host = e.MAC, e.Host
				h.Evidence = append(h.Evidence, se)
			}
		case event.RegDereg, event.RegExpire:
			if held && e.DUID == h.DUID {
				h.Evidence = append(h.Evidence, se)
				held = false
			}
		}
	}
	return h, held
}
