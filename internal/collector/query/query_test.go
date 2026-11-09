package query

import (
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func se(id int64, typ, duid, mac string, ts time.Time) store.StoredEvent {
	e := event.New(typ, ts)
	e.DUID, e.MAC = duid, mac
	return store.StoredEvent{ID: id, Event: e}
}

// expire is a reg.expire stamped at ts whose binding last refreshed at lastSeen with valid lifetime valid.
func expire(id int64, duid string, ts, lastSeen time.Time, valid uint32) store.StoredEvent {
	e := event.New(event.RegExpire, ts)
	e.DUID = duid
	e.LastSeen, e.Valid = event.TimePtr(lastSeen), event.U32(valid)
	return store.StoredEvent{ID: id, Event: e}
}

func TestHolderAt(t *testing.T) {
	base := []store.StoredEvent{
		se(1, event.RegAdd, "A", "m1", t0),
		se(2, event.RegChange, "A", "m2", t0.Add(time.Hour)),
		se(3, event.RegConflict, "B", "m3", t0.Add(2*time.Hour)),
		se(4, event.RegExpire, "B", "m3", t0.Add(3*time.Hour)),
	}
	cases := []struct {
		name string
		evs  []store.StoredEvent
		at   time.Time
		held bool
		duid string
		mac  string
	}{
		{"before first event", base, t0.Add(-time.Minute), false, "", ""},
		{"after add", base, t0.Add(30 * time.Minute), true, "A", "m1"},
		{"after change", base, t0.Add(90 * time.Minute), true, "A", "m2"},
		{"after conflict takeover", base, t0.Add(150 * time.Minute), true, "B", "m3"},
		{"after expire", base, t0.Add(4 * time.Hour), false, "", ""},
		{"dereg ends holding", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			se(2, event.RegDereg, "A", "m1", t0.Add(time.Hour)),
		}, t0.Add(2 * time.Hour), false, "", ""},
		{"dereg not yet applied", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			se(2, event.RegDereg, "A", "m1", t0.Add(time.Hour)),
		}, t0.Add(30 * time.Minute), true, "A", "m1"},
		{"expire for other DUID does not end holding", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			expire(2, "B", t0.Add(time.Hour), t0, 10),
		}, t0.Add(2 * time.Hour), true, "A", "m1"},
		{"expire sweep-stamped late, real end before at", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			expire(2, "A", t0.Add(3*time.Hour), t0, 3600),
		}, t0.Add(2 * time.Hour), false, "", ""},
		{"expire real end after at", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			expire(2, "A", t0.Add(3*time.Hour), t0, 3*3600),
		}, t0.Add(2 * time.Hour), true, "A", "m1"},
		{"infinite lifetime uses InfiniteTTL", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			expire(2, "A", t0.Add(13*time.Hour), t0, dhcp6.Infinity),
		}, t0.Add(11 * time.Hour), true, "A", "m1"},
		{"event exactly at at applies (add)", base[:1], t0, true, "A", "m1"},
		{"event exactly at at applies (dereg)", []store.StoredEvent{
			se(1, event.RegAdd, "A", "m1", t0),
			se(2, event.RegDereg, "A", "m1", t0.Add(time.Hour)),
		}, t0.Add(time.Hour), false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, held := HolderAt(tc.evs, tc.at)
			if held != tc.held {
				t.Fatalf("held = %v, want %v (holder %+v)", held, tc.held, h)
			}
			if held && (h.DUID != tc.duid || h.MAC != tc.mac) {
				t.Fatalf("holder = %+v, want duid=%s mac=%s", h, tc.duid, tc.mac)
			}
		})
	}
	h, _ := HolderAt(base, t0.Add(90*time.Minute))
	if len(h.Evidence) != 2 || !h.Since.Equal(t0) {
		t.Errorf("evidence/since wrong: %+v", h)
	}
}
