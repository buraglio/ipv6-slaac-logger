package query

import (
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func se(id int64, typ, duid, mac string, ts time.Time) store.StoredEvent {
	e := event.New(typ, ts)
	e.DUID, e.MAC = duid, mac
	return store.StoredEvent{ID: id, Event: e}
}

func TestHolderAt(t *testing.T) {
	evs := []store.StoredEvent{
		se(1, event.RegAdd, "A", "m1", t0),
		se(2, event.RegChange, "A", "m2", t0.Add(time.Hour)),
		se(3, event.RegConflict, "B", "m3", t0.Add(2*time.Hour)),
		se(4, event.RegExpire, "B", "m3", t0.Add(3*time.Hour)),
	}
	cases := []struct {
		at   time.Time
		held bool
		duid string
		mac  string
	}{
		{t0.Add(-time.Minute), false, "", ""},
		{t0.Add(30 * time.Minute), true, "A", "m1"},
		{t0.Add(90 * time.Minute), true, "A", "m2"},
		{t0.Add(150 * time.Minute), true, "B", "m3"},
		{t0.Add(4 * time.Hour), false, "B", "m3"},
	}
	for _, tc := range cases {
		h, held := HolderAt(evs, tc.at)
		if held != tc.held || (tc.duid != "" && (h.DUID != tc.duid || h.MAC != tc.mac)) {
			t.Errorf("at %v: held=%v holder=%+v", tc.at, held, h)
		}
	}
	h, _ := HolderAt(evs, t0.Add(90*time.Minute))
	if len(h.Evidence) != 2 || !h.Since.Equal(t0) {
		t.Errorf("evidence/since wrong: %+v", h)
	}
}
