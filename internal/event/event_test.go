package event

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEventJSONShape(t *testing.T) {
	e := New(RegAdd, time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC))
	e.Addr = "2001:db8:10::5"
	e.DUID = "00:03:00:01:5c:1e:9a:3b:21:aa"
	e.DUIDType = "LL"
	e.MAC = "5c:1e:9a:3b:21:aa"
	e.MACSrc = "duid"
	e.Origin = "agent"
	e.Host = "lab-mbp"
	e.Via = "multicast"
	e.Link = "eth0"
	e.Preferred = U32(14400)
	e.Valid = U32(86400)
	e.XID = "a1b2c3"
	got, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ts":"2026-11-08T21:14:03.412Z","event":"reg.add","addr":"2001:db8:10::5","duid":"00:03:00:01:5c:1e:9a:3b:21:aa","duid_type":"LL","mac":"5c:1e:9a:3b:21:aa","mac_src":"duid","origin":"agent","host":"lab-mbp","via":"multicast","link":"eth0","preferred_lft":14400,"valid_lft":86400,"xid":"a1b2c3"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestZeroLifetimesAreEmitted(t *testing.T) {
	e := New(RegDereg, time.Now())
	e.Preferred, e.Valid = U32(0), U32(0)
	got, _ := e.JSON()
	if !bytes.Contains(got, []byte(`"preferred_lft":0`)) || !bytes.Contains(got, []byte(`"valid_lft":0`)) {
		t.Fatalf("zero lifetimes missing: %s", got)
	}
}

func TestCEEPrefix(t *testing.T) {
	got, err := New(Stats, time.Now()).CEE()
	if err != nil || !strings.HasPrefix(string(got), "@cee:{") {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestHostileStringsStaySingleLine(t *testing.T) {
	e := New(RegAdd, time.Now())
	e.Host = "evil\nhost\r<13>1 2026-01-01T00:00:00Z fake ra-logger - - forged"
	e.Reason = "x\x00y"
	got, err := e.CEE()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control bytes leaked into record: %q", got)
	}
}

func TestNewTruncatesToMillisUTC(t *testing.T) {
	loc := time.FixedZone("X", 3600)
	e := New(RegAdd, time.Date(2026, 1, 1, 0, 0, 0, 123_456_789, loc))
	if e.TS.Location() != time.UTC || e.TS.Nanosecond() != 123_000_000 {
		t.Fatalf("TS = %v", e.TS)
	}
}

func TestSeverity(t *testing.T) {
	cases := map[string]Severity{
		RegAdd: SevInfo, NDNew: SevInfo, RASeen: SevInfo, Stats: SevInfo,
		RegConflict: SevNotice, NDConflict: SevNotice, RAChange: SevNotice, RegExpire: SevNotice, NDExpire: SevNotice,
		RegReject: SevWarning, StoreError: SevWarning,
	}
	for typ, want := range cases {
		if got := New(typ, time.Now()).Severity(); got != want {
			t.Errorf("%s: severity %d, want %d", typ, got, want)
		}
	}
}

func TestTimestampsAreFixedWidth(t *testing.T) {
	e := New(RegExpire, time.Date(2026, 11, 8, 21, 14, 3, 0, time.UTC))
	e.FirstSeen = TimePtr(time.Date(2026, 11, 8, 20, 0, 0, 120_000_000, time.UTC))
	e.LastSeen = TimePtr(time.Date(2026, 11, 8, 21, 0, 0, 0, time.FixedZone("X", 3600)))
	got, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"ts":"2026-11-08T21:14:03.000Z"`,
		`"first_seen":"2026-11-08T20:00:00.120Z"`,
		`"last_seen":"2026-11-08T20:00:00.000Z"`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	var back Event
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if !back.TS.Equal(e.TS) || back.FirstSeen == nil || !back.FirstSeen.Equal(*e.FirstSeen) || !back.LastSeen.Equal(*e.LastSeen) || back.Type != RegExpire {
		t.Fatalf("round trip = %+v", back)
	}
	// Records written before fixed-width timestamps still decode.
	var old Event
	if err := json.Unmarshal([]byte(`{"ts":"2026-11-08T21:14:03Z","event":"reg.add","first_seen":"2026-11-08T20:00:00.12Z"}`), &old); err != nil ||
		!old.TS.Equal(e.TS) || !old.FirstSeen.Equal(*e.FirstSeen) {
		t.Fatalf("old format: %+v %v", old, err)
	}
}

func TestFieldOrderPreserved(t *testing.T) {
	e := New(RegConflict, time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC))
	e.Addr, e.PrevDUID, e.Reason, e.Src, e.Count = "a", "p", "r", "s", 3
	e.FirstSeen, e.LastSeen = TimePtr(e.TS), TimePtr(e.TS)
	e.Counters = map[string]uint64{"x": 1}
	got, _ := e.JSON()
	want := `{"ts":"2026-11-08T21:14:03.412Z","event":"reg.conflict","addr":"a","prev_duid":"p","first_seen":"2026-11-08T21:14:03.412Z","last_seen":"2026-11-08T21:14:03.412Z","reason":"r","src":"s","count":3,"counters":{"x":1}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestHTMLNotEscaped(t *testing.T) {
	e := New(RegAdd, time.Now())
	e.Host = "<a&b>"
	got, _ := e.JSON()
	if !bytes.Contains(got, []byte(`"host":"<a&b>"`)) || bytes.HasSuffix(got, []byte("\n")) {
		t.Fatalf("got %q", got)
	}
}

func TestWireMatchesEvent(t *testing.T) {
	ev, w := reflect.TypeOf(Event{}), reflect.TypeOf(wireEvent{})
	if ev.NumField() != w.NumField() {
		t.Fatalf("Event has %d fields, wireEvent %d", ev.NumField(), w.NumField())
	}
	for i := 0; i < ev.NumField(); i++ {
		a, b := ev.Field(i), w.Field(i)
		if a.Name != b.Name || a.Tag != b.Tag {
			t.Errorf("field %d: Event %s %q, wireEvent %s %q", i, a.Name, a.Tag, b.Name, b.Tag)
		}
	}
}

func TestNewFieldsRoundTrip(t *testing.T) {
	ts := time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC)
	nd := New(NDNew, ts)
	nd.MAC, nd.Addr, nd.VLAN, nd.Kind, nd.PrevMAC = "aa:bb:cc:dd:ee:ff", "2001:db8:10::5", 20, "dad", "11:22:33:44:55:66"
	ra := New(RAChange, ts)
	ra.Managed, ra.Other = Bool(true), Bool(false)
	ra.Prefixes = []string{"2001:db8:10::/64"}
	ra.RouterLft = U32(1800)
	for _, e := range []Event{nd, ra} {
		b, err := e.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var got Event
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Errorf("round trip: got %+v want %+v", got, e)
		}
	}
	b, _ := ra.JSON()
	if !strings.Contains(string(b), `"managed":true,"other":false`) {
		t.Errorf("missing managed/other in %s", b)
	}
	b, _ = nd.JSON()
	if !strings.Contains(string(b), `"vlan":20,"kind":"dad","prev_mac":"11:22:33:44:55:66"`) {
		t.Errorf("missing vlan/kind in %s", b)
	}
}
