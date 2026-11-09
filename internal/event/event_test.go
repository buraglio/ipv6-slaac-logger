package event

import (
	"bytes"
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
