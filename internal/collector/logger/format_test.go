package logger

import (
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/event"
)

var ts = time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC)

func TestParseFacility(t *testing.T) {
	if f, err := ParseFacility("LOCAL5"); err != nil || f != 21 {
		t.Fatalf("got %d %v", f, err)
	}
	if _, err := ParseFacility("local9"); err == nil {
		t.Fatal("accepted local9")
	}
}

func TestFormatRFC5424(t *testing.T) {
	e := event.New(event.RegReject, ts)
	e.Reason = "scope"
	got, err := FormatRFC5424(e, 21, "collector1", 42)
	if err != nil {
		t.Fatal(err)
	}
	want := `<172>1 2026-11-08T21:14:03.412Z collector1 slaac-logger 42 reg.reject - @cee:{"ts":"2026-11-08T21:14:03.412Z","event":"reg.reject","reason":"scope"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestFormatRFC5424SanitizesHostname(t *testing.T) {
	e := event.New(event.RegAdd, ts)
	got, _ := FormatRFC5424(e, 21, "bad host\n", 1)
	if !strings.Contains(string(got), " bad_host_ slaac-logger ") {
		t.Fatalf("got %s", got)
	}
	got, _ = FormatRFC5424(e, 21, "", 1)
	if !strings.Contains(string(got), "Z - slaac-logger ") {
		t.Fatalf("empty hostname not replaced by nil value: %s", got)
	}
}

func TestFormatLocal(t *testing.T) {
	e := event.New(event.RegAdd, ts)
	got, err := FormatLocal(e, 21, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "<174>" + e.TS.Local().Format(time.Stamp) + ` slaac-logger[42]: @cee:{"ts":"2026-11-08T21:14:03.412Z","event":"reg.add"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestOctetFrame(t *testing.T) {
	if got := string(OctetFrame([]byte("hello"))); got != "5 hello" {
		t.Fatalf("got %q", got)
	}
}
