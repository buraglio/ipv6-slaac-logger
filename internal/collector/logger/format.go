// Package logger formats events as syslog messages, delivers them to sinks,
// and forwards the store's event stream to each sink at-least-once.
package logger

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Facility is a syslog facility number.
type Facility int

var facilityNames = map[string]Facility{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// ParseFacility parses a facility name such as "local5".
func ParseFacility(s string) (Facility, error) {
	f, ok := facilityNames[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("logger: unknown syslog facility %q", s)
	}
	return f, nil
}

// AppName is the syslog APP-NAME / tag.
const AppName = "ra-logger"

const rfc5424Time = "2006-01-02T15:04:05.000Z07:00"

func pri(f Facility, e event.Event) int { return int(f)*8 + int(e.Severity()) }

// FormatLocal renders the BSD-style line glibc syslog(3) sends to /dev/log:
// "<PRI>Mmm dd hh:mm:ss ra-logger[PID]: @cee:{...}".
func FormatLocal(e event.Event, f Facility, pid int) ([]byte, error) {
	msg, err := e.CEE()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "<%d>%s %s[%d]: %s", pri(f, e), e.TS.Local().Format(time.Stamp), AppName, pid, msg), nil
}

// FormatRFC5424 renders "<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID - MSG".
func FormatRFC5424(e event.Event, f Facility, hostname string, pid int) ([]byte, error) {
	msg, err := e.CEE()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "<%d>1 %s %s %s %d %s - %s",
		pri(f, e), e.TS.UTC().Format(rfc5424Time), sanitizeHeader(hostname), AppName, pid, e.Type, msg), nil
}

// sanitizeHeader makes s a valid RFC 5424 header field (PRINTUSASCII, max 255).
func sanitizeHeader(s string) string {
	if s == "" {
		return "-"
	}
	b := []byte(s)
	if len(b) > 255 {
		b = b[:255]
	}
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			b[i] = '_'
		}
	}
	return string(b)
}

// OctetFrame applies RFC 6587 octet-counting framing.
func OctetFrame(msg []byte) []byte {
	out := strconv.AppendInt(nil, int64(len(msg)), 10)
	out = append(out, ' ')
	return append(out, msg...)
}
