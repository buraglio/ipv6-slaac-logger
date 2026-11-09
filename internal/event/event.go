// Package event defines the record schema shared by every ipv6-ra-logger
// component (spec §3). One Event is one syslog line and one row in the store.
package event

import (
	"encoding/json"
	"time"
)

// Event types.
const (
	RegAdd      = "reg.add"
	RegChange   = "reg.change"
	RegDereg    = "reg.dereg"
	RegExpire   = "reg.expire"
	RegConflict = "reg.conflict"
	RegReject   = "reg.reject"
	NDNew       = "nd.new"
	NDExpire    = "nd.expire"
	NDConflict  = "nd.conflict"
	RASeen      = "ra.seen"
	RAChange    = "ra.change"
	Stats       = "stats"
	StoreError  = "store.error"
)

// Severity is a syslog severity (RFC 5424 §6.2.1).
type Severity int

const (
	SevWarning Severity = 4
	SevNotice  Severity = 5
	SevInfo    Severity = 6
	SevDebug   Severity = 7
)

// Event is one forensic record. Field order defines JSON order.
type Event struct {
	TS        time.Time         `json:"ts"`
	Type      string            `json:"event"`
	Addr      string            `json:"addr,omitempty"`
	DUID      string            `json:"duid,omitempty"`
	DUIDType  string            `json:"duid_type,omitempty"`
	MAC       string            `json:"mac,omitempty"`
	MACSrc    string            `json:"mac_src,omitempty"`
	Origin    string            `json:"origin,omitempty"`
	Host      string            `json:"host,omitempty"`
	Via       string            `json:"via,omitempty"`
	Link      string            `json:"link,omitempty"`
	Preferred *uint32           `json:"preferred_lft,omitempty"`
	Valid     *uint32           `json:"valid_lft,omitempty"`
	XID       string            `json:"xid,omitempty"`
	PrevDUID  string            `json:"prev_duid,omitempty"`
	FirstSeen *time.Time        `json:"first_seen,omitempty"`
	LastSeen  *time.Time        `json:"last_seen,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Src       string            `json:"src,omitempty"`
	Count     uint64            `json:"count,omitempty"`
	Counters  map[string]uint64 `json:"counters,omitempty"`
}

// New returns an event of the given type stamped with now (UTC, millisecond precision).
func New(typ string, now time.Time) Event {
	return Event{TS: now.UTC().Truncate(time.Millisecond), Type: typ}
}

// U32 returns a pointer to v, for lifetime fields where 0 is meaningful.
func U32(v uint32) *uint32 { return &v }

// TimePtr returns a pointer to t in UTC with millisecond precision.
func TimePtr(t time.Time) *time.Time {
	u := t.UTC().Truncate(time.Millisecond)
	return &u
}

// Severity maps the event type to a syslog severity (spec §5.7).
func (e Event) Severity() Severity {
	switch e.Type {
	case RegConflict, NDConflict, RAChange, RegExpire, NDExpire:
		return SevNotice
	case RegReject, StoreError:
		return SevWarning
	}
	return SevInfo
}

// JSON encodes the event. encoding/json escapes control characters, so the
// result is always a single line.
func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

// CEE returns the JSON prefixed with the "@cee:" cookie for rsyslog mmjsonparse.
func (e Event) CEE() ([]byte, error) {
	j, err := e.JSON()
	if err != nil {
		return nil, err
	}
	return append([]byte("@cee:"), j...), nil
}
