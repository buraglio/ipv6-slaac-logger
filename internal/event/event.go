// Package event defines the record schema shared by every ipv6-ra-logger
// component (spec §3). One Event is one syslog line and one row in the store.
package event

import (
	"bytes"
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

// TimeFormat is the fixed-width JSON timestamp format: UTC with exactly three
// fractional digits, so records sort and align as text.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// msTime is a time.Time that marshals in TimeFormat. Unmarshal accepts any
// RFC 3339 time, including records written before the format was fixed.
type msTime time.Time

func (t msTime) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(TimeFormat)+2)
	b = append(b, '"')
	b = time.Time(t).UTC().AppendFormat(b, TimeFormat)
	return append(b, '"'), nil
}

func (t *msTime) UnmarshalJSON(b []byte) error {
	return (*time.Time)(t).UnmarshalJSON(b)
}

func msPtr(t *time.Time) *msTime {
	if t == nil {
		return nil
	}
	m := msTime(*t)
	return &m
}

func timePtr(m *msTime) *time.Time {
	if m == nil {
		return nil
	}
	t := time.Time(*m)
	return &t
}

// wireEvent is Event's JSON form. Its fields must stay in Event's order with
// Event's tags (TestWireMatchesEvent checks this).
type wireEvent struct {
	TS        msTime            `json:"ts"`
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
	FirstSeen *msTime           `json:"first_seen,omitempty"`
	LastSeen  *msTime           `json:"last_seen,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Src       string            `json:"src,omitempty"`
	Count     uint64            `json:"count,omitempty"`
	Counters  map[string]uint64 `json:"counters,omitempty"`
}

// MarshalJSON writes fixed-width timestamps and does not HTML-escape <, >, &.
// Control characters are still escaped, so the result is one line.
func (e Event) MarshalJSON() ([]byte, error) {
	w := wireEvent{
		TS: msTime(e.TS), Type: e.Type, Addr: e.Addr, DUID: e.DUID, DUIDType: e.DUIDType,
		MAC: e.MAC, MACSrc: e.MACSrc, Origin: e.Origin, Host: e.Host, Via: e.Via, Link: e.Link,
		Preferred: e.Preferred, Valid: e.Valid, XID: e.XID, PrevDUID: e.PrevDUID,
		FirstSeen: msPtr(e.FirstSeen), LastSeen: msPtr(e.LastSeen),
		Reason: e.Reason, Src: e.Src, Count: e.Count, Counters: e.Counters,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (e *Event) UnmarshalJSON(b []byte) error {
	var w wireEvent
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Event{
		TS: time.Time(w.TS), Type: w.Type, Addr: w.Addr, DUID: w.DUID, DUIDType: w.DUIDType,
		MAC: w.MAC, MACSrc: w.MACSrc, Origin: w.Origin, Host: w.Host, Via: w.Via, Link: w.Link,
		Preferred: w.Preferred, Valid: w.Valid, XID: w.XID, PrevDUID: w.PrevDUID,
		FirstSeen: timePtr(w.FirstSeen), LastSeen: timePtr(w.LastSeen),
		Reason: w.Reason, Src: w.Src, Count: w.Count, Counters: w.Counters,
	}
	return nil
}

// JSON encodes the event as one line (see MarshalJSON).
func (e Event) JSON() ([]byte, error) { return e.MarshalJSON() }

// CEE returns the JSON prefixed with the "@cee:" cookie for rsyslog mmjsonparse.
func (e Event) CEE() ([]byte, error) {
	j, err := e.JSON()
	if err != nil {
		return nil, err
	}
	return append([]byte("@cee:"), j...), nil
}
