// Package store is the collector's SQLite source of truth: an append-only
// events table, current bindings, and per-output forwarder cursors.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/event"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts   INTEGER NOT NULL,
  type TEXT NOT NULL,
  addr TEXT NOT NULL DEFAULT '',
  duid TEXT NOT NULL DEFAULT '',
  mac  TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS events_addr ON events(addr, ts);
CREATE INDEX IF NOT EXISTS events_duid ON events(duid, ts);
CREATE INDEX IF NOT EXISTS events_mac  ON events(mac, ts);
CREATE TABLE IF NOT EXISTS bindings (
  addr       TEXT PRIMARY KEY,
  duid       TEXT NOT NULL,
  mac        TEXT NOT NULL DEFAULT '',
  mac_src    TEXT NOT NULL DEFAULT '',
  origin     TEXT NOT NULL DEFAULT '',
  host       TEXT NOT NULL DEFAULT '',
  via        TEXT NOT NULL DEFAULT '',
  link       TEXT NOT NULL DEFAULT '',
  preferred  INTEGER NOT NULL,
  valid      INTEGER NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bindings_expires ON bindings(expires_at);
CREATE INDEX IF NOT EXISTS bindings_duid    ON bindings(duid);
CREATE INDEX IF NOT EXISTS bindings_mac     ON bindings(mac);
CREATE TABLE IF NOT EXISTS forwarder_state (
  name    TEXT PRIMARY KEY,
  last_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sightings (
  mac TEXT NOT NULL, addr TEXT NOT NULL, link TEXT NOT NULL, vlan INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  proxy_suspect INTEGER NOT NULL DEFAULT 0, expired INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (mac, addr, link, vlan));
CREATE INDEX IF NOT EXISTS sightings_addr ON sightings(addr);
CREATE INDEX IF NOT EXISTS sightings_last ON sightings(last_seen);
CREATE TABLE IF NOT EXISTS routers (
  link TEXT NOT NULL, vlan INTEGER NOT NULL DEFAULT 0, mac TEXT NOT NULL, addr TEXT NOT NULL,
  managed INTEGER NOT NULL, other INTEGER NOT NULL, prefixes TEXT NOT NULL, lifetime INTEGER NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (link, vlan, mac, addr));
CREATE VIEW IF NOT EXISTS hosts AS
  SELECT b.addr, b.duid, b.host, CASE WHEN b.mac <> '' THEN b.mac ELSE COALESCE(s.mac, '') END AS mac,
         CASE WHEN b.mac <> '' THEN b.mac_src WHEN s.mac IS NOT NULL THEN 'nd' ELSE '' END AS mac_src,
         COALESCE(s.link, b.link) AS link, COALESCE(s.vlan, 0) AS vlan,
         MIN(b.first_seen, COALESCE(s.first_seen, b.first_seen)) AS first_seen,
         MAX(b.last_seen, COALESCE(s.last_seen, b.last_seen)) AS last_seen
  FROM bindings b LEFT JOIN sightings s
    ON s.addr = b.addr AND s.proxy_suspect = 0 AND s.expired = 0 AND (b.mac = '' OR s.mac = b.mac)
  UNION ALL
  SELECT s.addr, '', '', s.mac, 'nd', s.link, s.vlan, s.first_seen, s.last_seen
  FROM sightings s
  WHERE s.proxy_suspect = 0 AND s.expired = 0 AND NOT EXISTS (SELECT 1 FROM bindings b WHERE b.addr = s.addr);`

const bindingCols = `addr, duid, mac, mac_src, origin, host, via, link, preferred, valid, first_seen, last_seen, expires_at`

const upsertBinding = `INSERT INTO bindings(` + bindingCols + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(addr) DO UPDATE SET
  duid=excluded.duid, mac=excluded.mac, mac_src=excluded.mac_src, origin=excluded.origin,
  host=excluded.host, via=excluded.via, link=excluded.link, preferred=excluded.preferred,
  valid=excluded.valid, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
  expires_at=excluded.expires_at`

// lookupFields whitelists columns usable in *Where queries.
var lookupFields = map[string]string{"addr": "addr", "duid": "duid", "mac": "mac"}

// hostFields whitelists columns of the hosts view usable in HostsWhere.
var hostFields = map[string]string{"addr": "addr", "duid": "duid", "mac": "mac"}

// sightingFields whitelists columns usable in SightingsWhere.
var sightingFields = map[string]string{"addr": "addr", "mac": "mac"}

const sightingCols = `mac, addr, link, vlan, kind, first_seen, last_seen, proxy_suspect, expired`

const upsertSighting = `INSERT INTO sightings(` + sightingCols + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(mac, addr, link, vlan) DO UPDATE SET
  kind=excluded.kind, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
  proxy_suspect=excluded.proxy_suspect, expired=excluded.expired`

const routerCols = `link, vlan, mac, addr, managed, other, prefixes, lifetime, first_seen, last_seen`

const upsertRouter = `INSERT INTO routers(` + routerCols + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(link, vlan, mac, addr) DO UPDATE SET
  managed=excluded.managed, other=excluded.other, prefixes=excluded.prefixes,
  lifetime=excluded.lifetime, first_seen=excluded.first_seen, last_seen=excluded.last_seen`

// Store wraps the SQLite database.
type Store struct{ db *sql.DB }

// Binding is the current registration for one address.
type Binding struct {
	Addr      netip.Addr `json:"addr"`
	DUID      string     `json:"duid"`
	MAC       string     `json:"mac,omitempty"`
	MACSrc    string     `json:"mac_src,omitempty"`
	Origin    string     `json:"origin"`
	Host      string     `json:"host,omitempty"`
	Via       string     `json:"via"`
	Link      string     `json:"link"`
	Preferred uint32     `json:"preferred_lft"`
	Valid     uint32     `json:"valid_lft"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// Sighting is one observed (MAC, address, link, VLAN) association from ND traffic.
type Sighting struct {
	MAC          string     `json:"mac"`
	Addr         netip.Addr `json:"addr"`
	Link         string     `json:"link"`
	VLAN         uint16     `json:"vlan,omitempty"`
	Kind         string     `json:"kind"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	ProxySuspect bool       `json:"proxy_suspect,omitempty"`
	Expired      bool       `json:"expired,omitempty"`
}

// Router is a router observed advertising on a link.
type Router struct {
	Link      string     `json:"link"`
	VLAN      uint16     `json:"vlan,omitempty"`
	MAC       string     `json:"mac"`
	Addr      netip.Addr `json:"addr"` // link-local
	Managed   bool       `json:"managed"`
	Other     bool       `json:"other"`
	Prefixes  []string   `json:"prefixes"` // sorted
	Lifetime  uint16     `json:"router_lft"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// Host is one row of the hosts view: a binding and/or sighting per address.
type Host struct {
	Addr      netip.Addr `json:"addr"`
	DUID      string     `json:"duid,omitempty"`
	Host      string     `json:"host,omitempty"`
	MAC       string     `json:"mac,omitempty"`
	MACSrc    string     `json:"mac_src,omitempty"`
	Link      string     `json:"link,omitempty"`
	VLAN      uint16     `json:"vlan,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// StoredEvent is an event with its row ID.
type StoredEvent struct {
	ID    int64
	Event event.Event
}

// Change is applied atomically by Commit.
type Change struct {
	Events []event.Event
	Put    []Binding
	Delete []netip.Addr

	PutSightings []Sighting
	PutRouters   []Router
}

// Open opens (creating if needed) a read-write database.
func Open(path string) (*Store, error) {
	return open(path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", true)
}

// OpenReadOnly opens an existing database for queries only.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return open(path+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)", false)
}

func open(dsn string, initSchema bool) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // single writer; see plan notes on batching
	if initSchema {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: init schema: %w", err)
		}
	} else if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Commit applies c in one transaction.
func (s *Store) Commit(ctx context.Context, c Change) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, e := range c.Events {
		body, err := e.JSON()
		if err != nil {
			return fmt.Errorf("store: encode event: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events(ts, type, addr, duid, mac, body) VALUES (?, ?, ?, ?, ?, ?)`,
			e.TS.UnixMilli(), e.Type, e.Addr, e.DUID, e.MAC, string(body)); err != nil {
			return fmt.Errorf("store: insert event: %w", err)
		}
	}
	for _, b := range c.Put {
		if _, err := tx.ExecContext(ctx, upsertBinding,
			b.Addr.String(), b.DUID, b.MAC, b.MACSrc, b.Origin, b.Host, b.Via, b.Link,
			int64(b.Preferred), int64(b.Valid),
			b.FirstSeen.UnixMilli(), b.LastSeen.UnixMilli(), b.ExpiresAt.UnixMilli()); err != nil {
			return fmt.Errorf("store: upsert binding: %w", err)
		}
	}
	for _, a := range c.Delete {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bindings WHERE addr = ?`, a.String()); err != nil {
			return fmt.Errorf("store: delete binding: %w", err)
		}
	}
	for _, sg := range c.PutSightings {
		if _, err := tx.ExecContext(ctx, upsertSighting,
			sg.MAC, sg.Addr.String(), sg.Link, int64(sg.VLAN), sg.Kind,
			sg.FirstSeen.UnixMilli(), sg.LastSeen.UnixMilli(), b2i(sg.ProxySuspect), b2i(sg.Expired)); err != nil {
			return fmt.Errorf("store: upsert sighting: %w", err)
		}
	}
	for _, r := range c.PutRouters {
		prefixes, err := json.Marshal(append([]string{}, r.Prefixes...))
		if err != nil {
			return fmt.Errorf("store: encode prefixes: %w", err)
		}
		if _, err := tx.ExecContext(ctx, upsertRouter,
			r.Link, int64(r.VLAN), r.MAC, r.Addr.String(), b2i(r.Managed), b2i(r.Other),
			string(prefixes), int64(r.Lifetime), r.FirstSeen.UnixMilli(), r.LastSeen.UnixMilli()); err != nil {
			return fmt.Errorf("store: upsert router: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanBinding(sc scanner) (Binding, error) {
	var b Binding
	var addr string
	var pref, valid, first, last, exp int64
	if err := sc.Scan(&addr, &b.DUID, &b.MAC, &b.MACSrc, &b.Origin, &b.Host, &b.Via, &b.Link,
		&pref, &valid, &first, &last, &exp); err != nil {
		return Binding{}, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return Binding{}, fmt.Errorf("store: bad addr %q: %w", addr, err)
	}
	b.Addr = a
	b.Preferred, b.Valid = uint32(pref), uint32(valid)
	b.FirstSeen = time.UnixMilli(first).UTC()
	b.LastSeen = time.UnixMilli(last).UTC()
	b.ExpiresAt = time.UnixMilli(exp).UTC()
	return b, nil
}

// GetBinding returns the binding for addr, if any.
func (s *Store) GetBinding(ctx context.Context, addr netip.Addr) (Binding, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+bindingCols+` FROM bindings WHERE addr = ?`, addr.String())
	b, err := scanBinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	return b, true, nil
}

func (s *Store) queryBindings(ctx context.Context, q string, args ...any) ([]Binding, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExpiredBindings returns bindings whose expires_at is at or before now.
func (s *Store) ExpiredBindings(ctx context.Context, now time.Time) ([]Binding, error) {
	return s.queryBindings(ctx, `SELECT `+bindingCols+` FROM bindings WHERE expires_at <= ? ORDER BY expires_at`, now.UnixMilli())
}

// BindingsWhere returns bindings where field ("addr", "duid", "mac") equals value.
func (s *Store) BindingsWhere(ctx context.Context, field, value string) ([]Binding, error) {
	col, ok := lookupFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	return s.queryBindings(ctx, `SELECT `+bindingCols+` FROM bindings WHERE `+col+` = ? ORDER BY first_seen`, value)
}

func (s *Store) queryEvents(ctx context.Context, q string, args ...any) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		var se StoredEvent
		var body string
		if err := rows.Scan(&se.ID, &body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(body), &se.Event); err != nil {
			return nil, fmt.Errorf("store: decode event %d: %w", se.ID, err)
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// EventsAfter returns up to limit events with id > afterID, in id order.
func (s *Store) EventsAfter(ctx context.Context, afterID int64, limit int) ([]StoredEvent, error) {
	return s.queryEvents(ctx, `SELECT id, body FROM events WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
}

// EventsWhere returns events where field equals value within [from, to].
// A zero from or to leaves that side unbounded.
func (s *Store) EventsWhere(ctx context.Context, field, value string, from, to time.Time) ([]StoredEvent, error) {
	col, ok := lookupFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	lo, hi := int64(math.MinInt64), int64(math.MaxInt64)
	if !from.IsZero() {
		lo = from.UnixMilli()
	}
	if !to.IsZero() {
		hi = to.UnixMilli()
	}
	return s.queryEvents(ctx, `SELECT id, body FROM events WHERE `+col+` = ? AND ts >= ? AND ts <= ? ORDER BY ts, id`, value, lo, hi)
}

// Cursor returns the last forwarded event ID for name (0 if none).
func (s *Store) Cursor(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT last_id FROM forwarder_state WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// SetCursor records the last forwarded event ID for name.
func (s *Store) SetCursor(ctx context.Context, name string, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO forwarder_state(name, last_id) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id`,
		name, id)
	return err
}

// PurgeEventsBefore deletes events older than t and returns how many were removed.
func (s *Store) PurgeEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("store: bad addr %q: %w", s, err)
	}
	return a, nil
}

func (s *Store) querySightings(ctx context.Context, q string, args ...any) ([]Sighting, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sighting
	for rows.Next() {
		var sg Sighting
		var addr string
		var vlan, first, last, proxy, expired int64
		if err := rows.Scan(&sg.MAC, &addr, &sg.Link, &vlan, &sg.Kind, &first, &last, &proxy, &expired); err != nil {
			return nil, err
		}
		if sg.Addr, err = parseAddr(addr); err != nil {
			return nil, err
		}
		sg.VLAN = uint16(vlan)
		sg.FirstSeen, sg.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		sg.ProxySuspect, sg.Expired = proxy != 0, expired != 0
		out = append(out, sg)
	}
	return out, rows.Err()
}

// Sightings returns all sightings, omitting expired ones unless includeExpired.
func (s *Store) Sightings(ctx context.Context, includeExpired bool) ([]Sighting, error) {
	q := `SELECT ` + sightingCols + ` FROM sightings`
	if !includeExpired {
		q += ` WHERE expired = 0`
	}
	return s.querySightings(ctx, q+` ORDER BY first_seen, mac, addr`)
}

// SightingsWhere returns sightings where field ("addr", "mac") equals value.
func (s *Store) SightingsWhere(ctx context.Context, field, value string) ([]Sighting, error) {
	col, ok := sightingFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	return s.querySightings(ctx, `SELECT `+sightingCols+` FROM sightings WHERE `+col+` = ? ORDER BY first_seen, mac, addr`, value)
}

// Routers returns the observed routers last seen at or after since (the zero
// time returns all of them).
func (s *Store) Routers(ctx context.Context, since time.Time) ([]Router, error) {
	q := `SELECT ` + routerCols + ` FROM routers`
	var args []any
	if !since.IsZero() {
		q += ` WHERE last_seen >= ?`
		args = append(args, since.UnixMilli())
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY link, vlan, mac, addr`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Router
	for rows.Next() {
		var r Router
		var addr, prefixes string
		var vlan, managed, other, lifetime, first, last int64
		if err := rows.Scan(&r.Link, &vlan, &r.MAC, &addr, &managed, &other, &prefixes, &lifetime, &first, &last); err != nil {
			return nil, err
		}
		if r.Addr, err = parseAddr(addr); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(prefixes), &r.Prefixes); err != nil {
			return nil, fmt.Errorf("store: decode prefixes %q: %w", prefixes, err)
		}
		r.VLAN, r.Managed, r.Other, r.Lifetime = uint16(vlan), managed != 0, other != 0, uint16(lifetime)
		r.FirstSeen, r.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// HostsWhere returns hosts-view rows where field ("addr", "mac", "duid") equals value.
func (s *Store) HostsWhere(ctx context.Context, field, value string) ([]Host, error) {
	col, ok := hostFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT addr, duid, host, mac, mac_src, link, vlan, first_seen, last_seen FROM hosts WHERE `+col+` = ? ORDER BY first_seen, addr`, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var addr string
		var vlan, first, last int64
		if err := rows.Scan(&addr, &h.DUID, &h.Host, &h.MAC, &h.MACSrc, &h.Link, &vlan, &first, &last); err != nil {
			return nil, err
		}
		if h.Addr, err = parseAddr(addr); err != nil {
			return nil, err
		}
		h.VLAN = uint16(vlan)
		h.FirstSeen, h.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// PurgeStaleBefore deletes sightings and routers last seen before t and
// returns how many rows of each were removed.
func (s *Store) PurgeStaleBefore(ctx context.Context, t time.Time) (sightings, routers int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	var n [2]int64
	for i, tbl := range []string{"sightings", "routers"} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+tbl+` WHERE last_seen < ?`, t.UnixMilli())
		if err != nil {
			return 0, 0, err
		}
		if n[i], err = res.RowsAffected(); err != nil {
			return 0, 0, err
		}
	}
	return n[0], n[1], tx.Commit()
}
