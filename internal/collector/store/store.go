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

	"github.com/buraglio/ipv6-ra-logger/internal/event"

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
);`

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
