//go:build !windows

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

func TestQueryCmd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	add := event.New(event.RegAdd, t0)
	add.Addr, add.DUID, add.MAC = "2001:db8:10::5", "00:03:00:01:5c:1e:9a:3b:21:aa", "5c:1e:9a:3b:21:aa"
	exp := add
	exp.Type, exp.TS = event.RegExpire, t0.Add(2*time.Hour)
	b := store.Binding{Addr: netip.MustParseAddr("2001:db8:10::5"), DUID: add.DUID, Via: "multicast", Link: "eth0",
		FirstSeen: t0, LastSeen: t0, ExpiresAt: t0.Add(2 * time.Hour)}
	if err := st.Commit(context.Background(), store.Change{Events: []event.Event{add, exp}, Put: []store.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	var out bytes.Buffer
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10:0::5", "-at", t0.Add(time.Hour).Format(time.RFC3339)}, &out); err != nil {
		t.Fatal(err)
	}
	holderLine := ""
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "Holder at") {
			holderLine = line
		}
	}
	if holderLine == "" || !strings.Contains(holderLine, add.DUID) {
		t.Fatalf("holder line %q missing DUID %s in text output:\n%s", holderLine, add.DUID, out.String())
	}

	out.Reset()
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", t0.Add(3 * time.Hour).Format(time.RFC3339), "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Holder struct {
			Held bool   `json:"held"`
			DUID string `json:"duid"`
		} `json:"holder"`
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Holder.Held || len(res.Events) != 2 {
		t.Fatalf("json output: %s (%v)", out.String(), err)
	}

	// -from starts after the reg.add, so the window holds no events; the holder must still be found.
	out.Reset()
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-from", t0.Add(30 * time.Minute).Format(time.RFC3339),
		"-at", t0.Add(time.Hour).Format(time.RFC3339), "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	res.Holder.Held, res.Holder.DUID = false, ""
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.Holder.Held || res.Holder.DUID != add.DUID || len(res.Events) != 0 {
		t.Fatalf("-from json output: %s (%v)", out.String(), err)
	}

	if err := queryCmd([]string{"-db", path}, &out); err == nil {
		t.Fatal("expected error without a lookup key")
	}
	if err := queryCmd([]string{"-db", path, "-addr", "x", "-mac", "y"}, &out); err == nil {
		t.Fatal("expected error with two lookup keys")
	}
}

func TestQueryHolderFromCurrentBindingAfterPurge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	// The reg.add is past retention: only the (long-refreshed) binding remains.
	b := store.Binding{Addr: netip.MustParseAddr("2001:db8:10::5"), DUID: "00:03:00:01:5c:1e:9a:3b:21:aa", MAC: "5c:1e:9a:3b:21:aa",
		Host: "h.example", Via: "multicast", Link: "eth0", FirstSeen: t0, LastSeen: t0.Add(500 * 24 * time.Hour),
		ExpiresAt: t0.Add(501 * 24 * time.Hour)}
	if err := st.Commit(context.Background(), store.Change{Put: []store.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	at := t0.Add(24 * time.Hour).Format(time.RFC3339)

	var out bytes.Buffer
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", at, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Holder struct {
			Held   bool      `json:"held"`
			DUID   string    `json:"duid"`
			MAC    string    `json:"mac"`
			Host   string    `json:"host"`
			Since  time.Time `json:"since"`
			Source string    `json:"source"`
		} `json:"holder"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	h := res.Holder
	if !h.Held || h.Source != "current_binding" || h.DUID != b.DUID || h.MAC != b.MAC || h.Host != b.Host || !h.Since.Equal(t0) {
		t.Fatalf("holder = %+v\n%s", h, out.String())
	}

	out.Reset()
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", at}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(from current binding; earlier events may be past retention)") {
		t.Fatalf("text output lacks the current-binding note:\n%s", out.String())
	}

	out.Reset()
	before := t0.Add(-time.Hour).Format(time.RFC3339)
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", before, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	res.Holder.Held = true
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Holder.Held {
		t.Fatalf("-at before first_seen: %s (%v)", out.String(), err)
	}
}

// sightingDB returns a database holding only a sighting and its nd.new event.
func sightingDB(t *testing.T) (path string, t0 time.Time) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "q.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	nd := event.New(event.NDNew, t0)
	nd.Addr, nd.MAC, nd.Link = "2001:db8:10::5", "aa:bb:cc:dd:ee:ff", "eth0"
	sg := store.Sighting{MAC: nd.MAC, Addr: netip.MustParseAddr(nd.Addr), Link: "eth0", Kind: "na",
		FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour)}
	if err := st.Commit(context.Background(), store.Change{Events: []event.Event{nd}, PutSightings: []store.Sighting{sg}}); err != nil {
		t.Fatal(err)
	}
	return path, t0
}

func TestQueryShowsSightings(t *testing.T) {
	path, t0 := sightingDB(t)
	var out bytes.Buffer
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Sightings []json.RawMessage `json:"sightings"`
		Hosts     []struct {
			MAC    string `json:"mac"`
			MACSrc string `json:"mac_src"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res.Sightings) != 1 || len(res.Hosts) != 1 ||
		res.Hosts[0].MACSrc != "nd" || res.Hosts[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("json output: %s (%v)", out.String(), err)
	}
	out.Reset()
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", t0.Add(time.Hour).Format(time.RFC3339)}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sighted MACs: aa:bb:cc:dd:ee:ff") || !strings.Contains(out.String(), "Sightings:") {
		t.Fatalf("text output:\n%s", out.String())
	}
}

func TestQueryHolderUsesSightingsWhenNoBinding(t *testing.T) {
	path, t0 := sightingDB(t)
	var out bytes.Buffer
	if err := queryCmd([]string{"-db", path, "-addr", "2001:db8:10::5", "-at", t0.Add(time.Hour).Format(time.RFC3339), "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Holder struct {
			Held   bool     `json:"held"`
			NDMACs []string `json:"nd_macs"`
		} `json:"holder"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Holder.Held ||
		len(res.Holder.NDMACs) != 1 || res.Holder.NDMACs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("json output: %s (%v)", out.String(), err)
	}
	if !strings.Contains(out.String(), `"held": false`) || !strings.Contains(out.String(), `"nd_macs"`) {
		t.Fatalf("json output: %s", out.String())
	}
}

// A database created before the sniffer has no sightings table or hosts view,
// and the read-only open does not add them: query must report no rows.
func TestQueryOnPreSnifferDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP VIEW hosts`, `DROP TABLE sightings`, `DROP TABLE routers`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	for _, args := range [][]string{
		{"-addr", "2001:db8:10::5"}, {"-mac", "aa:bb:cc:dd:ee:ff"}, {"-duid", "00:04:01"},
		{"-addr", "2001:db8:10::5", "-at", "2026-11-08T12:00:00Z"},
	} {
		var out bytes.Buffer
		if err := queryCmd(append([]string{"-db", path, "-json"}, args...), &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var res struct {
			Sightings []json.RawMessage `json:"sightings"`
			Hosts     []json.RawMessage `json:"hosts"`
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Sightings == nil || res.Hosts == nil || len(res.Sightings)+len(res.Hosts) != 0 {
			t.Fatalf("%v: output %s (%v)", args, out.String(), err)
		}
	}
}
