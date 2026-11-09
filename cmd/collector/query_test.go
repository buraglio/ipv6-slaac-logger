//go:build !windows

package main

import (
	"bytes"
	"context"
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
	if !strings.Contains(out.String(), "Holder at") || !strings.Contains(out.String(), add.DUID) {
		t.Fatalf("text output:\n%s", out.String())
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

	if err := queryCmd([]string{"-db", path}, &out); err == nil {
		t.Fatal("expected error without a lookup key")
	}
	if err := queryCmd([]string{"-db", path, "-addr", "x", "-mac", "y"}, &out); err == nil {
		t.Fatal("expected error with two lookup keys")
	}
}
