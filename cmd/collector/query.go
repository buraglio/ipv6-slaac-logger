//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/buraglio/ipv6-slaac-logger/internal/collector/query"
	"github.com/buraglio/ipv6-slaac-logger/internal/collector/store"
	"github.com/buraglio/ipv6-slaac-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-slaac-logger/internal/event"
)

type holderOut struct {
	At    time.Time `json:"at"`
	Held  bool      `json:"held"`
	DUID  string    `json:"duid,omitempty"`
	MAC   string    `json:"mac,omitempty"`
	Host  string    `json:"host,omitempty"`
	Since time.Time `json:"since,omitzero"`
	// NDMACs are the MACs the sniffer saw using the address at At.
	NDMACs []string `json:"nd_macs,omitempty"`
	// Source is "events" when the answer comes from event history, or
	// "current_binding" when the events are gone (past retention) and the
	// still-live binding shows the address has been held since FirstSeen.
	Source string `json:"source"`
}

type queryResult struct {
	Bindings  []store.Binding  `json:"bindings"`
	Sightings []store.Sighting `json:"sightings"`
	Hosts     []store.Host     `json:"hosts"`
	Events    []event.Event    `json:"events"`
	Holder    *holderOut       `json:"holder,omitempty"`
}

func queryCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	db := fs.String("db", "/var/lib/slaac-logger/slaac-logger.db", "collector database")
	addrS := fs.String("addr", "", "IPv6 address to look up")
	macS := fs.String("mac", "", "MAC address to look up")
	duidS := fs.String("duid", "", "DUID (hex) to look up")
	atS := fs.String("at", "", "RFC 3339 time: events up to then, and who held -addr then")
	fromS := fs.String("from", "", "RFC 3339 start of the event window")
	toS := fs.String("to", "", "RFC 3339 end of the event window")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	field, value, err := lookupKey(*addrS, *macS, *duidS)
	if err != nil {
		return err
	}
	from, err := parseTime(*fromS)
	if err != nil {
		return err
	}
	to, err := parseTime(*toS)
	if err != nil {
		return err
	}
	at, err := parseTime(*atS)
	if err != nil {
		return err
	}
	if !at.IsZero() {
		if !to.IsZero() {
			return errors.New("use -at or -to, not both")
		}
		to = at
	}
	st, err := store.OpenReadOnly(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	evs, err := st.EventsWhere(ctx, field, value, from, to)
	if err != nil {
		return err
	}
	bs, err := st.BindingsWhere(ctx, field, value)
	if err != nil {
		return err
	}
	res := queryResult{Bindings: bs, Sightings: []store.Sighting{}, Hosts: []store.Host{}, Events: make([]event.Event, len(evs))}
	if field != "duid" {
		sg, err := st.SightingsWhere(ctx, field, value)
		if err != nil && !noSuchTable(err) {
			return err
		}
		res.Sightings = append(res.Sightings, sg...)
	}
	hs, err := st.HostsWhere(ctx, field, value)
	if err != nil && !noSuchTable(err) {
		return err
	}
	res.Hosts = append(res.Hosts, hs...)
	for i, se := range evs {
		res.Events[i] = se.Event
	}
	if field == "addr" && !at.IsZero() {
		// The holder may have been set before -from, so replay the full history.
		all, err := st.EventsWhere(ctx, field, value, time.Time{}, time.Time{})
		if err != nil {
			return err
		}
		h, held := query.HolderAt(all, at)
		res.Holder = &holderOut{At: at, Held: held, DUID: h.DUID, MAC: h.MAC, Host: h.Host, Since: h.Since, Source: "events"}
		if !held {
			// The binding keeps FirstSeen across refreshes, so a live binding
			// first seen by -at has held the address continuously since then,
			// even when its reg.add has been purged by retention.
			for _, b := range bs {
				if !b.FirstSeen.After(at) && at.Before(b.ExpiresAt) {
					res.Holder = &holderOut{At: at, Held: true, DUID: b.DUID, MAC: b.MAC, Host: b.Host,
						Since: b.FirstSeen, Source: "current_binding"}
					break
				}
			}
		}
		res.Holder.NDMACs = query.SightedAt(all, res.Sightings, at)
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	return writeText(w, res)
}

// noSuchTable reports a database that predates the sniffer: the read-only
// open does not create its tables, so those lookups are empty, not errors.
func noSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

func lookupKey(addr, mac, duid string) (string, string, error) {
	n := 0
	for _, s := range []string{addr, mac, duid} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return "", "", errors.New("exactly one of -addr, -mac, -duid is required")
	}
	switch {
	case addr != "":
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return "", "", err
		}
		return "addr", a.String(), nil
	case mac != "":
		m, err := net.ParseMAC(mac)
		if err != nil {
			return "", "", err
		}
		return "mac", m.String(), nil
	default:
		d, err := dhcp6.ParseHex(duid)
		if err != nil {
			return "", "", err
		}
		return "duid", dhcp6.FormatHex(d), nil
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeText(w io.Writer, res queryResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CURRENT BINDINGS")
	if len(res.Bindings) == 0 {
		fmt.Fprintln(tw, "  (none)")
	} else {
		fmt.Fprintln(tw, "ADDR\tDUID\tMAC\tHOST\tVIA\tLINK\tFIRST SEEN\tLAST SEEN\tEXPIRES")
		for _, b := range res.Bindings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				b.Addr, b.DUID, dash(b.MAC), dash(b.Host), b.Via, b.Link, ts(b.FirstSeen), ts(b.LastSeen), ts(b.ExpiresAt))
		}
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "Sightings:")
	if len(res.Sightings) == 0 {
		fmt.Fprintln(tw, "  (none)")
	} else {
		fmt.Fprintln(tw, "MAC\tADDR\tLINK\tVLAN\tKIND\tFIRST SEEN\tLAST SEEN\tFLAGS")
		for _, sg := range res.Sightings {
			var flags []string
			if sg.ProxySuspect {
				flags = append(flags, "proxy_suspect")
			}
			if sg.Expired {
				flags = append(flags, "expired")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				sg.MAC, sg.Addr, sg.Link, sg.VLAN, sg.Kind, ts(sg.FirstSeen), ts(sg.LastSeen), dash(strings.Join(flags, ",")))
		}
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "EVENTS")
	if len(res.Events) == 0 {
		fmt.Fprintln(tw, "  (none)")
	} else {
		fmt.Fprintln(tw, "TIME\tEVENT\tADDR\tDUID\tMAC\tHOST\tVIA\tDETAIL")
		for _, e := range res.Events {
			detail := e.Reason
			if e.PrevDUID != "" {
				detail = "prev_duid=" + e.PrevDUID
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				ts(e.TS), e.Type, dash(e.Addr), dash(e.DUID), dash(e.MAC), dash(e.Host), dash(e.Via), dash(detail))
		}
	}
	if h := res.Holder; h != nil {
		fmt.Fprintln(tw)
		if h.Held {
			note := ""
			if h.Source == "current_binding" {
				note = " (from current binding; earlier events may be past retention)"
			}
			fmt.Fprintf(tw, "Holder at %s: duid=%s mac=%s host=%s since=%s%s\n", ts(h.At), h.DUID, dash(h.MAC), dash(h.Host), ts(h.Since), note)
		} else {
			fmt.Fprintf(tw, "No holder at %s\n", ts(h.At))
		}
		if len(h.NDMACs) > 0 {
			fmt.Fprintf(tw, "sighted MACs: %s\n", strings.Join(h.NDMACs, ", "))
		}
	}
	return tw.Flush()
}
