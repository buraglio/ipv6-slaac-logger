package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/buraglio/ipv6-ra-logger/internal/agent/addrsrc"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

type listRow struct {
	IfName    string `json:"ifname"`
	Addr      string `json:"addr"`
	Origin    string `json:"origin"`
	State     string `json:"state"`
	Preferred string `json:"preferred"`
	Valid     string `json:"valid"`
	Eligible  bool   `json:"eligible"`
}

func stateName(s addrsrc.State) string {
	switch s {
	case addrsrc.StateReady:
		return "ready"
	case addrsrc.StateNotReady:
		return "not-ready"
	case addrsrc.StateDuplicate:
		return "duplicate"
	}
	return fmt.Sprintf("state-%d", uint8(s))
}

func lifetime(v uint32) string {
	if v == dhcp6.Infinity {
		return "infinite"
	}
	return fmt.Sprintf("%ds", v)
}

// listCmd prints every local IPv6 address and whether the agent would register
// it. It never writes state.
func listCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addrs, err := addrsrc.New().List()
	if err != nil {
		return err
	}
	rows := make([]listRow, 0, len(addrs))
	for _, a := range addrs {
		rows = append(rows, listRow{
			IfName: a.IfName, Addr: a.Addr.String(), Origin: string(a.Origin),
			State: stateName(a.State), Preferred: lifetime(a.Preferred),
			Valid: lifetime(a.Valid), Eligible: addrsrc.Eligible(a),
		})
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IFNAME\tADDR\tORIGIN\tSTATE\tPREFERRED\tVALID\tELIGIBLE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%t\n", r.IfName, r.Addr, r.Origin, r.State, r.Preferred, r.Valid, r.Eligible)
	}
	return tw.Flush()
}
