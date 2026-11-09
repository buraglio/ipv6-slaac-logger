package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSystemdTemplateHardening(t *testing.T) {
	for _, want := range []string{"DynamicUser=yes", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "NoNewPrivileges=yes", "ProtectSystem=strict"} {
		if !strings.Contains(systemdTemplate, want) {
			t.Errorf("template lacks %q", want)
		}
	}
	if strings.Contains(systemdTemplate, "CAP_NET_RAW") {
		t.Error("template must not grant CAP_NET_RAW")
	}
}

func TestListRuns(t *testing.T) {
	var buf bytes.Buffer
	if err := listCmd([]string{"-json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil {
		t.Fatalf("not a JSON array: %v\n%s", err, buf.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	code, out := runCLI([]string{"agent", "frobnicate"}, &bytes.Buffer{})
	if code != 2 || !strings.Contains(out, "usage: agent") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if got := realMain([]string{"agent", "frobnicate"}); got != 2 {
		t.Fatalf("realMain = %d", got)
	}
}
