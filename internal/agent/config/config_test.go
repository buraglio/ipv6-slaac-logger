package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Multicast != "auto" || c.Heartbeat.Duration != time.Hour || c.EnterpriseNumber != 67611 || c.LogLevel != "info" || c.StateDir == "" {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if want := Default(); c.StateDir != want.StateDir || c.Multicast != want.Multicast || c.Heartbeat != want.Heartbeat {
		t.Fatalf("got %+v want %+v", c, want)
	}
}

func TestLoadUnknownKeyFails(t *testing.T) {
	_, err := Load(write(t, "colectors = []\n"))
	if err == nil || !strings.Contains(err.Error(), "colectors") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]string{
		"multicast":     `multicast = "never"`,
		"heartbeat":     `heartbeat = "30s"`,
		"ipv4":          `collectors = ["192.0.2.1"]`,
		"not-addr":      `collectors = ["not-an-addr"]`,
		"duid hex":      `duid = "zz"`,
		"duid short":    `duid = "00:01"`,
		"duid long":     fmt.Sprintf("duid = %q", strings.Repeat("ab", 131)),
		"glob":          `include_interfaces = ["["]`,
		"exclude glob":  `exclude_interfaces = ["["]`,
		"log level":     `log_level = "loud"`,
		"bad heartbeat": `heartbeat = "soon"`,
	}
	for name, body := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			if _, err := Load(write(t, body+"\n")); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("good collectors", func(t *testing.T) {
		c, err := Load(write(t, `collectors = ["2001:db8::53", "[2001:db8::54]:5470"]`+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(c.CollectorAddrs()); got != "[[2001:db8::53]:547 [2001:db8::54]:5470]" {
			t.Fatalf("got %s", got)
		}
	})
	t.Run("good duid", func(t *testing.T) {
		c, err := Load(write(t, `duid = "00:03:00:01:5c:1e:9a:3b:21:aa"`+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.DUIDBytes()) != 10 {
			t.Fatalf("duid = %x", c.DUIDBytes())
		}
	})
	t.Run("duid unset", func(t *testing.T) {
		if Default().DUIDBytes() != nil {
			t.Fatal("want nil")
		}
	})
}

func TestExampleConfigLoads(t *testing.T) {
	if _, err := Load("../../../packaging/agent.example.toml"); err != nil {
		t.Fatal(err)
	}
}
