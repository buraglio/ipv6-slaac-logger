package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load(write(t, "[[interface]]\nname = \"eth0\"\nroles = [\"listen\", \"responder\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != "/var/lib/slaac-logger" || c.ListenAddr != "[::]:547" || c.RetentionDays != 400 ||
		c.Vendor.EnterpriseNumber != 67611 || c.Log.Facility != "local5" ||
		len(c.Log.Outputs) != 1 || c.Log.Outputs[0].Type != "unix" || c.Log.Outputs[0].Address != "/dev/log" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if !c.Interfaces[0].Has(RoleResponder) || c.Interfaces[0].Has(RoleSniff) {
		t.Fatal("Has() wrong")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "bogus = 1\n",
		"bad role":             "[[interface]]\nname=\"eth0\"\nroles=[\"listen\",\"dance\"]\n",
		"responder w/o listen": "[[interface]]\nname=\"eth0\"\nroles=[\"responder\"]\n",
		"empty name":           "[[interface]]\nroles=[\"listen\"]\n",
		"duplicate interface":  "[[interface]]\nname=\"eth0\"\n[[interface]]\nname=\"eth0\"\n",
		"bad prefix":           "[[interface]]\nname=\"eth0\"\nprefixes=[\"nope\"]\n",
		"ipv4 prefix":          "[registrar]\nallowed_prefixes=[\"192.0.2.0/24\"]\n",
		"bad trusted relay":    "[registrar]\ntrusted_relays=[\"nope\"]\n",
		"bad facility":         "[log]\nfacility=\"local9\"\n",
		"bad output type":      "[[log.output]]\ntype=\"carrier-pigeon\"\naddress=\"x\"\n",
		"tcp without address":  "[[log.output]]\ntype=\"tcp\"\n",
		"negative retention":   "retention_days = -1\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadTrustedRelays(t *testing.T) {
	c, err := Load(write(t, "[registrar]\ntrusted_relays=[\"2001:db8:ffff::/64\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Registrar.TrustedRelays) != 1 {
		t.Fatalf("TrustedRelays = %v, want 1 entry", c.Registrar.TrustedRelays)
	}
}

func TestParsePrefixesMasks(t *testing.T) {
	p, err := ParsePrefixes([]string{"2001:db8:10::5/64"})
	if err != nil || p[0].String() != "2001:db8:10::/64" {
		t.Fatalf("got %v %v", p, err)
	}
}

func TestRetentionDaysZeroRejected(t *testing.T) {
	_, err := Load(write(t, "retention_days = 0\n"))
	if err == nil || err.Error() != "config: retention_days must be at least 1 (omit it for the 400-day default)" {
		t.Fatalf("err = %v", err)
	}
	c, err := Load(write(t, "state_dir = \"/tmp/x\"\n"))
	if err != nil || c.RetentionDays != 400 {
		t.Fatalf("omitted retention_days: %+v %v", c, err)
	}
	if _, err := Load(write(t, "retention_days = -3\n")); err == nil {
		t.Fatal("negative retention_days accepted")
	}
}

func TestSnifferDefaultsAndLimits(t *testing.T) {
	c, err := Load(write(t, "[[interface]]\nname=\"eth0\"\nroles=[\"sniff\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sniffer.Idle() != 24*time.Hour || c.Sniffer.LogLinkLocal || c.Sniffer.ProxyThreshold != 32 || c.Sniffer.MaxEntries != 100000 ||
		c.Sniffer.MaxRouters != 1000 {
		t.Fatalf("sniffer defaults = %+v", c.Sniffer)
	}
	c, err = Load(write(t, "[sniffer]\nidle_timeout=\"90m\"\nlog_link_local=true\nproxy_threshold=2\nmax_entries=100\nmax_routers=10\n"))
	if err != nil || c.Sniffer.Idle() != 90*time.Minute || !c.Sniffer.LogLinkLocal || c.Sniffer.MaxRouters != 10 {
		t.Fatalf("explicit sniffer = %+v %v", c.Sniffer, err)
	}
	for name, body := range map[string]string{
		"idle too short":   "[sniffer]\nidle_timeout=\"30s\"\n",
		"idle unparsable":  "[sniffer]\nidle_timeout=\"soon\"\n",
		"threshold 1":      "[sniffer]\nproxy_threshold=1\n",
		"threshold 0":      "[sniffer]\nproxy_threshold=0\n",
		"max_entries 99":   "[sniffer]\nmax_entries=99\n",
		"max_entries zero": "[sniffer]\nmax_entries=0\n",
		"max_routers 9":    "[sniffer]\nmax_routers=9\n",
		"max_routers zero": "[sniffer]\nmax_routers=0\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
