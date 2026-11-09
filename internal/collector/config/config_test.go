package config

import (
	"os"
	"path/filepath"
	"testing"
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
	if c.StateDir != "/var/lib/ra-logger" || c.ListenAddr != "[::]:547" || c.RetentionDays != 400 ||
		c.Vendor.EnterpriseNumber != 32473 || c.Log.Facility != "local5" ||
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
