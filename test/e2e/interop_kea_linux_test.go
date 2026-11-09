//go:build e2e && interop && linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAgentKeaInterop checks that Kea 3.0 accepts the agent's ADDR-REG-INFORM
// (including the Vendor Class and FQDN options) and records the SLAAC address
// in its lease file. Kea runs in ral-c on the link without the collector.
//
// Build both test files with: go test -c -tags e2e,interop ./test/e2e
func TestAgentKeaInterop(t *testing.T) {
	kea, err := exec.LookPath("kea-dhcp6")
	if err != nil {
		t.Skip("kea-dhcp6 not found on PATH; install ISC Kea 3.0 to run this interop test")
	}

	setupNetns(t)
	startRadvd(t, "ral-c", "veth-c", "2001:db8:10::/64")

	dir := t.TempDir()
	leases := filepath.Join(dir, "leases6.csv")
	keaCfg := fmt.Sprintf(`{
  "Dhcp6": {
    "interfaces-config": { "interfaces": ["veth-c"] },
    "lease-database": { "type": "memfile", "name": %q, "lfc-interval": 0 },
    "subnet6": [
      { "id": 1, "subnet": "2001:db8:10::/64", "interface": "veth-c" }
    ],
    "loggers": [
      { "name": "kea-dhcp6", "severity": "DEBUG", "debuglevel": 50,
        "output-options": [ { "output": "stderr" } ] }
    ]
  }
}
`, leases)
	keaCfgPath := filepath.Join(dir, "kea-dhcp6.conf")
	if err := os.WriteFile(keaCfgPath, []byte(keaCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	k := &proc{stdout: &lineLog{}, stderr: &lineLog{}, done: make(chan struct{})}
	k.cmd = exec.Command("ip", "netns", "exec", "ral-c", kea, "-c", keaCfgPath)
	// Kea restricts where it writes lease, PID and lock files unless told otherwise.
	k.cmd.Env = append(os.Environ(),
		"KEA_LEASE_DIR="+dir, "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
	k.cmd.Stdout, k.cmd.Stderr = k.stdout, k.stderr
	if err := k.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = k.cmd.Wait()
		close(k.done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			k.stdout.dump(t, "kea stdout")
			k.stderr.dump(t, "kea stderr")
		}
	})
	t.Cleanup(func() { k.stop(t) })

	slaac := waitSLAAC(t, "ral-h", "veth-h", 15*time.Second)
	t.Logf("slaac=%s", slaac)

	// Kea logs to stderr (and stdout, depending on version); wait on either.
	deadline := time.Now().Add(15 * time.Second)
	for !logHas(k, "DHCP6_STARTED") {
		select {
		case <-k.done:
			t.Fatal("kea-dhcp6 exited before starting")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("kea-dhcp6 did not log DHCP6_STARTED within 15s")
		}
		time.Sleep(100 * time.Millisecond)
	}

	state := t.TempDir()
	cfgPath := filepath.Join(state, "agent.toml")
	agentCfg := fmt.Sprintf("state_dir = %q\nmulticast = \"always\"\nenterprise_number = 32473\nheartbeat = \"1m\"\n", state)
	if err := os.WriteFile(cfgPath, []byte(agentCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	a := startAgent(t, cfgPath)

	want := strings.ToLower(slaac)
	deadline = time.Now().Add(20 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(leases); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.ToLower(ln), want+",") {
					found = true
					t.Logf("lease line: %s", ln)
					break
				}
			}
		}
		if found {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !found {
		b, _ := os.ReadFile(leases)
		t.Fatalf("no lease for %s within 20s in %s:\n%s", want, leases, b)
	}

	a.stderr.mu.Lock()
	defer a.stderr.mu.Unlock()
	for _, ln := range a.stderr.lines {
		if strings.Contains(ln, "send failed") {
			t.Errorf("agent logged a send failure: %s", ln)
		}
	}
}

func logHas(p *proc, sub string) bool {
	for _, l := range []*lineLog{p.stderr, p.stdout} {
		l.mu.Lock()
		for _, ln := range l.lines {
			if strings.Contains(ln, sub) {
				l.mu.Unlock()
				return true
			}
		}
		l.mu.Unlock()
	}
	return false
}
