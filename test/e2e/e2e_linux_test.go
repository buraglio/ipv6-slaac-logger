//go:build e2e && linux

// Package e2e runs the collector and regsend in Linux network namespaces.
// Run as root:  sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e
// or with prebuilt binaries:  sudo RAL_BIN_DIR=$PWD/bin ./bin/e2e.test -test.v
package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var binDir string

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("e2e: skipping, requires root for network namespaces")
		os.Exit(0)
	}
	binDir = os.Getenv("RAL_BIN_DIR")
	cleanup := func() {}
	if binDir == "" {
		dir, err := os.MkdirTemp("", "ral-e2e-bin")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, b := range []string{"collector", "regsend", "agent"} {
			out, err := exec.Command("go", "build", "-o", filepath.Join(dir, b), "../../cmd/"+b).CombinedOutput()
			if err != nil {
				fmt.Printf("build %s: %v\n%s", b, err, out)
				os.Exit(1)
			}
		}
		binDir = dir
		cleanup = func() { os.RemoveAll(dir) }
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func setupNetns(t *testing.T) {
	t.Helper()
	for _, ns := range []string{"ral-c", "ral-h"} {
		_ = exec.Command("ip", "netns", "del", ns).Run() // leftovers from an aborted run
		sh(t, "ip", "netns", "add", ns)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", "ral-c").Run()
		_ = exec.Command("ip", "netns", "del", "ral-h").Run()
	})
	sh(t, "ip", "link", "add", "veth-c", "netns", "ral-c", "type", "veth", "peer", "name", "veth-h", "netns", "ral-h")
	cfg := map[string][]string{
		"ral-c": {"veth-c", "2001:db8:10::1/64"},
		"ral-h": {"veth-h", "2001:db8:10::100/64", "2001:db8:10::101/64"},
	}
	for ns, c := range cfg {
		sh(t, "ip", "-n", ns, "link", "set", "lo", "up")
		sh(t, "ip", "-n", ns, "link", "set", c[0], "up")
		for _, a := range c[1:] {
			sh(t, "ip", "-n", ns, "-6", "addr", "add", a, "dev", c[0], "nodad")
		}
	}
}

// lineLog is an io.Writer that collects complete lines.
type lineLog struct {
	mu    sync.Mutex
	buf   []byte
	lines []string
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		l.lines = append(l.lines, string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

func (l *lineLog) waitFor(t *testing.T, timeout time.Duration, subs ...string) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, ln := range l.lines {
			all := true
			for _, s := range subs {
				if !strings.Contains(ln, s) {
					all = false
					break
				}
			}
			if all {
				l.mu.Unlock()
				return ln
			}
		}
		l.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("no line containing %q within %v; got:\n%s", subs, timeout, strings.Join(l.lines, "\n"))
	return ""
}

// proc is a running binary (collector or agent) and its captured output.
type proc struct {
	cmd            *exec.Cmd
	stdout, stderr *lineLog
	done           chan struct{} // closed when the process has exited
}

// stop sends SIGTERM and waits up to 10s for exit, then kills the process.
func (c *proc) stop(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Logf("process did not exit within 10s of SIGTERM; killing it")
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

func (l *lineLog) dump(t *testing.T, name string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Logf("%s (%d lines):\n%s", name, len(l.lines), strings.Join(l.lines, "\n"))
	if len(l.buf) > 0 {
		t.Logf("%s (partial line): %s", name, l.buf)
	}
}

func startCollector(t *testing.T, state string, roles ...string) *proc {
	t.Helper()
	all := append([]string{"listen", "responder"}, roles...)
	quoted := make([]string, len(all))
	for i, r := range all {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	cfg := fmt.Sprintf(`state_dir = %q
listen_addr = "[::]:547"

[[interface]]
name = "veth-c"
roles = [%s]

[registrar]
allowed_prefixes = ["2001:db8:10::/64"]

[[log.output]]
type = "stdout"
`, state, strings.Join(quoted, ", "))
	cfgPath := filepath.Join(state, "collector.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &proc{stdout: &lineLog{}, stderr: &lineLog{}, done: make(chan struct{})}
	c.cmd = exec.Command("ip", "netns", "exec", "ral-c", filepath.Join(binDir, "collector"), "run", "-config", cfgPath)
	c.cmd.Stdout, c.cmd.Stderr = c.stdout, c.stderr
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = c.cmd.Wait()
		close(c.done)
	}()
	// Cleanups run last-in first-out: stop the collector, then dump its output.
	t.Cleanup(func() {
		if t.Failed() {
			c.stdout.dump(t, "collector stdout")
			c.stderr.dump(t, "collector stderr")
		}
	})
	t.Cleanup(func() { c.stop(t) })
	c.stderr.waitFor(t, 5*time.Second, "collector started")
	return c
}

// startRadvd runs radvd in namespace ns, advertising prefix on ifname with the
// O flag set. It is killed at cleanup.
func startRadvd(t *testing.T, ns, ifname, prefix string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "radvd.conf")
	pidPath := filepath.Join(dir, "radvd.pid")
	cfg := fmt.Sprintf(`interface %s {
	AdvSendAdvert on;
	MinRtrAdvInterval 3;
	MaxRtrAdvInterval 4;
	AdvOtherConfigFlag on;
	prefix %s {
		AdvOnLink on;
		AdvAutonomous on;
	};
};
`, ifname, prefix)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, "ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	r := &proc{stdout: &lineLog{}, stderr: &lineLog{}, done: make(chan struct{})}
	r.cmd = exec.Command("ip", "netns", "exec", ns, "radvd", "-n", "-m", "stderr", "-C", cfgPath, "-p", pidPath)
	r.cmd.Stdout, r.cmd.Stderr = r.stdout, r.stderr
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = r.cmd.Wait()
		close(r.done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			r.stderr.dump(t, "radvd stderr")
		}
	})
	t.Cleanup(func() { r.stop(t) })
}

// startAgent runs the agent in the ral-h namespace with the config file cfgPath.
func startAgent(t *testing.T, cfgPath string) *proc {
	t.Helper()
	a := &proc{stdout: &lineLog{}, stderr: &lineLog{}, done: make(chan struct{})}
	a.cmd = exec.Command("ip", "netns", "exec", "ral-h", filepath.Join(binDir, "agent"), "-config", cfgPath, "run")
	a.cmd.Stdout, a.cmd.Stderr = a.stdout, a.stderr
	if err := a.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = a.cmd.Wait()
		close(a.done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			a.stdout.dump(t, "agent stdout")
			a.stderr.dump(t, "agent stderr")
		}
	})
	t.Cleanup(func() { a.stop(t) })
	return a
}

// fieldAfter returns the whitespace-separated field following key in line.
func fieldAfter(line, key string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == key {
			return f[i+1]
		}
	}
	return ""
}

// waitSLAAC polls ns for a non-tentative, non-temporary dynamic global address
// on ifname and returns it without the prefix length.
func waitSLAAC(t *testing.T, ns, ifname string, timeout time.Duration) string {
	t.Helper()
	var out string
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, _ := exec.Command("ip", "-n", ns, "-6", "-o", "addr", "show", "dev", ifname, "scope", "global", "dynamic").CombinedOutput()
		out = string(b)
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "tentative") || strings.Contains(ln, "temporary") {
				continue
			}
			if a := fieldAfter(ln, "inet6"); a != "" {
				return strings.SplitN(a, "/", 2)[0]
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no SLAAC address on %s/%s within %v; last ip output:\n%s", ns, ifname, timeout, out)
	return ""
}

// linkMAC returns the link-layer address of ifname in ns.
func linkMAC(t *testing.T, ns, ifname string) string {
	t.Helper()
	out := sh(t, "ip", "-n", ns, "-o", "link", "show", ifname)
	mac := fieldAfter(out, "link/ether")
	if mac == "" {
		t.Fatalf("no MAC for %s in ip output: %s", ifname, out)
	}
	return strings.ToLower(mac)
}

func regsend(args ...string) (string, int) {
	cmd := exec.Command("ip", append([]string{"netns", "exec", "ral-h", filepath.Join(binDir, "regsend")}, args...)...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		return string(out) + err.Error(), -1
	}
	return string(out), 0
}

func regsendExpect(t *testing.T, want int, args ...string) string {
	t.Helper()
	var out string
	var code int
	for i := 0; i < 10; i++ {
		if out, code = regsend(args...); code == want {
			return out
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("regsend %v: exit %d, want %d\n%s", args, code, want, out)
	return ""
}

func TestCollectorEndToEnd(t *testing.T) {
	setupNetns(t)
	state := t.TempDir()
	c := startCollector(t, state)
	stdout := c.stdout

	t.Run("multicast registration", func(t *testing.T) {
		out := regsendExpect(t, 0, "-iface", "veth-h", "-addr", "2001:db8:10::100", "-agent", "-host", "h1.example.com")
		if !strings.Contains(out, "type=37") || !strings.Contains(out, "ia_echo=true") {
			t.Fatalf("regsend output: %s", out)
		}
		stdout.waitFor(t, 5*time.Second, `"event":"reg.add"`, `"addr":"2001:db8:10::100"`,
			`"origin":"agent"`, `"via":"multicast"`, `"host":"h1.example.com"`, `"mac_src":"vendor"`)
	})

	t.Run("unicast registration", func(t *testing.T) {
		regsendExpect(t, 0, "-addr", "2001:db8:10::101", "-to", "2001:db8:10::1")
		stdout.waitFor(t, 5*time.Second, `"event":"reg.add"`, `"addr":"2001:db8:10::101"`, `"via":"unicast"`)
	})

	t.Run("malformed registration is rejected", func(t *testing.T) {
		regsendExpect(t, 3, "-iface", "veth-h", "-addr", "2001:db8:10::100", "-mutate", "server-id", "-wait", "1s")
		stdout.waitFor(t, 5*time.Second, `"event":"reg.reject"`, `"reason":"server_id_present"`)
	})

	t.Run("responder answers information-request", func(t *testing.T) {
		out := regsendExpect(t, 0, "-mode", "info", "-iface", "veth-h")
		if !strings.Contains(out, "addr_reg_enable=true") {
			t.Fatalf("regsend output: %s", out)
		}
	})

	t.Run("query finds the binding", func(t *testing.T) {
		c.stop(t)
		out := sh(t, filepath.Join(binDir, "collector"), "query", "-db", filepath.Join(state, "ra-logger.db"), "-addr", "2001:db8:10::100")
		if !strings.Contains(out, "reg.add") || !strings.Contains(out, "2001:db8:10::100") {
			t.Fatalf("query output:\n%s", out)
		}
	})
}

func TestAgentEndToEnd(t *testing.T) {
	setupNetns(t)
	c := startCollector(t, t.TempDir())
	startRadvd(t, "ral-c", "veth-c", "2001:db8:10::/64")

	slaac := waitSLAAC(t, "ral-h", "veth-h", 15*time.Second)
	mac := linkMAC(t, "ral-h", "veth-h")
	t.Logf("slaac=%s mac=%s", slaac, mac)

	state := t.TempDir()
	cfgPath := filepath.Join(state, "agent.toml")
	cfg := fmt.Sprintf("state_dir = %q\ncollectors = [\"2001:db8:10::1\"]\nheartbeat = \"1m\"\n", state)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	a := startAgent(t, cfgPath)
	started := a.stderr.waitFor(t, 10*time.Second, "agent started", "duid=")
	if !strings.Contains(started, "duid_source=generated") {
		t.Fatalf("first start: want duid_source=generated, got: %s", started)
	}
	duid1 := fieldValue(started, "duid")

	for _, addr := range []string{slaac, "2001:db8:10::100"} {
		c.stdout.waitFor(t, 20*time.Second, `"event":"reg.add"`, `"addr":"`+addr+`"`,
			`"origin":"agent"`, `"mac":"`+mac+`"`)
	}

	c.stdout.mu.Lock()
	for _, ln := range c.stdout.lines {
		if strings.Contains(ln, `"event":"reg.add"`) && strings.Contains(ln, `"addr":"fe80:`) {
			t.Errorf("link-local address was registered: %s", ln)
		}
	}
	c.stdout.mu.Unlock()

	a.stop(t)
	time.Sleep(2 * time.Second)
	c.stdout.mu.Lock()
	for _, ln := range c.stdout.lines {
		if strings.Contains(ln, `"event":"reg.dereg"`) {
			t.Errorf("unexpected de-registration after agent stop: %s", ln)
		}
	}
	c.stdout.mu.Unlock()

	a2 := startAgent(t, cfgPath)
	started2 := a2.stderr.waitFor(t, 10*time.Second, "agent started", "duid=")
	if duid2 := fieldValue(started2, "duid"); duid1 == "" || duid2 != duid1 {
		t.Fatalf("DUID changed across restart: %q -> %q", duid1, duid2)
	}
}

// fieldValue returns the value of key=value in a logfmt-style line.
func fieldValue(line, key string) string {
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func (l *lineLog) count(subs ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, ln := range l.lines {
		ok := true
		for _, s := range subs {
			if !strings.Contains(ln, s) {
				ok = false
				break
			}
		}
		if ok {
			n++
		}
	}
	return n
}

func TestSnifferEndToEnd(t *testing.T) {
	setupNetns(t)
	state := t.TempDir()
	c := startCollector(t, state, "sniff")
	stdout := c.stdout
	mac := linkMAC(t, "ral-h", "veth-h")
	// The capture socket must be open before the DAD probe is sent.
	c.stderr.waitFor(t, 10*time.Second, "sniffer capturing", "link=veth-c")

	// DAD: a new address with DAD enabled sends an NS from ::.
	sh(t, "ip", "-n", "ral-h", "-6", "addr", "add", "2001:db8:10::200/64", "dev", "veth-h")
	stdout.waitFor(t, 10*time.Second, `"event":"nd.new"`, `"addr":"2001:db8:10::200"`,
		`"mac":"`+mac+`"`, `"kind":"dad"`, `"link":"veth-c"`)

	// VLAN: the kernel strips the tag on veth into PACKET_AUXDATA.
	sh(t, "ip", "-n", "ral-h", "link", "add", "link", "veth-h", "name", "veth-h.20", "type", "vlan", "id", "20")
	sh(t, "ip", "-n", "ral-h", "link", "set", "veth-h.20", "up")
	sh(t, "ip", "-n", "ral-h", "-6", "addr", "add", "2001:db8:20::5/64", "dev", "veth-h.20")
	stdout.waitFor(t, 10*time.Second, `"event":"nd.new"`, `"addr":"2001:db8:20::5"`, `"vlan":20`)

	// RA: radvd in the collector's namespace; its outgoing RA must be seen.
	startRadvd(t, "ral-c", "veth-c", "2001:db8:10::/64")
	stdout.waitFor(t, 15*time.Second, `"event":"ra.seen"`, `"other":true`, `"prefixes":["2001:db8:10::/64"]`)

	// Repeat silence: further NS/NA traffic must not re-emit nd.new.
	before := stdout.count(`"event":"nd.new"`, `"addr":"2001:db8:10::200"`)
	if before == 0 {
		t.Fatal("no nd.new for ::200 counted")
	}
	for i := 0; i < 5; i++ {
		_ = exec.Command("ip", "netns", "exec", "ral-c", "ping", "-6", "-c", "1", "-W", "1", "2001:db8:10::200").Run()
	}
	time.Sleep(2 * time.Second)
	if after := stdout.count(`"event":"nd.new"`, `"addr":"2001:db8:10::200"`); after != before {
		t.Fatalf("nd.new for ::200 repeated: %d -> %d", before, after)
	}

	// Query the persisted sighting.
	c.stop(t)
	out := sh(t, filepath.Join(binDir, "collector"), "query", "-db", filepath.Join(state, "ra-logger.db"),
		"-addr", "2001:db8:10::200", "-json")
	for _, want := range []string{`"sightings"`, mac, `"mac_src": "nd"`} {
		if !strings.Contains(out, want) && !strings.Contains(out, strings.ReplaceAll(want, `": "`, `":"`)) {
			t.Fatalf("query -json lacks %s:\n%s", want, out)
		}
	}
}
