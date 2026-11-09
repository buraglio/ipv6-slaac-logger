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
		for _, b := range []string{"collector", "regsend"} {
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

// collectorProc is a running collector and its captured output.
type collectorProc struct {
	cmd            *exec.Cmd
	stdout, stderr *lineLog
	done           chan struct{} // closed when the process has exited
}

// stop sends SIGTERM and waits up to 10s for exit, then kills the process.
func (c *collectorProc) stop(t *testing.T) {
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
		t.Logf("collector did not exit within 10s of SIGTERM; killing it")
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

func (l *lineLog) dump(t *testing.T, name string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Logf("collector %s (%d lines):\n%s", name, len(l.lines), strings.Join(l.lines, "\n"))
	if len(l.buf) > 0 {
		t.Logf("collector %s (partial line): %s", name, l.buf)
	}
}

func startCollector(t *testing.T, state string) *collectorProc {
	t.Helper()
	cfg := fmt.Sprintf(`state_dir = %q
listen_addr = "[::]:547"

[[interface]]
name = "veth-c"
roles = ["listen", "responder"]

[registrar]
allowed_prefixes = ["2001:db8:10::/64"]

[[log.output]]
type = "stdout"
`, state)
	cfgPath := filepath.Join(state, "collector.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collectorProc{stdout: &lineLog{}, stderr: &lineLog{}, done: make(chan struct{})}
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
			c.stdout.dump(t, "stdout")
			c.stderr.dump(t, "stderr")
		}
	})
	t.Cleanup(func() { c.stop(t) })
	c.stderr.waitFor(t, 5*time.Second, "collector started")
	return c
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
