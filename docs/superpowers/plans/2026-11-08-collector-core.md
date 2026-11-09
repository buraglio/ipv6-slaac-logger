# Collector Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working RFC 9686 registration server (the `collector`) that records registrations to SQLite, forwards structured events to syslog/rsyslog, answers Information-Requests with option 148, and can be queried. A test sender (`regsend`) and a Linux end-to-end test prove it works.

**Architecture:** One Go module. Pure-Go packages:
- `internal/dhcp6`: wire codec
- `internal/event`: shared record schema
- `internal/collector/*`: store, logger/forwarder, recorder, registrar, responder, listener, config, netinfo, serverid, query

`cmd/collector` wires them together. `cmd/regsend` is a developer tool. SQLite is the source of truth. Forwarders read from it, with a saved cursor per output, to deliver at-least-once.

**Tech Stack:** Go 1.25, `modernc.org/sqlite`, `github.com/BurntSushi/toml`, `golang.org/x/net/ipv6`, `golang.org/x/time/rate`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-08-ipv6-ra-logger-design.md`

**Not in this plan (later plans):**
- Plan 2: the agent, plus Kea interop.
- Plan 3: the sniffer, RA monitor, `nd.*`/`ra.*` events, the `hosts` view joined with sightings, and store write batching.
- Plan 4: `release.yml`, GoReleaser, nfpm packages, SBOM and attestations.

## Global Constraints

- Module path: `github.com/buraglio/ipv6-ra-logger`. Confirm it with the user before Task 1. If it changes, replace it everywhere.
- `go.mod` declares `go 1.25`.
- Every package must build with `CGO_ENABLED=0`. Use only pure-Go dependencies.
- The collector targets Linux. Files that use x/net/ipv6 sockets, and everything in `cmd/collector`, carry `//go:build !windows`. All other packages must build and pass tests on Linux, macOS and Windows.
- The Vendor Class enterprise number defaults to **32473** (the RFC 5612 documentation PEN) and is configurable.
- Record format: JSON, prefixed with `@cee:` for syslog. Field names exactly as spec §3.2: `ts, event, addr, duid, duid_type, mac, mac_src, origin, host, via, link, preferred_lft, valid_lft, xid`, plus `prev_duid, first_seen, last_seen, reason, src, count, counters`.
- Defaults: `retention_days = 400`, `facility = "local5"`, `listen_addr = "[::]:547"`, `state_dir = "/var/lib/ra-logger"`.
- The registrar rejects any ADDR-REG-INFORM carrying a Server ID or Option Request (strict RFC 9686).
- No panic on any network input.
- GitHub Actions are pinned by SHA:
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
  - `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0`
- Tool versions: staticcheck `2026.2.2`, govulncheck `v1.9.0`.

## Spec interpretation notes (decided while planning)

- **`reg.change` lifetimes.** Refreshes always push the expiry later, so "a lifetime change of more than 1%" is read as: the new expiry is *earlier* than the stored one by more than 1% of the new valid lifetime (the lifetime was shortened, as in renumbering). Changes to MAC, link, host or origin also count. A change of `via` alone does **not** count, because topology C sends each registration both by multicast and by unicast.
- **MAC precedence:**
  1. the relay's CLLAO (`cllao`)
  2. the MAC the agent reports in Vendor Class (`vendor`)
  3. the MAC embedded in a DUID-LL or DUID-LLT (`duid`)
- **Infinite valid lifetime:** the binding expires after 12 h unless refreshed.
- **`info.reply`** goes to the debug-level process log, not into the events table.
- **Store batching** is deferred to Plan 3, where the sniffer creates write volume. Plan 1 serializes writes with `SetMaxOpenConns(1)`.
- **Delivery over plain TCP/TLS** is at-least-once only up to the kernel send buffer. Events written to a connection just before it dies can be lost. RELP is future work.

## Review Focus

1. **Hostile or malformed packets** (truncated options, option lengths larger than the packet, more than 8 nested relays, garbage bytes) must be dropped and counted, never cause a panic. Tests: the fuzz targets in Tasks 1–2, plus the relay-depth, garbage and `FuzzDispatch` tests in Task 10.
2. **A flood of invalid registrations** must produce bounded log volume: at most 20 individual `reg.reject` events in a burst, then a `suppressed` summary with a count. Test: `TestRejectFloodIsBounded` in Task 8.
3. **Hostile strings in client options** (CR/LF, control characters, fake syslog headers in the hostname) must never split or forge a log line. Tests: the FQDN rejection tests in Task 2 and `TestHostileStringsStaySingleLine` in Task 3.
4. **The same registration arriving by multicast and by unicast** must produce one `reg.add` and no `reg.change` churn. Test: `TestMulticastAndUnicastCopiesDoNotChurn` in Task 8.
5. **A syslog destination that is down, or a restarted collector,** must cause missed events to be replayed from the saved cursor, neither lost nor all re-sent. Tests: `TestForwarderAtLeastOnce` and `TestForwarderResumesAfterRestart` in Task 6.

---

## File Structure

```
go.mod, go.sum, .gitignore
.github/workflows/ci.yml
internal/dhcp6/        consts.go options.go message.go iaaddr.go vendor.go fqdn.go duid.go addrreg.go (+ _test.go)
internal/event/        event.go (+ test)
internal/collector/store/      store.go (+ test)
internal/collector/logger/     format.go sink.go forwarder.go (+ tests)
internal/collector/recorder/   recorder.go (+ test)
internal/collector/registrar/  request.go policy.go validate.go ratelimit.go registrar.go (+ tests)
internal/collector/responder/  responder.go (+ test)
internal/collector/listener/   dispatch.go socket.go(!windows) (+ tests)
internal/collector/config/     config.go (+ tests)
internal/collector/netinfo/    netinfo.go (+ test)
internal/collector/serverid/   serverid.go (+ test)
internal/collector/query/      query.go (+ test)
cmd/collector/         main.go run.go query.go (+ tests)   all !windows
cmd/regsend/           main.go build.go (+ test)
packaging/systemd/     ra-logger-collector.service ra-logger.sysusers
packaging/rsyslog/     30-ra-logger.conf
packaging/collector.example.toml
test/e2e/e2e_linux_test.go     (build tags: e2e && linux)
README.md
```

---

### Task 1: Module scaffold, CI, DHCPv6 option and message codec

**Files:**
- Create: `go.mod`, `.gitignore`, `.github/workflows/ci.yml`
- Create: `internal/dhcp6/consts.go`, `internal/dhcp6/options.go`, `internal/dhcp6/message.go`
- Test: `internal/dhcp6/options_test.go`, `internal/dhcp6/message_test.go`

**Interfaces:**
- Produces:
  - Constants `MsgReply, MsgInformationRequest, MsgRelayForw, MsgRelayRepl, MsgAddrRegInform, MsgAddrRegReply` (`uint8`)
  - Constants `OptClientID, OptServerID, OptIAAddr, OptORO, OptRelayMsg, OptUserClass, OptVendorClass, OptInterfaceID, OptClientFQDN, OptClientLinkLayerAddr, OptAddrRegEnable` (`uint16`)
  - `ClientPort, ServerPort`
  - `var AllRelayAgentsAndServers netip.Addr`
  - `var ErrTruncated, ErrRelay error`
  - `type Option struct{Code uint16; Data []byte}`; `type Options []Option`
  - `ParseOptions([]byte) (Options, error)`; `(Options) AppendTo([]byte) ([]byte, error)`; `(Options) Get(uint16) (Option, bool)`; `(Options) Count(uint16) int`
  - `type Message struct{Type uint8; XID [3]byte; Options Options}`; `ParseMessage([]byte) (*Message, error)`; `(*Message) Marshal() ([]byte, error)`; `IsRelayType(uint8) bool`
  - `type RelayMessage struct{Type, HopCount uint8; LinkAddr, PeerAddr netip.Addr; Options Options}`; `ParseRelay([]byte) (*RelayMessage, error)`; `(*RelayMessage) Marshal() ([]byte, error)`

- [ ] **Step 1: Initialize the module and repository files**

```bash
cd /Users/buraglio/Documents/Dev/ipv6-ra-logger
go mod init github.com/buraglio/ipv6-ra-logger
go mod edit -go=1.25
mkdir -p internal/dhcp6 .github/workflows
```

Create `.gitignore`:

```
/bin/
/dist/
*.test
*.db
*.db-wal
*.db-shm
```

Create `.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    name: test (${{ matrix.os }})
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - run: go vet ./...
      - run: go test -race ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - run: go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...
      - run: go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - name: Short fuzz run of every Fuzz target
        run: |
          set -euo pipefail
          for pkg in $(go list ./...); do
            for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
              go test -run='^$' -fuzz="^${target}\$" -fuzztime=20s "$pkg"
            done
          done
```

- [ ] **Step 2: Write the failing tests**

`internal/dhcp6/options_test.go`:

```go
package dhcp6

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseOptionsRoundTrip(t *testing.T) {
	in := []byte{
		0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, // Client ID, 2 bytes
		0x00, 0x94, 0x00, 0x00, // option 148, empty
	}
	opts, err := ParseOptions(in)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("got %d options, want 2", len(opts))
	}
	if opts[0].Code != OptClientID || !bytes.Equal(opts[0].Data, []byte{0xaa, 0xbb}) {
		t.Errorf("opts[0] = %+v", opts[0])
	}
	if opts[1].Code != OptAddrRegEnable || len(opts[1].Data) != 0 {
		t.Errorf("opts[1] = %+v", opts[1])
	}
	out, err := opts.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round trip = %x, want %x", out, in)
	}
}

func TestParseOptionsTruncated(t *testing.T) {
	cases := map[string][]byte{
		"short header": {0x00},
		"short data":   {0x00, 0x01, 0x00, 0x05, 0xaa},
	}
	for name, in := range cases {
		if _, err := ParseOptions(in); !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: err = %v, want ErrTruncated", name, err)
		}
	}
}

func TestParseOptionsCopiesData(t *testing.T) {
	in := []byte{0x00, 0x01, 0x00, 0x01, 0xaa}
	opts, err := ParseOptions(in)
	if err != nil {
		t.Fatal(err)
	}
	in[4] = 0xff
	if opts[0].Data[0] != 0xaa {
		t.Fatal("option data aliases the input buffer")
	}
}

func TestOptionsGetCount(t *testing.T) {
	opts := Options{{Code: OptIAAddr}, {Code: OptClientID, Data: []byte{1}}, {Code: OptIAAddr}}
	if n := opts.Count(OptIAAddr); n != 2 {
		t.Errorf("Count(IAAddr) = %d, want 2", n)
	}
	if o, ok := opts.Get(OptClientID); !ok || o.Data[0] != 1 {
		t.Errorf("Get(ClientID) = %+v, %v", o, ok)
	}
	if _, ok := opts.Get(OptServerID); ok {
		t.Error("Get(ServerID) found an option that is not present")
	}
}

func TestAppendToRejectsOversizeOption(t *testing.T) {
	opts := Options{{Code: OptClientID, Data: make([]byte, 0x10000)}}
	if _, err := opts.AppendTo(nil); err == nil {
		t.Fatal("expected an error for a 65536-byte option")
	}
}

func FuzzParseOptions(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb})
	f.Add([]byte{0x00, 0x94, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		opts, err := ParseOptions(b)
		if err != nil {
			return
		}
		out, err := opts.AppendTo(nil)
		if err != nil {
			t.Fatalf("AppendTo after successful parse: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("round trip mismatch: %x != %x", out, b)
		}
	})
}
```

`internal/dhcp6/message_test.go`:

```go
package dhcp6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	in := []byte{MsgAddrRegInform, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x01, 0xaa}
	m, err := ParseMessage(in)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Type != MsgAddrRegInform || m.XID != [3]byte{1, 2, 3} || len(m.Options) != 1 {
		t.Fatalf("unexpected message: %+v", m)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round trip = %x, want %x", out, in)
	}
}

func TestParseMessageErrors(t *testing.T) {
	if _, err := ParseMessage([]byte{MsgAddrRegInform, 1, 2}); !errors.Is(err, ErrTruncated) {
		t.Errorf("short: err = %v, want ErrTruncated", err)
	}
	relay := make([]byte, 34)
	relay[0] = MsgRelayForw
	if _, err := ParseMessage(relay); !errors.Is(err, ErrRelay) {
		t.Errorf("relay: err = %v, want ErrRelay", err)
	}
}

func TestRelayRoundTrip(t *testing.T) {
	inner := []byte{MsgAddrRegInform, 9, 9, 9}
	r := &RelayMessage{
		Type:     MsgRelayForw,
		HopCount: 1,
		LinkAddr: netip.MustParseAddr("2001:db8:10::1"),
		PeerAddr: netip.MustParseAddr("2001:db8:10::5"),
		Options:  Options{{Code: OptRelayMsg, Data: inner}},
	}
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 34+4+len(inner) {
		t.Fatalf("len = %d", len(b))
	}
	got, err := ParseRelay(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != r.Type || got.HopCount != 1 || got.LinkAddr != r.LinkAddr || got.PeerAddr != r.PeerAddr {
		t.Fatalf("got %+v", got)
	}
	if o, ok := got.Options.Get(OptRelayMsg); !ok || !bytes.Equal(o.Data, inner) {
		t.Fatalf("relay message option = %+v", o)
	}
}

func TestParseRelayErrors(t *testing.T) {
	if _, err := ParseRelay(make([]byte, 33)); !errors.Is(err, ErrTruncated) {
		t.Errorf("short: err = %v, want ErrTruncated", err)
	}
	notRelay := make([]byte, 34)
	notRelay[0] = MsgAddrRegInform
	if _, err := ParseRelay(notRelay); err == nil {
		t.Error("non-relay type: expected error")
	}
}

func TestRelayMarshalRejectsNonIPv6(t *testing.T) {
	r := &RelayMessage{Type: MsgRelayRepl, PeerAddr: netip.MustParseAddr("2001:db8::1")}
	if _, err := r.Marshal(); err == nil {
		t.Fatal("expected error for zero LinkAddr")
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{MsgAddrRegInform, 1, 2, 3, 0, 1, 0, 1, 0xaa})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMessage(b)
		if err != nil {
			return
		}
		out, err := m.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x, %v", out, err)
		}
	})
}

func FuzzParseRelay(f *testing.F) {
	seed := make([]byte, 38)
	seed[0] = MsgRelayForw
	seed[35] = byte(OptRelayMsg)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRelay(b)
		if err != nil {
			return
		}
		out, err := r.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x, %v", out, err)
		}
	})
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/dhcp6/`
Expected: FAIL to compile with `undefined: ParseOptions`, `undefined: OptClientID` and so on.

- [ ] **Step 4: Implement**

`internal/dhcp6/consts.go`:

```go
// Package dhcp6 encodes and decodes the subset of DHCPv6 (RFC 8415) and
// RFC 9686 (address registration) used by ipv6-ra-logger.
package dhcp6

import "net/netip"

// Message types.
const (
	MsgReply              uint8 = 7
	MsgInformationRequest uint8 = 11
	MsgRelayForw          uint8 = 12
	MsgRelayRepl          uint8 = 13
	MsgAddrRegInform      uint8 = 36 // RFC 9686
	MsgAddrRegReply       uint8 = 37 // RFC 9686
)

// Option codes.
const (
	OptClientID            uint16 = 1
	OptServerID            uint16 = 2
	OptIAAddr              uint16 = 5
	OptORO                 uint16 = 6
	OptRelayMsg            uint16 = 9
	OptUserClass           uint16 = 15
	OptVendorClass         uint16 = 16
	OptInterfaceID         uint16 = 18
	OptClientFQDN          uint16 = 39  // RFC 4704
	OptClientLinkLayerAddr uint16 = 79  // RFC 6939
	OptAddrRegEnable       uint16 = 148 // RFC 9686
)

// UDP ports (RFC 8415 §7.2).
const (
	ClientPort = 546
	ServerPort = 547
)

// AllRelayAgentsAndServers is ff02::1:2.
var AllRelayAgentsAndServers = netip.MustParseAddr("ff02::1:2")
```

`internal/dhcp6/options.go`:

```go
package dhcp6

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrTruncated is returned when input ends before a declared length.
var ErrTruncated = errors.New("dhcp6: truncated")

// Option is one DHCPv6 option. Data excludes the 4-byte code/length header.
type Option struct {
	Code uint16
	Data []byte
}

// Options is an ordered option list. Duplicates are preserved.
type Options []Option

// ParseOptions decodes a sequence of options. Option data is copied, so the
// result never aliases b.
func ParseOptions(b []byte) (Options, error) {
	var opts Options
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, ErrTruncated
		}
		code := binary.BigEndian.Uint16(b[0:2])
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+n {
			return nil, ErrTruncated
		}
		data := make([]byte, n)
		copy(data, b[4:4+n])
		opts = append(opts, Option{Code: code, Data: data})
		b = b[4+n:]
	}
	return opts, nil
}

// AppendTo appends the wire encoding of o to dst.
func (o Options) AppendTo(dst []byte) ([]byte, error) {
	for _, opt := range o {
		if len(opt.Data) > 0xffff {
			return nil, fmt.Errorf("dhcp6: option %d too long (%d bytes)", opt.Code, len(opt.Data))
		}
		dst = binary.BigEndian.AppendUint16(dst, opt.Code)
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(opt.Data)))
		dst = append(dst, opt.Data...)
	}
	return dst, nil
}

// Get returns the first option with the given code.
func (o Options) Get(code uint16) (Option, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt, true
		}
	}
	return Option{}, false
}

// Count returns how many options have the given code.
func (o Options) Count(code uint16) int {
	n := 0
	for _, opt := range o {
		if opt.Code == code {
			n++
		}
	}
	return n
}
```

`internal/dhcp6/message.go`:

```go
package dhcp6

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrRelay is returned by ParseMessage when given a relay message.
var ErrRelay = errors.New("dhcp6: relay message")

// Message is a client/server DHCPv6 message.
type Message struct {
	Type    uint8
	XID     [3]byte
	Options Options
}

// IsRelayType reports whether t is Relay-Forward or Relay-Reply.
func IsRelayType(t uint8) bool { return t == MsgRelayForw || t == MsgRelayRepl }

// ParseMessage decodes a client/server message.
func ParseMessage(b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, ErrTruncated
	}
	if IsRelayType(b[0]) {
		return nil, ErrRelay
	}
	opts, err := ParseOptions(b[4:])
	if err != nil {
		return nil, err
	}
	m := &Message{Type: b[0], Options: opts}
	copy(m.XID[:], b[1:4])
	return m, nil
}

// Marshal encodes m.
func (m *Message) Marshal() ([]byte, error) {
	return m.Options.AppendTo([]byte{m.Type, m.XID[0], m.XID[1], m.XID[2]})
}

// RelayMessage is a Relay-Forward or Relay-Reply message.
type RelayMessage struct {
	Type     uint8
	HopCount uint8
	LinkAddr netip.Addr
	PeerAddr netip.Addr
	Options  Options
}

// ParseRelay decodes a relay message.
func ParseRelay(b []byte) (*RelayMessage, error) {
	if len(b) < 34 {
		return nil, ErrTruncated
	}
	if !IsRelayType(b[0]) {
		return nil, fmt.Errorf("dhcp6: type %d is not a relay message", b[0])
	}
	opts, err := ParseOptions(b[34:])
	if err != nil {
		return nil, err
	}
	return &RelayMessage{
		Type:     b[0],
		HopCount: b[1],
		LinkAddr: netip.AddrFrom16([16]byte(b[2:18])),
		PeerAddr: netip.AddrFrom16([16]byte(b[18:34])),
		Options:  opts,
	}, nil
}

// Marshal encodes r.
func (r *RelayMessage) Marshal() ([]byte, error) {
	if !r.LinkAddr.Is6() || !r.PeerAddr.Is6() {
		return nil, fmt.Errorf("dhcp6: relay addresses must be IPv6 (link %v, peer %v)", r.LinkAddr, r.PeerAddr)
	}
	b := make([]byte, 0, 34)
	b = append(b, r.Type, r.HopCount)
	la, pa := r.LinkAddr.As16(), r.PeerAddr.As16()
	b = append(b, la[:]...)
	b = append(b, pa[:]...)
	return r.Options.AppendTo(b)
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go vet ./... && go test -race ./internal/dhcp6/ && go test -run='^$' -fuzz='^FuzzParseOptions$' -fuzztime=10s ./internal/dhcp6/`
Expected: PASS, and the fuzz run reports no failures.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore .github/workflows/ci.yml internal/dhcp6
git commit -m "feat(dhcp6): option and message codec, CI workflow"
```

---

### Task 2: Option payloads (IA Address, Vendor Class, FQDN, DUID, CLLAO) and the ADDR-REG-INFORM builder

**Files:**
- Create: `internal/dhcp6/iaaddr.go`, `vendor.go`, `fqdn.go`, `duid.go`, `addrreg.go`
- Test: `internal/dhcp6/payloads_test.go`

**Interfaces:**
- Consumes: `Options`, `Option`, `Message`, `ErrTruncated` (Task 1)
- Produces:
  - IA Address: `type IAAddress struct{Addr netip.Addr; Preferred, Valid uint32; Options Options}`; `const Infinity uint32 = 0xffffffff`; `ParseIAAddress([]byte) (IAAddress, error)`; `(IAAddress) Marshal() ([]byte, error)`
  - Vendor Class: `type VendorClass struct{Enterprise uint32; Data [][]byte}`; `ParseVendorClass([]byte) (VendorClass, error)`; `(VendorClass) Marshal() ([]byte, error)`
  - FQDN: `const FQDNFlagN uint8 = 0x04`; `var ErrBadFQDN error`; `ParseFQDN([]byte) (flags uint8, name string, err error)`; `EncodeFQDN(flags uint8, name string) ([]byte, error)`
  - DUID: `DUIDTypeLLT, DUIDTypeEN, DUIDTypeLL, DUIDTypeUUID, HWTypeEthernet` (`uint16`); `DUIDTypeName([]byte) string`; `MACFromDUID([]byte) (net.HardwareAddr, bool)`; `ParseCLLAO([]byte) (net.HardwareAddr, bool)`; `FormatHex([]byte) string` (colon hex); `ParseHex(string) ([]byte, error)`; `NewDUIDLL(net.HardwareAddr) []byte`; `NewDUIDUUID([16]byte) []byte`
  - Builder: `NewAddrRegInform(xid [3]byte, duid []byte, ia IAAddress, extra ...Option) (*Message, error)` (option order: Client ID, IA Address, then extra); `RandomXID() ([3]byte, error)`

- [ ] **Step 1: Write the failing tests**

`internal/dhcp6/payloads_test.go`:

```go
package dhcp6

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

var testMAC = net.HardwareAddr{0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa}

func TestIAAddressRoundTrip(t *testing.T) {
	ia := IAAddress{Addr: netip.MustParseAddr("2001:db8:10::5"), Preferred: 3600, Valid: 7200}
	b, err := ia.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 24 {
		t.Fatalf("len = %d, want 24", len(b))
	}
	got, err := ParseIAAddress(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != ia.Addr || got.Preferred != 3600 || got.Valid != 7200 || len(got.Options) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseIAAddressTruncated(t *testing.T) {
	if _, err := ParseIAAddress(make([]byte, 23)); !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
}

func TestIAAddressMarshalRejectsIPv4(t *testing.T) {
	if _, err := (IAAddress{Addr: netip.MustParseAddr("192.0.2.1")}).Marshal(); err == nil {
		t.Fatal("expected error")
	}
}

func TestVendorClassRoundTrip(t *testing.T) {
	vc := VendorClass{Enterprise: 32473, Data: [][]byte{[]byte("ra-logger-agent/0.1"), []byte("os=linux")}}
	b, err := vc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseVendorClass(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enterprise != 32473 || len(got.Data) != 2 || string(got.Data[1]) != "os=linux" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseVendorClassTruncated(t *testing.T) {
	for _, in := range [][]byte{{0, 0, 0x7e}, {0, 0, 0x7e, 0xd9, 0, 5, 'a'}} {
		if _, err := ParseVendorClass(in); !errors.Is(err, ErrTruncated) {
			t.Errorf("%x: err = %v", in, err)
		}
	}
}

func TestFQDNRoundTrip(t *testing.T) {
	b, err := EncodeFQDN(FQDNFlagN, "host.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	flags, name, err := ParseFQDN(b)
	if err != nil {
		t.Fatal(err)
	}
	if flags != FQDNFlagN || name != "host.example.com" {
		t.Fatalf("got %x %q", flags, name)
	}
}

func TestFQDNRejectsHostileInput(t *testing.T) {
	cases := map[string][]byte{
		"newline in label": {0, 3, 'a', '\n', 'b', 0},
		"label too long":   append([]byte{0, 64}, bytes.Repeat([]byte{'a'}, 64)...),
		"trailing bytes":   {0, 1, 'a', 0, 1},
		"short label":      {0, 5, 'a'},
	}
	for name, in := range cases {
		if _, _, err := ParseFQDN(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := EncodeFQDN(0, "bad\nname"); err == nil {
		t.Error("EncodeFQDN accepted a control character")
	}
	if _, err := EncodeFQDN(0, strings.Repeat("a", 64)); err == nil {
		t.Error("EncodeFQDN accepted a 64-byte label")
	}
}

func TestMACFromDUID(t *testing.T) {
	ll := NewDUIDLL(testMAC)
	if mac, ok := MACFromDUID(ll); !ok || mac.String() != testMAC.String() {
		t.Errorf("LL: %v %v", mac, ok)
	}
	llt := append([]byte{0, 1, 0, 1, 0x2e, 0x5b, 0x11, 0x22}, testMAC...)
	if mac, ok := MACFromDUID(llt); !ok || mac.String() != testMAC.String() {
		t.Errorf("LLT: %v %v", mac, ok)
	}
	en := []byte{0, 2, 0, 0, 0x7e, 0xd9, 1, 2, 3}
	if _, ok := MACFromDUID(en); ok {
		t.Error("EN: should not yield a MAC")
	}
	nonEther := append([]byte{0, 3, 0, 6}, testMAC...)
	if _, ok := MACFromDUID(nonEther); ok {
		t.Error("non-Ethernet hwtype should not yield a MAC")
	}
	if DUIDTypeName(ll) != "LL" || DUIDTypeName(llt) != "LLT" || DUIDTypeName(en) != "EN" || DUIDTypeName([]byte{1}) != "unknown" {
		t.Error("DUIDTypeName mismatch")
	}
}

func TestParseCLLAO(t *testing.T) {
	if mac, ok := ParseCLLAO(append([]byte{0, 1}, testMAC...)); !ok || mac.String() != testMAC.String() {
		t.Errorf("got %v %v", mac, ok)
	}
	if _, ok := ParseCLLAO([]byte{0, 1, 2}); ok {
		t.Error("short CLLAO accepted")
	}
}

func TestHex(t *testing.T) {
	if s := FormatHex([]byte{0, 3, 0xab}); s != "00:03:ab" {
		t.Errorf("FormatHex = %q", s)
	}
	for _, in := range []string{"00:03:ab", "0003ab", " 00:03:AB "} {
		b, err := ParseHex(in)
		if err != nil || !bytes.Equal(b, []byte{0, 3, 0xab}) {
			t.Errorf("ParseHex(%q) = %x, %v", in, b, err)
		}
	}
	if _, err := ParseHex("zz"); err == nil {
		t.Error("ParseHex accepted non-hex")
	}
}

func TestNewAddrRegInformGolden(t *testing.T) {
	ia := IAAddress{Addr: netip.MustParseAddr("2001:db8:10::5"), Preferred: 3600, Valid: 7200}
	m, err := NewAddrRegInform([3]byte{1, 2, 3}, NewDUIDLL(testMAC), ia)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x24, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa,
		0x00, 0x05, 0x00, 0x18,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x1c, 0x20,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func FuzzParseIAAddress(f *testing.F) {
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		ia, err := ParseIAAddress(b)
		if err != nil {
			return
		}
		out, err := ia.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x %v", out, err)
		}
	})
}

func FuzzParseVendorClass(f *testing.F) {
	f.Add([]byte{0, 0, 0x7e, 0xd9, 0, 1, 'a'})
	f.Fuzz(func(t *testing.T, b []byte) {
		vc, err := ParseVendorClass(b)
		if err != nil {
			return
		}
		out, err := vc.Marshal()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("round trip: %x %v", out, err)
		}
	})
}

func FuzzParseFQDN(f *testing.F) {
	f.Add([]byte{0, 4, 'h', 'o', 's', 't', 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, name, err := ParseFQDN(b)
		if err != nil {
			return
		}
		for _, c := range []byte(name) {
			if c < 0x21 || c > 0x7e {
				t.Fatalf("non-printable byte %#x in accepted name %q", c, name)
			}
		}
	})
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/dhcp6/`
Expected: FAIL with `undefined: IAAddress`, `undefined: NewDUIDLL` and so on.

- [ ] **Step 3: Implement**

`internal/dhcp6/iaaddr.go`:

```go
package dhcp6

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Infinity is the "infinite" lifetime value (RFC 8415 §7.7).
const Infinity uint32 = 0xffffffff

// IAAddress is the payload of OPTION_IAADDR (5).
type IAAddress struct {
	Addr      netip.Addr
	Preferred uint32
	Valid     uint32
	Options   Options
}

// ParseIAAddress decodes an IA Address option payload.
func ParseIAAddress(data []byte) (IAAddress, error) {
	if len(data) < 24 {
		return IAAddress{}, ErrTruncated
	}
	opts, err := ParseOptions(data[24:])
	if err != nil {
		return IAAddress{}, err
	}
	return IAAddress{
		Addr:      netip.AddrFrom16([16]byte(data[0:16])),
		Preferred: binary.BigEndian.Uint32(data[16:20]),
		Valid:     binary.BigEndian.Uint32(data[20:24]),
		Options:   opts,
	}, nil
}

// Marshal encodes the IA Address payload.
func (a IAAddress) Marshal() ([]byte, error) {
	if !a.Addr.Is6() {
		return nil, fmt.Errorf("dhcp6: IA address %v is not IPv6", a.Addr)
	}
	x := a.Addr.As16()
	b := make([]byte, 0, 24)
	b = append(b, x[:]...)
	b = binary.BigEndian.AppendUint32(b, a.Preferred)
	b = binary.BigEndian.AppendUint32(b, a.Valid)
	return a.Options.AppendTo(b)
}
```

`internal/dhcp6/vendor.go`:

```go
package dhcp6

import (
	"encoding/binary"
	"fmt"
)

// VendorClass is the payload of OPTION_VENDOR_CLASS (16).
type VendorClass struct {
	Enterprise uint32
	Data       [][]byte
}

// ParseVendorClass decodes a Vendor Class option payload.
func ParseVendorClass(data []byte) (VendorClass, error) {
	if len(data) < 4 {
		return VendorClass{}, ErrTruncated
	}
	vc := VendorClass{Enterprise: binary.BigEndian.Uint32(data[0:4])}
	b := data[4:]
	for len(b) > 0 {
		if len(b) < 2 {
			return VendorClass{}, ErrTruncated
		}
		n := int(binary.BigEndian.Uint16(b[0:2]))
		if len(b) < 2+n {
			return VendorClass{}, ErrTruncated
		}
		d := make([]byte, n)
		copy(d, b[2:2+n])
		vc.Data = append(vc.Data, d)
		b = b[2+n:]
	}
	return vc, nil
}

// Marshal encodes the Vendor Class payload.
func (vc VendorClass) Marshal() ([]byte, error) {
	b := binary.BigEndian.AppendUint32(nil, vc.Enterprise)
	for _, d := range vc.Data {
		if len(d) > 0xffff {
			return nil, fmt.Errorf("dhcp6: vendor class data too long (%d bytes)", len(d))
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(d)))
		b = append(b, d...)
	}
	return b, nil
}
```

`internal/dhcp6/fqdn.go`:

```go
package dhcp6

import (
	"errors"
	"strings"
)

// FQDNFlagN asks the server not to perform DNS updates (RFC 4704).
const FQDNFlagN uint8 = 0x04

// ErrBadFQDN is returned for malformed or unsafe Client FQDN payloads.
var ErrBadFQDN = errors.New("dhcp6: malformed FQDN")

// ParseFQDN decodes an OPTION_CLIENT_FQDN (39) payload. Labels must be printable
// ASCII (0x21-0x7e) so names can never inject control characters into logs.
func ParseFQDN(data []byte) (uint8, string, error) {
	if len(data) < 1 {
		return 0, "", ErrTruncated
	}
	flags := data[0]
	b := data[1:]
	var labels []string
	total := 0
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 {
			if len(b) != 1 {
				return 0, "", ErrBadFQDN
			}
			break
		}
		if n > 63 || len(b) < 1+n {
			return 0, "", ErrBadFQDN
		}
		label := b[1 : 1+n]
		if !printable(label) {
			return 0, "", ErrBadFQDN
		}
		total += n + 1
		if total > 255 {
			return 0, "", ErrBadFQDN
		}
		labels = append(labels, string(label))
		b = b[1+n:]
	}
	return flags, strings.Join(labels, "."), nil
}

// EncodeFQDN encodes flags and a fully qualified name.
func EncodeFQDN(flags uint8, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	b := []byte{flags}
	if name == "" {
		return b, nil
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 || !printable([]byte(l)) {
			return nil, ErrBadFQDN
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	if len(b)-1 > 255 {
		return nil, ErrBadFQDN
	}
	return b, nil
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
```

`internal/dhcp6/duid.go`:

```go
package dhcp6

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// DUID types (RFC 8415 §11, RFC 6355).
const (
	DUIDTypeLLT  uint16 = 1
	DUIDTypeEN   uint16 = 2
	DUIDTypeLL   uint16 = 3
	DUIDTypeUUID uint16 = 4

	HWTypeEthernet uint16 = 1
)

// DUIDTypeName returns "LLT", "EN", "LL", "UUID" or "unknown".
func DUIDTypeName(d []byte) string {
	if len(d) < 2 {
		return "unknown"
	}
	switch binary.BigEndian.Uint16(d[0:2]) {
	case DUIDTypeLLT:
		return "LLT"
	case DUIDTypeEN:
		return "EN"
	case DUIDTypeLL:
		return "LL"
	case DUIDTypeUUID:
		return "UUID"
	}
	return "unknown"
}

// MACFromDUID extracts the Ethernet MAC from a DUID-LLT or DUID-LL.
func MACFromDUID(d []byte) (net.HardwareAddr, bool) {
	if len(d) < 4 || binary.BigEndian.Uint16(d[2:4]) != HWTypeEthernet {
		return nil, false
	}
	switch binary.BigEndian.Uint16(d[0:2]) {
	case DUIDTypeLLT:
		if len(d) == 14 {
			return net.HardwareAddr(bytes.Clone(d[8:14])), true
		}
	case DUIDTypeLL:
		if len(d) == 10 {
			return net.HardwareAddr(bytes.Clone(d[4:10])), true
		}
	}
	return nil, false
}

// ParseCLLAO extracts an Ethernet MAC from OPTION_CLIENT_LINKLAYER_ADDR (79).
func ParseCLLAO(data []byte) (net.HardwareAddr, bool) {
	if len(data) != 8 || binary.BigEndian.Uint16(data[0:2]) != HWTypeEthernet {
		return nil, false
	}
	return net.HardwareAddr(bytes.Clone(data[2:8])), true
}

// FormatHex renders bytes as colon-separated lowercase hex ("00:03:ab").
func FormatHex(b []byte) string { return net.HardwareAddr(b).String() }

// ParseHex accepts colon-separated or plain hex.
func ParseHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dhcp6: bad hex %q: %w", s, err)
	}
	return b, nil
}

// NewDUIDLL builds a DUID-LL for an Ethernet MAC.
func NewDUIDLL(mac net.HardwareAddr) []byte {
	return append([]byte{0, 3, 0, 1}, mac...)
}

// NewDUIDUUID builds a DUID-UUID (RFC 6355).
func NewDUIDUUID(u [16]byte) []byte {
	return append([]byte{0, 4}, u[:]...)
}
```

`internal/dhcp6/addrreg.go`:

```go
package dhcp6

import "crypto/rand"

// NewAddrRegInform builds an RFC 9686 ADDR-REG-INFORM carrying a Client ID and
// exactly one IA Address, followed by any extra options (Vendor Class, FQDN).
func NewAddrRegInform(xid [3]byte, duid []byte, ia IAAddress, extra ...Option) (*Message, error) {
	iaData, err := ia.Marshal()
	if err != nil {
		return nil, err
	}
	opts := Options{{Code: OptClientID, Data: duid}, {Code: OptIAAddr, Data: iaData}}
	opts = append(opts, extra...)
	return &Message{Type: MsgAddrRegInform, XID: xid, Options: opts}, nil
}

// RandomXID returns a random 24-bit transaction ID.
func RandomXID() ([3]byte, error) {
	var x [3]byte
	_, err := rand.Read(x[:])
	return x, err
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/dhcp6/ && go test -run='^$' -fuzz='^FuzzParseFQDN$' -fuzztime=10s ./internal/dhcp6/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dhcp6
git commit -m "feat(dhcp6): IA address, vendor class, FQDN, DUID helpers and ADDR-REG-INFORM builder"
```

---

### Task 3: Event schema

**Files:**
- Create: `internal/event/event.go`
- Test: `internal/event/event_test.go`

**Interfaces:**
- Produces:
  - Type constants `RegAdd, RegChange, RegDereg, RegExpire, RegConflict, RegReject, NDNew, NDExpire, NDConflict, RASeen, RAChange, Stats, StoreError` (strings)
  - `type Severity int` with `SevWarning=4, SevNotice=5, SevInfo=6, SevDebug=7`
  - `type Event struct{...}` (fields below)
  - `New(typ string, now time.Time) Event`; `U32(uint32) *uint32`; `TimePtr(time.Time) *time.Time`
  - `(Event) Severity() Severity`; `(Event) JSON() ([]byte, error)`; `(Event) CEE() ([]byte, error)`

- [ ] **Step 1: Write the failing tests**

`internal/event/event_test.go`:

```go
package event

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEventJSONShape(t *testing.T) {
	e := New(RegAdd, time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC))
	e.Addr = "2001:db8:10::5"
	e.DUID = "00:03:00:01:5c:1e:9a:3b:21:aa"
	e.DUIDType = "LL"
	e.MAC = "5c:1e:9a:3b:21:aa"
	e.MACSrc = "duid"
	e.Origin = "agent"
	e.Host = "lab-mbp"
	e.Via = "multicast"
	e.Link = "eth0"
	e.Preferred = U32(14400)
	e.Valid = U32(86400)
	e.XID = "a1b2c3"
	got, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ts":"2026-11-08T21:14:03.412Z","event":"reg.add","addr":"2001:db8:10::5","duid":"00:03:00:01:5c:1e:9a:3b:21:aa","duid_type":"LL","mac":"5c:1e:9a:3b:21:aa","mac_src":"duid","origin":"agent","host":"lab-mbp","via":"multicast","link":"eth0","preferred_lft":14400,"valid_lft":86400,"xid":"a1b2c3"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestZeroLifetimesAreEmitted(t *testing.T) {
	e := New(RegDereg, time.Now())
	e.Preferred, e.Valid = U32(0), U32(0)
	got, _ := e.JSON()
	if !bytes.Contains(got, []byte(`"preferred_lft":0`)) || !bytes.Contains(got, []byte(`"valid_lft":0`)) {
		t.Fatalf("zero lifetimes missing: %s", got)
	}
}

func TestCEEPrefix(t *testing.T) {
	got, err := New(Stats, time.Now()).CEE()
	if err != nil || !strings.HasPrefix(string(got), "@cee:{") {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestHostileStringsStaySingleLine(t *testing.T) {
	e := New(RegAdd, time.Now())
	e.Host = "evil\nhost\r<13>1 2026-01-01T00:00:00Z fake ra-logger - - forged"
	e.Reason = "x\x00y"
	got, err := e.CEE()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control bytes leaked into record: %q", got)
	}
}

func TestNewTruncatesToMillisUTC(t *testing.T) {
	loc := time.FixedZone("X", 3600)
	e := New(RegAdd, time.Date(2026, 1, 1, 0, 0, 0, 123_456_789, loc))
	if e.TS.Location() != time.UTC || e.TS.Nanosecond() != 123_000_000 {
		t.Fatalf("TS = %v", e.TS)
	}
}

func TestSeverity(t *testing.T) {
	cases := map[string]Severity{
		RegAdd: SevInfo, NDNew: SevInfo, RASeen: SevInfo, Stats: SevInfo,
		RegConflict: SevNotice, NDConflict: SevNotice, RAChange: SevNotice, RegExpire: SevNotice, NDExpire: SevNotice,
		RegReject: SevWarning, StoreError: SevWarning,
	}
	for typ, want := range cases {
		if got := New(typ, time.Now()).Severity(); got != want {
			t.Errorf("%s: severity %d, want %d", typ, got, want)
		}
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/event/`
Expected: FAIL with `undefined: New`.

- [ ] **Step 3: Implement**

`internal/event/event.go`:

```go
// Package event defines the record schema shared by every ipv6-ra-logger
// component (spec §3). One Event is one syslog line and one row in the store.
package event

import (
	"encoding/json"
	"time"
)

// Event types.
const (
	RegAdd      = "reg.add"
	RegChange   = "reg.change"
	RegDereg    = "reg.dereg"
	RegExpire   = "reg.expire"
	RegConflict = "reg.conflict"
	RegReject   = "reg.reject"
	NDNew       = "nd.new"
	NDExpire    = "nd.expire"
	NDConflict  = "nd.conflict"
	RASeen      = "ra.seen"
	RAChange    = "ra.change"
	Stats       = "stats"
	StoreError  = "store.error"
)

// Severity is a syslog severity (RFC 5424 §6.2.1).
type Severity int

const (
	SevWarning Severity = 4
	SevNotice  Severity = 5
	SevInfo    Severity = 6
	SevDebug   Severity = 7
)

// Event is one forensic record. Field order defines JSON order.
type Event struct {
	TS        time.Time         `json:"ts"`
	Type      string            `json:"event"`
	Addr      string            `json:"addr,omitempty"`
	DUID      string            `json:"duid,omitempty"`
	DUIDType  string            `json:"duid_type,omitempty"`
	MAC       string            `json:"mac,omitempty"`
	MACSrc    string            `json:"mac_src,omitempty"`
	Origin    string            `json:"origin,omitempty"`
	Host      string            `json:"host,omitempty"`
	Via       string            `json:"via,omitempty"`
	Link      string            `json:"link,omitempty"`
	Preferred *uint32           `json:"preferred_lft,omitempty"`
	Valid     *uint32           `json:"valid_lft,omitempty"`
	XID       string            `json:"xid,omitempty"`
	PrevDUID  string            `json:"prev_duid,omitempty"`
	FirstSeen *time.Time        `json:"first_seen,omitempty"`
	LastSeen  *time.Time        `json:"last_seen,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Src       string            `json:"src,omitempty"`
	Count     uint64            `json:"count,omitempty"`
	Counters  map[string]uint64 `json:"counters,omitempty"`
}

// New returns an event of the given type stamped with now (UTC, millisecond precision).
func New(typ string, now time.Time) Event {
	return Event{TS: now.UTC().Truncate(time.Millisecond), Type: typ}
}

// U32 returns a pointer to v, for lifetime fields where 0 is meaningful.
func U32(v uint32) *uint32 { return &v }

// TimePtr returns a pointer to t in UTC with millisecond precision.
func TimePtr(t time.Time) *time.Time {
	u := t.UTC().Truncate(time.Millisecond)
	return &u
}

// Severity maps the event type to a syslog severity (spec §5.7).
func (e Event) Severity() Severity {
	switch e.Type {
	case RegConflict, NDConflict, RAChange, RegExpire, NDExpire:
		return SevNotice
	case RegReject, StoreError:
		return SevWarning
	}
	return SevInfo
}

// JSON encodes the event. encoding/json escapes control characters, so the
// result is always a single line.
func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

// CEE returns the JSON prefixed with the "@cee:" cookie for rsyslog mmjsonparse.
func (e Event) CEE() ([]byte, error) {
	j, err := e.JSON()
	if err != nil {
		return nil, err
	}
	return append([]byte("@cee:"), j...), nil
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/event/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/event
git commit -m "feat(event): shared forensic record schema"
```

---

### Task 4: SQLite store

**Files:**
- Create: `internal/collector/store/store.go`
- Test: `internal/collector/store/store_test.go`

**Interfaces:**
- Consumes: `event.Event`, `(Event).JSON()` (Task 3)
- Produces:
  - `type Store`; `Open(path string) (*Store, error)`; `OpenReadOnly(path string) (*Store, error)`; `(*Store) Close() error`
  - `type Binding struct{Addr netip.Addr; DUID, MAC, MACSrc, Origin, Host, Via, Link string; Preferred, Valid uint32; FirstSeen, LastSeen, ExpiresAt time.Time}` (JSON tags: snake_case)
  - `type StoredEvent struct{ID int64; Event event.Event}`
  - `type Change struct{Events []event.Event; Put []Binding; Delete []netip.Addr}`
  - `(*Store) Commit(ctx, Change) error` (one transaction)
  - Bindings: `GetBinding(ctx, netip.Addr) (Binding, bool, error)`; `ExpiredBindings(ctx, time.Time) ([]Binding, error)`; `BindingsWhere(ctx, field, value string) ([]Binding, error)` (field ∈ addr/duid/mac)
  - Events: `EventsAfter(ctx, afterID int64, limit int) ([]StoredEvent, error)`; `EventsWhere(ctx, field, value string, from, to time.Time) ([]StoredEvent, error)` (zero time = unbounded; ordered by ts, id)
  - Cursors and retention: `Cursor(ctx, name string) (int64, error)`; `SetCursor(ctx, name string, id int64) error`; `PurgeEventsBefore(ctx, time.Time) (int64, error)`

- [ ] **Step 1: Add the dependency**

Run: `go get modernc.org/sqlite@latest`

- [ ] **Step 2: Write the failing tests**

`internal/collector/store/store_test.go`:

```go
package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var (
	ctx   = context.Background()
	t0    = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	addrA = netip.MustParseAddr("2001:db8:10::5")
	addrB = netip.MustParseAddr("2001:db8:10::6")
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func sampleBinding(a netip.Addr) Binding {
	return Binding{
		Addr: a, DUID: "00:03:00:01:5c:1e:9a:3b:21:aa", MAC: "5c:1e:9a:3b:21:aa", MACSrc: "duid",
		Origin: "native", Via: "multicast", Link: "eth0", Preferred: 3600, Valid: 7200,
		FirstSeen: t0, LastSeen: t0, ExpiresAt: t0.Add(2 * time.Hour),
	}
}

func ev(typ string, a netip.Addr, ts time.Time, reason string) event.Event {
	e := event.New(typ, ts)
	e.Addr = a.String()
	e.Reason = reason
	return e
}

func TestCommitAndGetBinding(t *testing.T) {
	s, _ := openTemp(t)
	b := sampleBinding(addrA)
	if err := s.Commit(ctx, Change{Events: []event.Event{ev(event.RegAdd, addrA, t0, "")}, Put: []Binding{b}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetBinding(ctx, addrA)
	if err != nil || !ok {
		t.Fatalf("GetBinding: %v %v", ok, err)
	}
	if got != b {
		t.Fatalf("got  %+v\nwant %+v", got, b)
	}
	if _, ok, _ := s.GetBinding(ctx, addrB); ok {
		t.Fatal("found a binding that was never stored")
	}
}

func TestUpsertAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	b := sampleBinding(addrA)
	_ = s.Commit(ctx, Change{Put: []Binding{b}})
	b.LastSeen = t0.Add(time.Hour)
	_ = s.Commit(ctx, Change{Put: []Binding{b}})
	got, _, _ := s.GetBinding(ctx, addrA)
	if !got.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("LastSeen = %v", got.LastSeen)
	}
	_ = s.Commit(ctx, Change{Delete: []netip.Addr{addrA}})
	if _, ok, _ := s.GetBinding(ctx, addrA); ok {
		t.Fatal("binding survived delete")
	}
}

func TestEventsAfterAndCursor(t *testing.T) {
	s, _ := openTemp(t)
	for _, r := range []string{"a", "b", "c"} {
		_ = s.Commit(ctx, Change{Events: []event.Event{ev(event.RegReject, addrA, t0, r)}})
	}
	first, err := s.EventsAfter(ctx, 0, 2)
	if err != nil || len(first) != 2 || first[0].Event.Reason != "a" || first[1].ID <= first[0].ID {
		t.Fatalf("first page: %+v %v", first, err)
	}
	rest, _ := s.EventsAfter(ctx, first[1].ID, 10)
	if len(rest) != 1 || rest[0].Event.Reason != "c" {
		t.Fatalf("rest: %+v", rest)
	}
	if c, _ := s.Cursor(ctx, "out"); c != 0 {
		t.Fatalf("initial cursor = %d", c)
	}
	_ = s.SetCursor(ctx, "out", 2)
	_ = s.SetCursor(ctx, "out", 3)
	if c, _ := s.Cursor(ctx, "out"); c != 3 {
		t.Fatalf("cursor = %d", c)
	}
}

func TestEventBodyRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	e := ev(event.RegAdd, addrA, t0, "")
	e.Host = "h1"
	e.Valid = event.U32(0)
	_ = s.Commit(ctx, Change{Events: []event.Event{e}})
	got, _ := s.EventsAfter(ctx, 0, 1)
	if got[0].Event.Host != "h1" || got[0].Event.Valid == nil || *got[0].Event.Valid != 0 || !got[0].Event.TS.Equal(t0) {
		t.Fatalf("got %+v", got[0].Event)
	}
}

func TestExpiredBindings(t *testing.T) {
	s, _ := openTemp(t)
	a, b := sampleBinding(addrA), sampleBinding(addrB)
	a.ExpiresAt, b.ExpiresAt = t0.Add(time.Hour), t0.Add(3*time.Hour)
	_ = s.Commit(ctx, Change{Put: []Binding{a, b}})
	got, err := s.ExpiredBindings(ctx, t0.Add(2*time.Hour))
	if err != nil || len(got) != 1 || got[0].Addr != addrA {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestWhereQueries(t *testing.T) {
	s, _ := openTemp(t)
	_ = s.Commit(ctx, Change{
		Events: []event.Event{
			ev(event.RegAdd, addrA, t0, "1"),
			ev(event.RegAdd, addrB, t0.Add(time.Hour), "2"),
			ev(event.RegChange, addrA, t0.Add(2*time.Hour), "3"),
		},
		Put: []Binding{sampleBinding(addrA)},
	})
	got, err := s.EventsWhere(ctx, "addr", addrA.String(), t0.Add(30*time.Minute), time.Time{})
	if err != nil || len(got) != 1 || got[0].Event.Reason != "3" {
		t.Fatalf("EventsWhere: %+v %v", got, err)
	}
	all, _ := s.EventsWhere(ctx, "addr", addrA.String(), time.Time{}, time.Time{})
	if len(all) != 2 {
		t.Fatalf("unbounded window: %d events", len(all))
	}
	if _, err := s.EventsWhere(ctx, "body", "x", time.Time{}, time.Time{}); err == nil {
		t.Fatal("accepted an invalid field")
	}
	bs, err := s.BindingsWhere(ctx, "duid", "00:03:00:01:5c:1e:9a:3b:21:aa")
	if err != nil || len(bs) != 1 {
		t.Fatalf("BindingsWhere: %+v %v", bs, err)
	}
}

func TestPurgeEventsBefore(t *testing.T) {
	s, _ := openTemp(t)
	_ = s.Commit(ctx, Change{Events: []event.Event{ev(event.RegAdd, addrA, t0, ""), ev(event.RegAdd, addrA, t0.Add(48*time.Hour), "")}})
	n, err := s.PurgeEventsBefore(ctx, t0.Add(24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
}

func TestPersistsAndReadOnly(t *testing.T) {
	s, path := openTemp(t)
	_ = s.Commit(ctx, Change{Put: []Binding{sampleBinding(addrA)}})
	s.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, ok, err := ro.GetBinding(ctx, addrA); !ok || err != nil {
		t.Fatalf("read-only GetBinding: %v %v", ok, err)
	}
	if err := ro.Commit(ctx, Change{Delete: []netip.Addr{addrA}}); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	if _, err := OpenReadOnly(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("OpenReadOnly created a missing database")
	}
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/collector/store/`
Expected: FAIL with `undefined: Open`.

- [ ] **Step 4: Implement**

`internal/collector/store/store.go`:

```go
// Package store is the collector's SQLite source of truth: an append-only
// events table, current bindings, and per-output forwarder cursors.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts   INTEGER NOT NULL,
  type TEXT NOT NULL,
  addr TEXT NOT NULL DEFAULT '',
  duid TEXT NOT NULL DEFAULT '',
  mac  TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS events_addr ON events(addr, ts);
CREATE INDEX IF NOT EXISTS events_duid ON events(duid, ts);
CREATE INDEX IF NOT EXISTS events_mac  ON events(mac, ts);
CREATE TABLE IF NOT EXISTS bindings (
  addr       TEXT PRIMARY KEY,
  duid       TEXT NOT NULL,
  mac        TEXT NOT NULL DEFAULT '',
  mac_src    TEXT NOT NULL DEFAULT '',
  origin     TEXT NOT NULL DEFAULT '',
  host       TEXT NOT NULL DEFAULT '',
  via        TEXT NOT NULL DEFAULT '',
  link       TEXT NOT NULL DEFAULT '',
  preferred  INTEGER NOT NULL,
  valid      INTEGER NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bindings_expires ON bindings(expires_at);
CREATE INDEX IF NOT EXISTS bindings_duid    ON bindings(duid);
CREATE INDEX IF NOT EXISTS bindings_mac     ON bindings(mac);
CREATE TABLE IF NOT EXISTS forwarder_state (
  name    TEXT PRIMARY KEY,
  last_id INTEGER NOT NULL
);`

const bindingCols = `addr, duid, mac, mac_src, origin, host, via, link, preferred, valid, first_seen, last_seen, expires_at`

const upsertBinding = `INSERT INTO bindings(` + bindingCols + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(addr) DO UPDATE SET
  duid=excluded.duid, mac=excluded.mac, mac_src=excluded.mac_src, origin=excluded.origin,
  host=excluded.host, via=excluded.via, link=excluded.link, preferred=excluded.preferred,
  valid=excluded.valid, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
  expires_at=excluded.expires_at`

// lookupFields whitelists columns usable in *Where queries.
var lookupFields = map[string]string{"addr": "addr", "duid": "duid", "mac": "mac"}

// Store wraps the SQLite database.
type Store struct{ db *sql.DB }

// Binding is the current registration for one address.
type Binding struct {
	Addr      netip.Addr `json:"addr"`
	DUID      string     `json:"duid"`
	MAC       string     `json:"mac,omitempty"`
	MACSrc    string     `json:"mac_src,omitempty"`
	Origin    string     `json:"origin"`
	Host      string     `json:"host,omitempty"`
	Via       string     `json:"via"`
	Link      string     `json:"link"`
	Preferred uint32     `json:"preferred_lft"`
	Valid     uint32     `json:"valid_lft"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// StoredEvent is an event with its row ID.
type StoredEvent struct {
	ID    int64
	Event event.Event
}

// Change is applied atomically by Commit.
type Change struct {
	Events []event.Event
	Put    []Binding
	Delete []netip.Addr
}

// Open opens (creating if needed) a read-write database.
func Open(path string) (*Store, error) {
	return open(path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", true)
}

// OpenReadOnly opens an existing database for queries only.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return open(path+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)", false)
}

func open(dsn string, initSchema bool) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // single writer; see plan notes on batching
	if initSchema {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: init schema: %w", err)
		}
	} else if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Commit applies c in one transaction.
func (s *Store) Commit(ctx context.Context, c Change) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, e := range c.Events {
		body, err := e.JSON()
		if err != nil {
			return fmt.Errorf("store: encode event: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events(ts, type, addr, duid, mac, body) VALUES (?, ?, ?, ?, ?, ?)`,
			e.TS.UnixMilli(), e.Type, e.Addr, e.DUID, e.MAC, string(body)); err != nil {
			return fmt.Errorf("store: insert event: %w", err)
		}
	}
	for _, b := range c.Put {
		if _, err := tx.ExecContext(ctx, upsertBinding,
			b.Addr.String(), b.DUID, b.MAC, b.MACSrc, b.Origin, b.Host, b.Via, b.Link,
			int64(b.Preferred), int64(b.Valid),
			b.FirstSeen.UnixMilli(), b.LastSeen.UnixMilli(), b.ExpiresAt.UnixMilli()); err != nil {
			return fmt.Errorf("store: upsert binding: %w", err)
		}
	}
	for _, a := range c.Delete {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bindings WHERE addr = ?`, a.String()); err != nil {
			return fmt.Errorf("store: delete binding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanBinding(sc scanner) (Binding, error) {
	var b Binding
	var addr string
	var pref, valid, first, last, exp int64
	if err := sc.Scan(&addr, &b.DUID, &b.MAC, &b.MACSrc, &b.Origin, &b.Host, &b.Via, &b.Link,
		&pref, &valid, &first, &last, &exp); err != nil {
		return Binding{}, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return Binding{}, fmt.Errorf("store: bad addr %q: %w", addr, err)
	}
	b.Addr = a
	b.Preferred, b.Valid = uint32(pref), uint32(valid)
	b.FirstSeen = time.UnixMilli(first).UTC()
	b.LastSeen = time.UnixMilli(last).UTC()
	b.ExpiresAt = time.UnixMilli(exp).UTC()
	return b, nil
}

// GetBinding returns the binding for addr, if any.
func (s *Store) GetBinding(ctx context.Context, addr netip.Addr) (Binding, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+bindingCols+` FROM bindings WHERE addr = ?`, addr.String())
	b, err := scanBinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	return b, true, nil
}

func (s *Store) queryBindings(ctx context.Context, q string, args ...any) ([]Binding, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExpiredBindings returns bindings whose expires_at is at or before now.
func (s *Store) ExpiredBindings(ctx context.Context, now time.Time) ([]Binding, error) {
	return s.queryBindings(ctx, `SELECT `+bindingCols+` FROM bindings WHERE expires_at <= ? ORDER BY expires_at`, now.UnixMilli())
}

// BindingsWhere returns bindings where field ("addr", "duid", "mac") equals value.
func (s *Store) BindingsWhere(ctx context.Context, field, value string) ([]Binding, error) {
	col, ok := lookupFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	return s.queryBindings(ctx, `SELECT `+bindingCols+` FROM bindings WHERE `+col+` = ? ORDER BY first_seen`, value)
}

func (s *Store) queryEvents(ctx context.Context, q string, args ...any) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		var se StoredEvent
		var body string
		if err := rows.Scan(&se.ID, &body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(body), &se.Event); err != nil {
			return nil, fmt.Errorf("store: decode event %d: %w", se.ID, err)
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// EventsAfter returns up to limit events with id > afterID, in id order.
func (s *Store) EventsAfter(ctx context.Context, afterID int64, limit int) ([]StoredEvent, error) {
	return s.queryEvents(ctx, `SELECT id, body FROM events WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
}

// EventsWhere returns events where field equals value within [from, to].
// A zero from or to leaves that side unbounded.
func (s *Store) EventsWhere(ctx context.Context, field, value string, from, to time.Time) ([]StoredEvent, error) {
	col, ok := lookupFields[field]
	if !ok {
		return nil, fmt.Errorf("store: invalid lookup field %q", field)
	}
	lo, hi := int64(math.MinInt64), int64(math.MaxInt64)
	if !from.IsZero() {
		lo = from.UnixMilli()
	}
	if !to.IsZero() {
		hi = to.UnixMilli()
	}
	return s.queryEvents(ctx, `SELECT id, body FROM events WHERE `+col+` = ? AND ts >= ? AND ts <= ? ORDER BY ts, id`, value, lo, hi)
}

// Cursor returns the last forwarded event ID for name (0 if none).
func (s *Store) Cursor(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT last_id FROM forwarder_state WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// SetCursor records the last forwarded event ID for name.
func (s *Store) SetCursor(ctx context.Context, name string, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO forwarder_state(name, last_id) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id`,
		name, id)
	return err
}

// PurgeEventsBefore deletes events older than t and returns how many were removed.
func (s *Store) PurgeEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go mod tidy && go test -race ./internal/collector/store/`
Expected: PASS. If `TestPersistsAndReadOnly` fails because the DSN query string isn't recognized, switch both DSNs to the `file:` URI form (`"file:" + path + "?..."`) and re-run. Note which form worked in the commit message.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/collector/store
git commit -m "feat(store): SQLite events, bindings and forwarder cursors"
```

---

### Task 5: Syslog formatting and sinks

**Files:**
- Create: `internal/collector/logger/format.go`, `internal/collector/logger/sink.go`
- Test: `internal/collector/logger/format_test.go`, `internal/collector/logger/sink_test.go`

**Interfaces:**
- Consumes: `event.Event`, `(Event).CEE()`, `(Event).JSON()`, `(Event).Severity()` (Task 3)
- Produces:
  - Formatting: `type Facility int`; `ParseFacility(string) (Facility, error)`; `const AppName = "ra-logger"`; `FormatLocal(e, Facility, pid int) ([]byte, error)`; `FormatRFC5424(e, Facility, hostname string, pid int) ([]byte, error)`; `OctetFrame([]byte) []byte`
  - `type Sink interface{ Name() string; Send(event.Event) error; Close() error }`
  - Unix socket: `NewUnixSink(path string, f Facility) *UnixSink`
  - TCP/TLS: `NewTCPSink(addr string, f Facility, hostname string) *StreamSink`; `NewTLSSink(addr string, conf *tls.Config, f Facility, hostname string) *StreamSink`
  - Writer: `NewWriterSink(name string, w io.Writer) *WriterSink`

- [ ] **Step 1: Write the failing tests**

`internal/collector/logger/format_test.go`:

```go
package logger

import (
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var ts = time.Date(2026, 11, 8, 21, 14, 3, 412_000_000, time.UTC)

func TestParseFacility(t *testing.T) {
	if f, err := ParseFacility("LOCAL5"); err != nil || f != 21 {
		t.Fatalf("got %d %v", f, err)
	}
	if _, err := ParseFacility("local9"); err == nil {
		t.Fatal("accepted local9")
	}
}

func TestFormatRFC5424(t *testing.T) {
	e := event.New(event.RegReject, ts)
	e.Reason = "scope"
	got, err := FormatRFC5424(e, 21, "collector1", 42)
	if err != nil {
		t.Fatal(err)
	}
	want := `<172>1 2026-11-08T21:14:03.412Z collector1 ra-logger 42 reg.reject - @cee:{"ts":"2026-11-08T21:14:03.412Z","event":"reg.reject","reason":"scope"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestFormatRFC5424SanitizesHostname(t *testing.T) {
	e := event.New(event.RegAdd, ts)
	got, _ := FormatRFC5424(e, 21, "bad host\n", 1)
	if !strings.Contains(string(got), " bad_host_ ra-logger ") {
		t.Fatalf("got %s", got)
	}
	got, _ = FormatRFC5424(e, 21, "", 1)
	if !strings.Contains(string(got), "Z - ra-logger ") {
		t.Fatalf("empty hostname not replaced by nil value: %s", got)
	}
}

func TestFormatLocal(t *testing.T) {
	e := event.New(event.RegAdd, ts)
	got, err := FormatLocal(e, 21, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "<174>" + e.TS.Local().Format(time.Stamp) + ` ra-logger[42]: @cee:{"ts":"2026-11-08T21:14:03.412Z","event":"reg.add"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestOctetFrame(t *testing.T) {
	if got := string(OctetFrame([]byte("hello"))); got != "5 hello" {
		t.Fatalf("got %q", got)
	}
}
```

`internal/collector/logger/sink_test.go`:

```go
package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

func TestStreamSinkReconnects(t *testing.T) {
	var mu sync.Mutex
	var got []string
	dials := 0
	s := &StreamSink{name: "test", fac: 21, hostname: "h", pid: 1}
	s.dial = func() (net.Conn, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("connection refused")
		}
		client, server := net.Pipe()
		go func() {
			buf := make([]byte, 4096)
			n, _ := server.Read(buf)
			mu.Lock()
			got = append(got, string(buf[:n]))
			mu.Unlock()
			server.Close()
		}()
		return client, nil
	}
	e := event.New(event.RegAdd, time.Now())
	if err := s.Send(e); err == nil {
		t.Fatal("first send should fail while the server is down")
	}
	if err := s.Send(e); err != nil {
		t.Fatalf("second send: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !regexp.MustCompile(`^\d+ <174>1 `).MatchString(got[0]) {
		t.Fatalf("frames = %q", got)
	}
}

func TestUnixSink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram sockets are not available on Windows")
	}
	dir, err := os.MkdirTemp("", "ral") // short path: macOS limits socket paths to 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "log.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := NewUnixSink(sock, 21)
	defer s.Close()
	if err := s.Send(event.New(event.RegAdd, time.Now())); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	line := string(buf[:n])
	if !strings.HasPrefix(line, "<174>") || !strings.Contains(line, "ra-logger[") || !strings.Contains(line, `"event":"reg.add"`) {
		t.Fatalf("line = %q", line)
	}
}

func TestWriterSink(t *testing.T) {
	var buf bytes.Buffer
	s := NewWriterSink("stdout", &buf)
	if err := s.Send(event.New(event.RegAdd, time.Now())); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("line = %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil || m["event"] != "reg.add" {
		t.Fatalf("not JSON: %q %v", line, err)
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/collector/logger/`
Expected: FAIL with `undefined: ParseFacility`, `undefined: StreamSink`.

- [ ] **Step 3: Implement**

`internal/collector/logger/format.go`:

```go
// Package logger formats events as syslog messages, delivers them to sinks,
// and forwards the store's event stream to each sink at-least-once.
package logger

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Facility is a syslog facility number.
type Facility int

var facilityNames = map[string]Facility{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// ParseFacility parses a facility name such as "local5".
func ParseFacility(s string) (Facility, error) {
	f, ok := facilityNames[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("logger: unknown syslog facility %q", s)
	}
	return f, nil
}

// AppName is the syslog APP-NAME / tag.
const AppName = "ra-logger"

const rfc5424Time = "2006-01-02T15:04:05.000Z07:00"

func pri(f Facility, e event.Event) int { return int(f)*8 + int(e.Severity()) }

// FormatLocal renders the BSD-style line glibc syslog(3) sends to /dev/log:
// "<PRI>Mmm dd hh:mm:ss ra-logger[PID]: @cee:{...}".
func FormatLocal(e event.Event, f Facility, pid int) ([]byte, error) {
	msg, err := e.CEE()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "<%d>%s %s[%d]: %s", pri(f, e), e.TS.Local().Format(time.Stamp), AppName, pid, msg), nil
}

// FormatRFC5424 renders "<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID - MSG".
func FormatRFC5424(e event.Event, f Facility, hostname string, pid int) ([]byte, error) {
	msg, err := e.CEE()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "<%d>1 %s %s %s %d %s - %s",
		pri(f, e), e.TS.UTC().Format(rfc5424Time), sanitizeHeader(hostname), AppName, pid, e.Type, msg), nil
}

// sanitizeHeader makes s a valid RFC 5424 header field (PRINTUSASCII, max 255).
func sanitizeHeader(s string) string {
	if s == "" {
		return "-"
	}
	b := []byte(s)
	if len(b) > 255 {
		b = b[:255]
	}
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			b[i] = '_'
		}
	}
	return string(b)
}

// OctetFrame applies RFC 6587 octet-counting framing.
func OctetFrame(msg []byte) []byte {
	out := strconv.AppendInt(nil, int64(len(msg)), 10)
	out = append(out, ' ')
	return append(out, msg...)
}
```

`internal/collector/logger/sink.go`:

```go
package logger

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Sink delivers one event. Implementations are safe for concurrent use.
type Sink interface {
	Name() string
	Send(e event.Event) error
	Close() error
}

// UnixSink writes to a local syslog datagram socket such as /dev/log.
type UnixSink struct {
	path string
	fac  Facility
	pid  int
	mu   sync.Mutex
	conn net.Conn
}

// NewUnixSink returns a sink for the unixgram socket at path.
func NewUnixSink(path string, f Facility) *UnixSink {
	return &UnixSink{path: path, fac: f, pid: os.Getpid()}
}

func (s *UnixSink) Name() string { return "unix:" + s.path }

func (s *UnixSink) Send(e event.Event) error {
	line, err := FormatLocal(e, s.fac, s.pid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := net.Dial("unixgram", s.path)
		if err != nil {
			return fmt.Errorf("logger: dial %s: %w", s.path, err)
		}
		s.conn = c
	}
	if _, err := s.conn.Write(line); err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("logger: write %s: %w", s.path, err)
	}
	return nil
}

func (s *UnixSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// StreamSink sends RFC 5424 messages with octet-counting framing over TCP or TLS,
// reconnecting lazily after errors.
type StreamSink struct {
	name     string
	dial     func() (net.Conn, error)
	fac      Facility
	hostname string
	pid      int
	mu       sync.Mutex
	conn     net.Conn
}

// NewTCPSink returns a plain-TCP syslog sink.
func NewTCPSink(addr string, f Facility, hostname string) *StreamSink {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &StreamSink{
		name: "tcp:" + addr, fac: f, hostname: hostname, pid: os.Getpid(),
		dial: func() (net.Conn, error) { return d.Dial("tcp", addr) },
	}
}

// NewTLSSink returns a TLS syslog sink (RFC 5425).
func NewTLSSink(addr string, conf *tls.Config, f Facility, hostname string) *StreamSink {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: conf}
	return &StreamSink{
		name: "tls:" + addr, fac: f, hostname: hostname, pid: os.Getpid(),
		dial: func() (net.Conn, error) { return d.Dial("tcp", addr) },
	}
}

func (s *StreamSink) Name() string { return s.name }

func (s *StreamSink) Send(e event.Event) error {
	msg, err := FormatRFC5424(e, s.fac, s.hostname, s.pid)
	if err != nil {
		return err
	}
	frame := OctetFrame(msg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := s.dial()
		if err != nil {
			return fmt.Errorf("logger: dial %s: %w", s.name, err)
		}
		s.conn = c
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(frame); err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("logger: write %s: %w", s.name, err)
	}
	return nil
}

func (s *StreamSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// WriterSink writes one JSON object per line (for stdout/journald/containers).
type WriterSink struct {
	name string
	mu   sync.Mutex
	w    io.Writer
}

// NewWriterSink returns a sink writing JSON lines to w.
func NewWriterSink(name string, w io.Writer) *WriterSink { return &WriterSink{name: name, w: w} }

func (s *WriterSink) Name() string { return s.name }

func (s *WriterSink) Send(e event.Event) error {
	j, err := e.JSON()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(j, '\n'))
	return err
}

func (s *WriterSink) Close() error { return nil }
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/collector/logger/`
Expected: PASS. `TestUnixSink` is skipped on Windows.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/logger
git commit -m "feat(logger): RFC 3164/5424 formatting and unix, TCP/TLS, writer sinks"
```

---

### Task 6: Forwarder (at-least-once delivery from the store) and Recorder (fallback when the store fails)

**Files:**
- Create: `internal/collector/logger/forwarder.go`, `internal/collector/recorder/recorder.go`
- Test: `internal/collector/logger/forwarder_test.go`, `internal/collector/recorder/recorder_test.go`

**Interfaces:**
- Consumes: `store.Store` (`EventsAfter`, `Cursor`, `SetCursor`, `Commit`), `store.StoredEvent`, `store.Change` (Task 4); `logger.Sink`, `logger.NewWriterSink` (Task 5)
- Produces:
  - `type Source interface{ EventsAfter(ctx, int64, int) ([]store.StoredEvent, error); Cursor(ctx, string) (int64, error); SetCursor(ctx, string, int64) error }`
  - `type Forwarder struct{Name string; Src Source; Sink Sink; Poll time.Duration; Batch int; MaxBackoff time.Duration; Log *slog.Logger}`; `(*Forwarder) RunOnce(ctx) (int, error)`; `(*Forwarder) Run(ctx)`; `Backoff(attempt int, max time.Duration) time.Duration`
  - `recorder.Committer interface{ Commit(ctx, store.Change) error }`
  - `recorder.Recorder{Store Committer; Fallback []logger.Sink; Log *slog.Logger; Now func() time.Time}`; `(*Recorder) Record(ctx, store.Change) error`

- [ ] **Step 1: Write the failing tests**

`internal/collector/logger/forwarder_test.go`:

```go
package logger

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

type flakySink struct {
	mu     sync.Mutex
	failAt map[int]bool
	calls  int
	got    []string
}

func (s *flakySink) Name() string { return "flaky" }
func (s *flakySink) Close() error { return nil }
func (s *flakySink) Send(e event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failAt[s.calls] {
		return errors.New("down")
	}
	s.got = append(s.got, e.Reason)
	return nil
}

func storeWith(t *testing.T, reasons ...string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	addEvents(t, st, reasons...)
	return st
}

func addEvents(t *testing.T, st *store.Store, reasons ...string) {
	t.Helper()
	for _, r := range reasons {
		e := event.New(event.RegReject, time.Now())
		e.Reason = r
		if err := st.Commit(context.Background(), store.Change{Events: []event.Event{e}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestForwarderAtLeastOnce(t *testing.T) {
	ctx := context.Background()
	st := storeWith(t, "a", "b", "c")
	sink := &flakySink{failAt: map[int]bool{2: true}}
	f := &Forwarder{Name: "out", Src: st, Sink: sink}

	n, err := f.RunOnce(ctx)
	if n != 1 || err == nil {
		t.Fatalf("first run: n=%d err=%v", n, err)
	}
	if cur, _ := st.Cursor(ctx, "out"); cur != 1 {
		t.Fatalf("cursor after partial failure = %d, want 1", cur)
	}
	if n, err = f.RunOnce(ctx); n != 2 || err != nil {
		t.Fatalf("second run: n=%d err=%v", n, err)
	}
	if n, err = f.RunOnce(ctx); n != 0 || err != nil {
		t.Fatalf("third run: n=%d err=%v", n, err)
	}
	if got := sink.got; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("delivered %v", got)
	}
}

func TestForwarderResumesAfterRestart(t *testing.T) {
	ctx := context.Background()
	st := storeWith(t, "a", "b")
	first := &flakySink{}
	if _, err := (&Forwarder{Name: "out", Src: st, Sink: first}).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	addEvents(t, st, "c")
	second := &flakySink{}
	if _, err := (&Forwarder{Name: "out", Src: st, Sink: second}).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(second.got) != 1 || second.got[0] != "c" {
		t.Fatalf("restarted forwarder sent %v, want [c]", second.got)
	}
}

func TestForwarderBatch(t *testing.T) {
	st := storeWith(t, "a", "b", "c")
	f := &Forwarder{Name: "out", Src: st, Sink: &flakySink{}, Batch: 2}
	if n, _ := f.RunOnce(context.Background()); n != 2 {
		t.Fatalf("n = %d, want 2", n)
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 10: time.Minute, 100: time.Minute}
	for attempt, want := range cases {
		if got := Backoff(attempt, time.Minute); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}

func TestForwarderRunStopsOnCancel(t *testing.T) {
	st := storeWith(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Forwarder{Name: "out", Src: st, Sink: &flakySink{}, Poll: 10 * time.Millisecond}).Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
```

`internal/collector/recorder/recorder_test.go`:

```go
package recorder

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

type fakeCommitter struct{ err error }

func (f fakeCommitter) Commit(context.Context, store.Change) error { return f.err }

func TestRecordFallsBackWhenStoreFails(t *testing.T) {
	var buf bytes.Buffer
	r := &Recorder{
		Store:    fakeCommitter{err: errors.New("disk full")},
		Fallback: []logger.Sink{logger.NewWriterSink("buf", &buf)},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e := event.New(event.RegAdd, time.Now())
	if err := r.Record(context.Background(), store.Change{Events: []event.Event{e}}); err == nil {
		t.Fatal("expected the store error to be returned")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"event":"reg.add"`) ||
		!strings.Contains(lines[1], `"event":"store.error"`) || !strings.Contains(lines[1], "disk full") {
		t.Fatalf("fallback output:\n%s", buf.String())
	}
}

func TestRecordSuccessSkipsFallback(t *testing.T) {
	var buf bytes.Buffer
	r := &Recorder{Store: fakeCommitter{}, Fallback: []logger.Sink{logger.NewWriterSink("buf", &buf)}}
	if err := r.Record(context.Background(), store.Change{Events: []event.Event{event.New(event.RegAdd, time.Now())}}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("fallback written on success: %s", buf.String())
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/collector/logger/ ./internal/collector/recorder/`
Expected: FAIL with `undefined: Forwarder`, `undefined: Recorder`.

- [ ] **Step 3: Implement**

`internal/collector/logger/forwarder.go`:

```go
package logger

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
)

// Source is the subset of *store.Store a Forwarder needs.
type Source interface {
	EventsAfter(ctx context.Context, afterID int64, limit int) ([]store.StoredEvent, error)
	Cursor(ctx context.Context, name string) (int64, error)
	SetCursor(ctx context.Context, name string, id int64) error
}

// Forwarder delivers stored events to one Sink, at least once, tracking
// progress in a named cursor so restarts resume where they left off.
type Forwarder struct {
	Name       string
	Src        Source
	Sink       Sink
	Poll       time.Duration // idle poll interval; default 1s
	Batch      int           // events per RunOnce; default 256
	MaxBackoff time.Duration // default 60s
	Log        *slog.Logger
}

func (f *Forwarder) batch() int {
	if f.Batch > 0 {
		return f.Batch
	}
	return 256
}

func (f *Forwarder) poll() time.Duration {
	if f.Poll > 0 {
		return f.Poll
	}
	return time.Second
}

func (f *Forwarder) maxBackoff() time.Duration {
	if f.MaxBackoff > 0 {
		return f.MaxBackoff
	}
	return time.Minute
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

// RunOnce sends up to one batch of pending events. On a send error it saves
// progress through the last delivered event and returns the error.
func (f *Forwarder) RunOnce(ctx context.Context) (int, error) {
	cur, err := f.Src.Cursor(ctx, f.Name)
	if err != nil {
		return 0, err
	}
	evs, err := f.Src.EventsAfter(ctx, cur, f.batch())
	if err != nil {
		return 0, err
	}
	sent, last := 0, cur
	for _, se := range evs {
		if err := f.Sink.Send(se.Event); err != nil {
			if last != cur {
				err = errors.Join(err, f.Src.SetCursor(ctx, f.Name, last))
			}
			return sent, err
		}
		last = se.ID
		sent++
	}
	if last != cur {
		if err := f.Src.SetCursor(ctx, f.Name, last); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// Run forwards until ctx is cancelled, backing off exponentially on errors.
func (f *Forwarder) Run(ctx context.Context) {
	attempt := 0
	for {
		n, err := f.RunOnce(ctx)
		var wait time.Duration
		switch {
		case err != nil:
			attempt++
			wait = Backoff(attempt, f.maxBackoff())
			f.log().Warn("forwarder: delivery failed", "sink", f.Sink.Name(), "attempt", attempt, "retry_in", wait, "err", err)
		case n == f.batch():
			attempt = 0 // more pending; loop immediately
		default:
			attempt = 0
			wait = f.poll()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Backoff returns 1s, 2s, 4s, ... capped at max.
func Backoff(attempt int, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Second << min(attempt-1, 16)
	if d > max || d <= 0 {
		return max
	}
	return d
}
```

`internal/collector/recorder/recorder.go`:

```go
// Package recorder commits changes to the store and, if the store fails,
// writes the events straight to the log sinks so nothing is lost silently.
package recorder

import (
	"context"
	"log/slog"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Committer is the subset of *store.Store the Recorder needs.
type Committer interface {
	Commit(ctx context.Context, c store.Change) error
}

// Recorder is the single write path for collector components.
type Recorder struct {
	Store    Committer
	Fallback []logger.Sink
	Log      *slog.Logger
	Now      func() time.Time
}

// Record commits c. On failure it sends c's events plus a store.error event
// directly to every fallback sink and returns the store error.
func (r *Recorder) Record(ctx context.Context, c store.Change) error {
	err := r.Store.Commit(ctx, c)
	if err == nil {
		return nil
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	if r.Log != nil {
		r.Log.Error("recorder: store commit failed; writing events directly to sinks", "err", err)
	}
	se := event.New(event.StoreError, now())
	se.Reason = err.Error()
	for _, s := range r.Fallback {
		for _, e := range c.Events {
			_ = s.Send(e)
		}
		_ = s.Send(se)
	}
	return err
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/collector/logger/ ./internal/collector/recorder/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/logger internal/collector/recorder
git commit -m "feat(logger): at-least-once forwarder with cursors; recorder with sink fallback"
```

---

### Task 7: Registrar request types, prefix policy, validation and rate limiting

**Files:**
- Create: `internal/collector/registrar/request.go`, `policy.go`, `validate.go`, `ratelimit.go`
- Test: `internal/collector/registrar/helpers_test.go`, `validate_test.go`, `ratelimit_test.go`

**Interfaces:**
- Consumes: `dhcp6.Message`, `dhcp6.ParseIAAddress`, option constants, `dhcp6.IAAddress` (Tasks 1–2)
- Produces:
  - Constants `ViaMulticast="multicast"`, `ViaUnicast="unicast"`, `ViaRelay="relay"`
  - `type RelayInfo struct{LinkAddr, PeerAddr netip.Addr; InterfaceID []byte; CLLAO net.HardwareAddr}`
  - `type Request struct{Msg *dhcp6.Message; Src netip.AddrPort; IfName string; Via string; Relay *RelayInfo}`
  - `type PrefixPolicy struct{OnLink func(ifname string) []netip.Prefix; Relay, Unicast []netip.Prefix}`; `(*PrefixPolicy) Allowed(*Request, netip.Addr) bool`
  - Reason constants `ReasonNotAddrReg, ReasonClientID, ReasonServerID, ReasonORO, ReasonIAAddr, ReasonScope, ReasonSourceMismatch, ReasonPrefix, ReasonRateLimited` (strings); `const MaxDUIDLen = 130`
  - `type Valid struct{DUID []byte; IA dhcp6.IAAddress; IARaw []byte}`; `Validate(*Request, *PrefixPolicy) (Valid, string)`
  - Rate limiting: `type Rate struct{PerSecond float64; Burst int}`; `type Limits struct{Global, PerPrefix, PerDUID Rate}`; `var DefaultLimits Limits`; `NewLimiter(Limits) *Limiter`; `(*Limiter) AllowSource(netip.Addr, time.Time) bool`; `(*Limiter) AllowDUID([]byte, time.Time) bool`

- [ ] **Step 1: Add the dependency**

Run: `go get golang.org/x/time/rate@latest`

- [ ] **Step 2: Write the failing tests**

`internal/collector/registrar/helpers_test.go` (shared with Task 8):

```go
package registrar

import (
	"net"
	"net/netip"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

var (
	testAddr = netip.MustParseAddr("2001:db8:10::5")
	testMAC  = net.HardwareAddr{0x5c, 0x1e, 0x9a, 0x3b, 0x21, 0xaa}
	testDUID = dhcp6.NewDUIDLL(testMAC)
	otherDUID = dhcp6.NewDUIDLL(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99})
	onLink   = netip.MustParsePrefix("2001:db8:10::/64")
	relayAddr = netip.MustParseAddr("2001:db8:ffff::1")
	relayLink = netip.MustParseAddr("2001:db8:10::1")
)

func testPolicy() *PrefixPolicy {
	return &PrefixPolicy{
		OnLink:  func(string) []netip.Prefix { return []netip.Prefix{onLink} },
		Relay:   []netip.Prefix{onLink},
		Unicast: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
}

func inform(t *testing.T, addr netip.Addr, duid []byte, valid uint32, extra ...dhcp6.Option) *dhcp6.Message {
	t.Helper()
	pref := valid / 2
	if valid == dhcp6.Infinity {
		pref = dhcp6.Infinity
	}
	m, err := dhcp6.NewAddrRegInform([3]byte{1, 2, 3}, duid, dhcp6.IAAddress{Addr: addr, Preferred: pref, Valid: valid}, extra...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mcastReq(m *dhcp6.Message, src netip.Addr) *Request {
	return &Request{Msg: m, Src: netip.AddrPortFrom(src, 546), IfName: "eth0", Via: ViaMulticast}
}

func relayReq(m *dhcp6.Message, peer netip.Addr) *Request {
	return &Request{
		Msg: m, Src: netip.AddrPortFrom(relayAddr, 547), IfName: "eth0", Via: ViaRelay,
		Relay: &RelayInfo{LinkAddr: relayLink, PeerAddr: peer},
	}
}

func without(m *dhcp6.Message, code uint16) *dhcp6.Message {
	out := &dhcp6.Message{Type: m.Type, XID: m.XID}
	for _, o := range m.Options {
		if o.Code != code {
			out.Options = append(out.Options, o)
		}
	}
	return out
}

func with(m *dhcp6.Message, opts ...dhcp6.Option) *dhcp6.Message {
	out := &dhcp6.Message{Type: m.Type, XID: m.XID, Options: append(dhcp6.Options{}, m.Options...)}
	out.Options = append(out.Options, opts...)
	return out
}
```

`internal/collector/registrar/validate_test.go`:

```go
package registrar

import (
	"net/netip"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func TestValidate(t *testing.T) {
	good := inform(t, testAddr, testDUID, 7200)
	iaOpt, _ := good.Options.Get(dhcp6.OptIAAddr)
	other := netip.MustParseAddr("2001:db8:10::6")
	offLink := netip.MustParseAddr("2001:db8:99::5")
	outside := netip.MustParseAddr("2001:db9::5")
	ll := netip.MustParseAddr("fe80::1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")

	notInform := inform(t, testAddr, testDUID, 7200)
	notInform.Type = dhcp6.MsgInformationRequest

	relayBadLink := relayReq(good, testAddr)
	relayBadLink.Relay.LinkAddr = netip.MustParseAddr("2001:db8:77::1")

	cases := []struct {
		name string
		req  *Request
		want string
	}{
		{"valid multicast", mcastReq(good, testAddr), ""},
		{"not addr-reg-inform", mcastReq(notInform, testAddr), ReasonNotAddrReg},
		{"no client id", mcastReq(without(good, dhcp6.OptClientID), testAddr), ReasonClientID},
		{"two client ids", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptClientID, Data: testDUID}), testAddr), ReasonClientID},
		{"client id too short", mcastReq(with(without(good, dhcp6.OptClientID), dhcp6.Option{Code: dhcp6.OptClientID, Data: []byte{1}}), testAddr), ReasonClientID},
		{"server id present", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 1}}), testAddr), ReasonServerID},
		{"oro present", mcastReq(with(good, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}}), testAddr), ReasonORO},
		{"no ia", mcastReq(without(good, dhcp6.OptIAAddr), testAddr), ReasonIAAddr},
		{"two ia", mcastReq(with(good, iaOpt), testAddr), ReasonIAAddr},
		{"malformed ia", mcastReq(with(without(good, dhcp6.OptIAAddr), dhcp6.Option{Code: dhcp6.OptIAAddr, Data: []byte{1, 2, 3}}), testAddr), ReasonIAAddr},
		{"link-local", mcastReq(inform(t, ll, testDUID, 7200), ll), ReasonScope},
		{"v4-mapped", mcastReq(inform(t, mapped, testDUID, 7200), mapped), ReasonScope},
		{"source mismatch", mcastReq(good, other), ReasonSourceMismatch},
		{"not on link", mcastReq(inform(t, offLink, testDUID, 7200), offLink), ReasonPrefix},
		{"unicast allowed", &Request{Msg: good, Src: netip.AddrPortFrom(testAddr, 546), Via: ViaUnicast}, ""},
		{"unicast outside", &Request{Msg: inform(t, outside, testDUID, 7200), Src: netip.AddrPortFrom(outside, 546), Via: ViaUnicast}, ReasonPrefix},
		{"relay ok", relayReq(good, testAddr), ""},
		{"relay peer mismatch", relayReq(good, other), ReasonSourceMismatch},
		{"relay link outside", relayBadLink, ReasonPrefix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, reason := Validate(tc.req, testPolicy())
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
			if tc.want == "" {
				o, _ := tc.req.Msg.Options.Get(dhcp6.OptIAAddr)
				ia, _ := dhcp6.ParseIAAddress(o.Data)
				if v.IA.Addr != ia.Addr || len(v.DUID) == 0 || len(v.IARaw) != 24 {
					t.Fatalf("bad Valid: %+v", v)
				}
			}
		})
	}
}
```

`internal/collector/registrar/ratelimit_test.go`:

```go
package registrar

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func TestKeyedBurstAndRefill(t *testing.T) {
	k := newKeyed(rate.Limit(1), 2)
	if !k.Allow("a", t0) || !k.Allow("a", t0) {
		t.Fatal("burst of 2 not allowed")
	}
	if k.Allow("a", t0) {
		t.Fatal("third request inside burst allowed")
	}
	if !k.Allow("b", t0) {
		t.Fatal("independent key limited")
	}
	if !k.Allow("a", t0.Add(time.Second)) {
		t.Fatal("token not refilled after 1s")
	}
}

func TestKeyedEvictsIdle(t *testing.T) {
	k := newKeyed(rate.Limit(1), 1)
	k.Allow("a", t0)
	k.Allow("b", t0.Add(11*time.Minute))
	if len(k.m) != 1 {
		t.Fatalf("entries = %d, want 1 after idle eviction", len(k.m))
	}
}

func TestLimiterSourceIsPerSlash64(t *testing.T) {
	l := NewLimiter(Limits{Global: Rate{1000, 1000}, PerPrefix: Rate{0.001, 1}, PerDUID: Rate{1000, 1000}})
	if !l.AllowSource(netip.MustParseAddr("2001:db8:10::5"), t0) {
		t.Fatal("first source denied")
	}
	if l.AllowSource(netip.MustParseAddr("2001:db8:10::6"), t0) {
		t.Fatal("same /64 not limited")
	}
	if !l.AllowSource(netip.MustParseAddr("2001:db8:11::5"), t0) {
		t.Fatal("different /64 limited")
	}
}

func TestLimiterGlobalAndDUID(t *testing.T) {
	l := NewLimiter(Limits{Global: Rate{0.001, 1}, PerPrefix: Rate{1000, 1000}, PerDUID: Rate{0.001, 1}})
	if !l.AllowSource(netip.MustParseAddr("2001:db8:10::5"), t0) || l.AllowSource(netip.MustParseAddr("2001:db8:20::5"), t0) {
		t.Fatal("global limit not enforced")
	}
	if !l.AllowDUID([]byte{0, 3, 1}, t0) || l.AllowDUID([]byte{0, 3, 1}, t0) {
		t.Fatal("per-DUID limit not enforced")
	}
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/collector/registrar/`
Expected: FAIL with `undefined: Validate`, `undefined: newKeyed`.

- [ ] **Step 4: Implement**

`internal/collector/registrar/request.go`:

```go
// Package registrar implements the RFC 9686 server side: it validates
// ADDR-REG-INFORM messages, maintains bindings, and builds ADDR-REG-REPLY.
package registrar

import (
	"net"
	"net/netip"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// How a registration reached the collector.
const (
	ViaMulticast = "multicast"
	ViaUnicast   = "unicast"
	ViaRelay     = "relay"
)

// RelayInfo is taken from the innermost Relay-Forward.
type RelayInfo struct {
	LinkAddr    netip.Addr
	PeerAddr    netip.Addr
	InterfaceID []byte
	CLLAO       net.HardwareAddr
}

// Request is one decoded ADDR-REG-INFORM plus how it arrived.
type Request struct {
	Msg    *dhcp6.Message
	Src    netip.AddrPort // UDP source of the packet (relay agent when Via == ViaRelay)
	IfName string
	Via    string
	Relay  *RelayInfo
}
```

`internal/collector/registrar/policy.go`:

```go
package registrar

import "net/netip"

// PrefixPolicy decides whether an address is "appropriate to the link" (RFC 9686 §5).
type PrefixPolicy struct {
	OnLink  func(ifname string) []netip.Prefix // multicast: on-link prefixes of the arrival interface
	Relay   []netip.Prefix                     // relayed: addr and relay link-address must share one
	Unicast []netip.Prefix                     // direct unicast: explicit allow list, default deny
}

// Allowed reports whether addr may be registered for req.
func (p *PrefixPolicy) Allowed(req *Request, addr netip.Addr) bool {
	switch req.Via {
	case ViaMulticast:
		return p.OnLink != nil && containsAny(p.OnLink(req.IfName), addr)
	case ViaRelay:
		if req.Relay == nil {
			return false
		}
		for _, pf := range p.Relay {
			if pf.Contains(addr) && pf.Contains(req.Relay.LinkAddr) {
				return true
			}
		}
		return false
	case ViaUnicast:
		return containsAny(p.Unicast, addr)
	}
	return false
}

func containsAny(pfx []netip.Prefix, a netip.Addr) bool {
	for _, p := range pfx {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
```

`internal/collector/registrar/validate.go`:

```go
package registrar

import "github.com/buraglio/ipv6-ra-logger/internal/dhcp6"

// Reject reasons (the "reason" field of reg.reject events).
const (
	ReasonNotAddrReg     = "not_addr_reg_inform"
	ReasonClientID       = "client_id"
	ReasonServerID       = "server_id_present"
	ReasonORO            = "oro_present"
	ReasonIAAddr         = "ia_addr"
	ReasonScope          = "scope"
	ReasonSourceMismatch = "source_mismatch"
	ReasonPrefix         = "prefix_not_allowed"
	ReasonRateLimited    = "rate_limited"
	ReasonDeregForeign   = "dereg_foreign_duid"
	ReasonSuppressed     = "suppressed"
)

// MaxDUIDLen is the largest valid DUID: 2-byte type + 128 bytes (RFC 8415 §11.1).
const MaxDUIDLen = 130

// Valid holds the fields of a message that passed validation.
type Valid struct {
	DUID  []byte
	IA    dhcp6.IAAddress
	IARaw []byte // the IA Address option payload, echoed verbatim in the reply
}

// Validate applies RFC 9686 §5 server checks. It returns a reject reason, or "".
func Validate(req *Request, pol *PrefixPolicy) (Valid, string) {
	m := req.Msg
	if m == nil || m.Type != dhcp6.MsgAddrRegInform {
		return Valid{}, ReasonNotAddrReg
	}
	if m.Options.Count(dhcp6.OptClientID) != 1 {
		return Valid{}, ReasonClientID
	}
	cid, _ := m.Options.Get(dhcp6.OptClientID)
	if len(cid.Data) < 2 || len(cid.Data) > MaxDUIDLen {
		return Valid{}, ReasonClientID
	}
	if m.Options.Count(dhcp6.OptServerID) > 0 {
		return Valid{}, ReasonServerID
	}
	if m.Options.Count(dhcp6.OptORO) > 0 {
		return Valid{}, ReasonORO
	}
	if m.Options.Count(dhcp6.OptIAAddr) != 1 {
		return Valid{}, ReasonIAAddr
	}
	iaOpt, _ := m.Options.Get(dhcp6.OptIAAddr)
	ia, err := dhcp6.ParseIAAddress(iaOpt.Data)
	if err != nil {
		return Valid{}, ReasonIAAddr
	}
	a := ia.Addr
	if a.Is4In6() || !a.IsGlobalUnicast() { // IsGlobalUnicast includes ULA
		return Valid{}, ReasonScope
	}
	if req.Via == ViaRelay {
		if req.Relay == nil || req.Relay.PeerAddr != a {
			return Valid{}, ReasonSourceMismatch
		}
	} else if req.Src.Addr().Unmap().WithZone("") != a {
		return Valid{}, ReasonSourceMismatch
	}
	if !pol.Allowed(req, a) {
		return Valid{}, ReasonPrefix
	}
	return Valid{DUID: cid.Data, IA: ia, IARaw: iaOpt.Data}, ""
}
```

`internal/collector/registrar/ratelimit.go`:

```go
package registrar

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate is a token-bucket rate.
type Rate struct {
	PerSecond float64
	Burst     int
}

// Limits configures the three registration limiters.
type Limits struct {
	Global    Rate
	PerPrefix Rate // keyed by the source /64; a LAN shares one /64, so keep this generous
	PerDUID   Rate
}

// DefaultLimits suit a few thousand hosts per collector.
var DefaultLimits = Limits{
	Global:    Rate{PerSecond: 500, Burst: 2000},
	PerPrefix: Rate{PerSecond: 50, Burst: 500},
	PerDUID:   Rate{PerSecond: 2, Burst: 64},
}

// Limiter applies global, per-/64 and per-DUID token buckets.
type Limiter struct {
	global *rate.Limiter
	prefix *keyed
	duid   *keyed
}

// NewLimiter builds a Limiter from l.
func NewLimiter(l Limits) *Limiter {
	return &Limiter{
		global: rate.NewLimiter(rate.Limit(l.Global.PerSecond), l.Global.Burst),
		prefix: newKeyed(rate.Limit(l.PerPrefix.PerSecond), l.PerPrefix.Burst),
		duid:   newKeyed(rate.Limit(l.PerDUID.PerSecond), l.PerDUID.Burst),
	}
}

// AllowSource checks the global and per-/64 buckets for src.
func (l *Limiter) AllowSource(src netip.Addr, now time.Time) bool {
	if !l.global.AllowN(now, 1) {
		return false
	}
	p, err := src.Unmap().WithZone("").Prefix(64)
	if err != nil {
		return false
	}
	return l.prefix.Allow(p.String(), now)
}

// AllowDUID checks the per-DUID bucket.
func (l *Limiter) AllowDUID(duid []byte, now time.Time) bool {
	return l.duid.Allow(string(duid), now)
}

const keyedIdle = 10 * time.Minute

type keyedEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// keyed is a map of token buckets with idle eviction to bound memory.
type keyed struct {
	mu        sync.Mutex
	r         rate.Limit
	burst     int
	m         map[string]*keyedEntry
	lastSweep time.Time
}

func newKeyed(r rate.Limit, burst int) *keyed {
	return &keyed{r: r, burst: burst, m: map[string]*keyedEntry{}}
}

func (k *keyed) Allow(key string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now.Sub(k.lastSweep) > time.Minute {
		for key, e := range k.m {
			if now.Sub(e.seen) > keyedIdle {
				delete(k.m, key)
			}
		}
		k.lastSweep = now
	}
	e, ok := k.m[key]
	if !ok {
		e = &keyedEntry{lim: rate.NewLimiter(k.r, k.burst)}
		k.m[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go mod tidy && go test -race ./internal/collector/registrar/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/collector/registrar
git commit -m "feat(registrar): RFC 9686 validation, prefix policy and rate limits"
```

---

### Task 8: Registrar handling, bindings, replies and expiry

**Files:**
- Create: `internal/collector/registrar/registrar.go`
- Test: `internal/collector/registrar/registrar_test.go`

**Interfaces:**
- Consumes:
  - Task 7: `Request`, `Validate`, `Limiter`, `PrefixPolicy`, the reason constants
  - Task 4: `store.Binding`, `store.Change`, `*store.Store`
  - Task 3: `event.*`
  - Task 2: `dhcp6.ParseVendorClass`, `dhcp6.ParseFQDN`, `dhcp6.MACFromDUID`, `dhcp6.FormatHex`, `dhcp6.ParseHex`, `dhcp6.DUIDTypeName`
- Produces:
  - `type BindingStore interface{ GetBinding(ctx, netip.Addr) (store.Binding, bool, error); ExpiredBindings(ctx, time.Time) ([]store.Binding, error) }`
  - `type Recorder interface{ Record(ctx, store.Change) error }` (satisfied by `*recorder.Recorder`)
  - `type Stats struct{Received, Replied, Rejected, RateLimited atomic.Uint64}`; `(*Stats) Snapshot() map[string]uint64`
  - `type Registrar struct{Bindings; Rec; Policy; Limits; ServerID; PEN; Now; Log; Stats ...}`
  - `New(b BindingStore, rec Recorder, pol *PrefixPolicy, serverID []byte, pen uint32) *Registrar`
  - `(*Registrar) Handle(ctx, *Request) *dhcp6.Message` (nil = drop); `(*Registrar) Sweep(ctx)`
  - Constants `InfiniteTTL = 12h`, `AgentPrefix = "ra-logger-agent/"`, `OriginNative`, `OriginAgent`, `MACSrcCLLAO`, `MACSrcVendor`, `MACSrcDUID`

- [ ] **Step 1: Write the failing tests**

`internal/collector/registrar/registrar_test.go`:

```go
package registrar

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var ctx = context.Background()

type commitRecorder struct{ st *store.Store }

func (c commitRecorder) Record(ctx context.Context, ch store.Change) error { return c.st.Commit(ctx, ch) }

type env struct {
	t   *testing.T
	st  *store.Store
	r   *Registrar
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, now: t0}
	e.r = New(st, commitRecorder{st}, testPolicy(), []byte{0, 4, 1, 2, 3, 4}, 32473)
	e.r.Now = func() time.Time { return e.now }
	return e
}

func (e *env) events() []event.Event {
	e.t.Helper()
	evs, err := e.st.EventsAfter(ctx, 0, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]event.Event, len(evs))
	for i, se := range evs {
		out[i] = se.Event
	}
	return out
}

func (e *env) types() []string {
	var out []string
	for _, ev := range e.events() {
		out = append(out, ev.Type)
	}
	return out
}

func (e *env) binding(a netip.Addr) (store.Binding, bool) {
	b, ok, err := e.st.GetBinding(ctx, a)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, ok
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAddRepliesAndRecords(t *testing.T) {
	e := newEnv(t)
	req := mcastReq(inform(t, testAddr, testDUID, 7200), testAddr)
	reply := e.r.Handle(ctx, req)
	if reply == nil || reply.Type != dhcp6.MsgAddrRegReply || reply.XID != [3]byte{1, 2, 3} {
		t.Fatalf("reply = %+v", reply)
	}
	inIA, _ := req.Msg.Options.Get(dhcp6.OptIAAddr)
	outIA, _ := reply.Options.Get(dhcp6.OptIAAddr)
	if !bytes.Equal(inIA.Data, outIA.Data) {
		t.Fatal("IA Address not echoed verbatim")
	}
	if cid, ok := reply.Options.Get(dhcp6.OptClientID); !ok || !bytes.Equal(cid.Data, testDUID) {
		t.Fatal("Client ID not echoed")
	}
	if sid, ok := reply.Options.Get(dhcp6.OptServerID); !ok || !bytes.Equal(sid.Data, []byte{0, 4, 1, 2, 3, 4}) {
		t.Fatal("Server ID missing")
	}
	evs := e.events()
	if len(evs) != 1 {
		t.Fatalf("events = %v", e.types())
	}
	ev := evs[0]
	if ev.Type != event.RegAdd || ev.MAC != testMAC.String() || ev.MACSrc != MACSrcDUID || ev.Origin != OriginNative ||
		ev.Via != ViaMulticast || ev.Link != "eth0" || ev.DUIDType != "LL" || ev.Valid == nil || *ev.Valid != 7200 || ev.XID != "010203" {
		t.Fatalf("event = %+v", ev)
	}
	b, ok := e.binding(testAddr)
	if !ok || !b.ExpiresAt.Equal(t0.Add(7200*time.Second)) {
		t.Fatalf("binding = %+v %v", b, ok)
	}
}

func TestRefreshIsSilent(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.now = t0.Add(time.Hour)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	if got := e.types(); !equal(got, []string{event.RegAdd}) {
		t.Fatalf("events = %v", got)
	}
	b, _ := e.binding(testAddr)
	if !b.FirstSeen.Equal(t0) || !b.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("first=%v last=%v", b.FirstSeen, b.LastSeen)
	}
}

func TestMulticastAndUnicastCopiesDoNotChurn(t *testing.T) {
	e := newEnv(t)
	m := inform(t, testAddr, testDUID, 7200)
	e.r.Handle(ctx, mcastReq(m, testAddr))
	uni := mcastReq(m, testAddr)
	uni.Via = ViaUnicast
	if e.r.Handle(ctx, uni) == nil {
		t.Fatal("unicast copy got no reply")
	}
	if got := e.types(); !equal(got, []string{event.RegAdd}) {
		t.Fatalf("events = %v", got)
	}
}

func TestConflict(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, otherDUID, 7200), testAddr))
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegConflict || evs[1].PrevDUID != dhcp6.FormatHex(testDUID) {
		t.Fatalf("events = %+v", evs)
	}
	b, _ := e.binding(testAddr)
	if b.DUID != dhcp6.FormatHex(otherDUID) {
		t.Fatalf("binding DUID = %s", b.DUID)
	}
}

func TestShortenedLifetimeIsChange(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 86400), testAddr))
	e.now = t0.Add(time.Minute)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 600), testAddr))
	if got := e.types(); !equal(got, []string{event.RegAdd, event.RegChange}) {
		t.Fatalf("events = %v", got)
	}
}

func TestDereg(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.now = t0.Add(time.Minute)
	if e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 0), testAddr)) == nil {
		t.Fatal("dereg got no reply")
	}
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegDereg || evs[1].FirstSeen == nil || !evs[1].FirstSeen.Equal(t0) {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); ok {
		t.Fatal("binding survived dereg")
	}
}

func TestDeregForeignDUIDRejected(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr))
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, otherDUID, 0), testAddr))
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegReject || evs[1].Reason != ReasonDeregForeign {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); !ok {
		t.Fatal("foreign dereg removed the binding")
	}
}

func agentOpts(t *testing.T, pen uint32, mac string) []dhcp6.Option {
	t.Helper()
	vc, err := dhcp6.VendorClass{Enterprise: pen, Data: [][]byte{
		[]byte("ra-logger-agent/0.1"), []byte("os=darwin"), []byte("if=en0"), []byte("mac=" + mac),
	}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fqdn, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, "lab-mbp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return []dhcp6.Option{{Code: dhcp6.OptVendorClass, Data: vc}, {Code: dhcp6.OptClientFQDN, Data: fqdn}}
}

func TestAgentVendorAndFQDN(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 32473, "02:00:00:00:00:01")...), testAddr))
	ev := e.events()[0]
	if ev.Origin != OriginAgent || ev.MAC != "02:00:00:00:00:01" || ev.MACSrc != MACSrcVendor || ev.Host != "lab-mbp.example.com" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestWrongPENIsNative(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 9, "02:00:00:00:00:01")...), testAddr))
	ev := e.events()[0]
	if ev.Origin != OriginNative || ev.MACSrc != MACSrcDUID {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRelayCLLAOWins(t *testing.T) {
	e := newEnv(t)
	req := relayReq(inform(t, testAddr, testDUID, 7200, agentOpts(t, 32473, "02:00:00:00:00:01")...), testAddr)
	req.Relay.CLLAO = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	if e.r.Handle(ctx, req) == nil {
		t.Fatal("relayed registration dropped")
	}
	ev := e.events()[0]
	if ev.MAC != "02:aa:bb:cc:dd:ee" || ev.MACSrc != MACSrcCLLAO || ev.Link != "relay/"+relayLink.String() || ev.Via != ViaRelay {
		t.Fatalf("event = %+v", ev)
	}
}

func TestInvalidIsRejectedWithoutReply(t *testing.T) {
	e := newEnv(t)
	m := with(inform(t, testAddr, testDUID, 7200), dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 9}})
	if e.r.Handle(ctx, mcastReq(m, testAddr)) != nil {
		t.Fatal("invalid message got a reply")
	}
	evs := e.events()
	if len(evs) != 1 || evs[0].Type != event.RegReject || evs[0].Reason != ReasonServerID || evs[0].Addr != testAddr.String() {
		t.Fatalf("events = %+v", evs)
	}
	if e.r.Stats.Rejected.Load() != 1 {
		t.Fatal("Rejected counter not incremented")
	}
}

func TestRejectFloodIsBounded(t *testing.T) {
	e := newEnv(t)
	m := with(inform(t, testAddr, testDUID, 7200), dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}})
	for i := 0; i < 100; i++ {
		e.r.Handle(ctx, mcastReq(m, testAddr))
	}
	if n := len(e.events()); n != 20 {
		t.Fatalf("individual reject events = %d, want 20", n)
	}
	e.r.Sweep(ctx)
	evs := e.events()
	last := evs[len(evs)-1]
	if len(evs) != 21 || last.Reason != ReasonSuppressed || last.Count != 80 {
		t.Fatalf("summary = %+v (total %d)", last, len(evs))
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.r.Limits = NewLimiter(Limits{Global: Rate{1000, 1000}, PerPrefix: Rate{0.001, 2}, PerDUID: Rate{1000, 1000}})
	replies := 0
	for i := 0; i < 5; i++ {
		if e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 7200), testAddr)) != nil {
			replies++
		}
	}
	if replies != 2 || e.r.Stats.RateLimited.Load() != 3 {
		t.Fatalf("replies=%d limited=%d", replies, e.r.Stats.RateLimited.Load())
	}
	e.r.Sweep(ctx)
	evs := e.events()
	last := evs[len(evs)-1]
	if last.Reason != ReasonRateLimited || last.Count != 3 {
		t.Fatalf("summary = %+v", last)
	}
}

func TestSweepExpires(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, 10), testAddr))
	e.now = t0.Add(11 * time.Second)
	e.r.Sweep(ctx)
	evs := e.events()
	if len(evs) != 2 || evs[1].Type != event.RegExpire || evs[1].LastSeen == nil || !evs[1].LastSeen.Equal(t0) {
		t.Fatalf("events = %+v", evs)
	}
	if _, ok := e.binding(testAddr); ok {
		t.Fatal("expired binding not removed")
	}
}

func TestInfiniteLifetime(t *testing.T) {
	e := newEnv(t)
	e.r.Handle(ctx, mcastReq(inform(t, testAddr, testDUID, dhcp6.Infinity), testAddr))
	b, _ := e.binding(testAddr)
	if !b.ExpiresAt.Equal(t0.Add(InfiniteTTL)) {
		t.Fatalf("ExpiresAt = %v", b.ExpiresAt)
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/collector/registrar/`
Expected: FAIL with `undefined: New`, `undefined: MACSrcDUID`.

- [ ] **Step 3: Implement**

`internal/collector/registrar/registrar.go`:

```go
package registrar

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

const (
	// InfiniteTTL bounds bindings registered with an infinite valid lifetime.
	InfiniteTTL = 12 * time.Hour
	// AgentPrefix starts the first Vendor Class string sent by ra-logger agents.
	AgentPrefix = "ra-logger-agent/"

	OriginNative = "native"
	OriginAgent  = "agent"

	MACSrcCLLAO  = "cllao"
	MACSrcVendor = "vendor"
	MACSrcDUID   = "duid"
)

// BindingStore reads current bindings.
type BindingStore interface {
	GetBinding(ctx context.Context, addr netip.Addr) (store.Binding, bool, error)
	ExpiredBindings(ctx context.Context, now time.Time) ([]store.Binding, error)
}

// Recorder writes changes (satisfied by *recorder.Recorder).
type Recorder interface {
	Record(ctx context.Context, c store.Change) error
}

// Stats are cumulative counters, reported in the periodic stats event.
type Stats struct {
	Received, Replied, Rejected, RateLimited atomic.Uint64
}

// Snapshot returns the counters as a map.
func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"received":     s.Received.Load(),
		"replied":      s.Replied.Load(),
		"rejected":     s.Rejected.Load(),
		"rate_limited": s.RateLimited.Load(),
	}
}

// Registrar is the RFC 9686 server state machine.
type Registrar struct {
	Bindings BindingStore
	Rec      Recorder
	Policy   *PrefixPolicy
	Limits   *Limiter
	ServerID []byte
	PEN      uint32
	Now      func() time.Time
	Log      *slog.Logger
	Stats    Stats

	mu                sync.Mutex // serializes binding read-modify-write and expiry
	rejectLog         *rate.Limiter
	suppressed        atomic.Uint64
	limitedSinceSweep atomic.Uint64
}

// New returns a Registrar with default limits.
func New(b BindingStore, rec Recorder, pol *PrefixPolicy, serverID []byte, pen uint32) *Registrar {
	return &Registrar{
		Bindings: b, Rec: rec, Policy: pol, Limits: NewLimiter(DefaultLimits),
		ServerID: serverID, PEN: pen, Now: time.Now, Log: slog.Default(),
		rejectLog: rate.NewLimiter(1, 20), // at most 20 individual reject events per burst, 1/s sustained
	}
}

// Handle processes one request and returns the reply, or nil to drop it.
func (r *Registrar) Handle(ctx context.Context, req *Request) *dhcp6.Message {
	now := r.Now()
	r.Stats.Received.Add(1)
	if !r.Limits.AllowSource(limitKey(req), now) {
		r.limited()
		return nil
	}
	v, reason := Validate(req, r.Policy)
	if reason != "" {
		r.reject(ctx, req, reason, now)
		return nil
	}
	if !r.Limits.AllowDUID(v.DUID, now) {
		r.limited()
		return nil
	}
	r.mu.Lock()
	r.apply(ctx, req, v, now)
	r.mu.Unlock()
	r.Stats.Replied.Add(1)
	return r.reply(req.Msg, v.IARaw)
}

func limitKey(req *Request) netip.Addr {
	if req.Via == ViaRelay && req.Relay != nil {
		return req.Relay.PeerAddr
	}
	return req.Src.Addr()
}

func (r *Registrar) limited() {
	r.Stats.RateLimited.Add(1)
	r.limitedSinceSweep.Add(1)
}

func (r *Registrar) reply(in *dhcp6.Message, iaRaw []byte) *dhcp6.Message {
	cid, _ := in.Options.Get(dhcp6.OptClientID)
	return &dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: in.XID, Options: dhcp6.Options{
		{Code: dhcp6.OptClientID, Data: cid.Data},
		{Code: dhcp6.OptServerID, Data: r.ServerID},
		{Code: dhcp6.OptIAAddr, Data: iaRaw},
	}}
}

func (r *Registrar) apply(ctx context.Context, req *Request, v Valid, now time.Time) {
	b := r.bindingFor(req, v, now)
	old, found, err := r.Bindings.GetBinding(ctx, b.Addr)
	if err != nil {
		r.Log.Error("registrar: read binding", "addr", b.Addr, "err", err)
		found = false
	}
	ev := eventFor(event.RegAdd, b, now)
	ev.DUIDType = dhcp6.DUIDTypeName(v.DUID)
	ev.Preferred = event.U32(v.IA.Preferred)
	ev.Valid = event.U32(v.IA.Valid)
	ev.XID = hex.EncodeToString(req.Msg.XID[:])
	ev.Src = req.Src.Addr().String()

	var c store.Change
	switch {
	case v.IA.Valid == 0:
		if !found {
			return
		}
		if old.DUID != b.DUID {
			r.reject(ctx, req, ReasonDeregForeign, now)
			return
		}
		ev.Type = event.RegDereg
		ev.FirstSeen = event.TimePtr(old.FirstSeen)
		ev.LastSeen = event.TimePtr(now)
		c = store.Change{Events: []event.Event{ev}, Delete: []netip.Addr{b.Addr}}
	case !found:
		c = store.Change{Events: []event.Event{ev}, Put: []store.Binding{b}}
	case old.DUID != b.DUID:
		ev.Type = event.RegConflict
		ev.PrevDUID = old.DUID
		c = store.Change{Events: []event.Event{ev}, Put: []store.Binding{b}}
	default:
		b.FirstSeen = old.FirstSeen
		c.Put = []store.Binding{b}
		if materialChange(old, b) {
			ev.Type = event.RegChange
			c.Events = []event.Event{ev}
		}
	}
	if err := r.Rec.Record(ctx, c); err != nil {
		r.Log.Error("registrar: record", "addr", b.Addr, "err", err)
	}
}

func (r *Registrar) bindingFor(req *Request, v Valid, now time.Time) store.Binding {
	b := store.Binding{
		Addr: v.IA.Addr, DUID: dhcp6.FormatHex(v.DUID), Origin: OriginNative,
		Via: req.Via, Link: req.IfName, Preferred: v.IA.Preferred, Valid: v.IA.Valid,
		FirstSeen: now, LastSeen: now,
	}
	if req.Via == ViaRelay && req.Relay != nil {
		b.Link = "relay/" + req.Relay.LinkAddr.String()
	}
	if v.IA.Valid == dhcp6.Infinity {
		b.ExpiresAt = now.Add(InfiniteTTL)
	} else {
		b.ExpiresAt = now.Add(time.Duration(v.IA.Valid) * time.Second)
	}
	info, isAgent := r.agentInfo(req.Msg)
	if isAgent {
		b.Origin = OriginAgent
	}
	// MAC precedence: relay-inserted CLLAO (observed by network gear), then the
	// agent-reported current interface MAC, then the MAC embedded in the DUID.
	switch {
	case req.Relay != nil && len(req.Relay.CLLAO) == 6:
		b.MAC, b.MACSrc = req.Relay.CLLAO.String(), MACSrcCLLAO
	case isAgent && validMAC(info["mac"]) != "":
		b.MAC, b.MACSrc = validMAC(info["mac"]), MACSrcVendor
	default:
		if mac, ok := dhcp6.MACFromDUID(v.DUID); ok {
			b.MAC, b.MACSrc = mac.String(), MACSrcDUID
		}
	}
	if o, ok := req.Msg.Options.Get(dhcp6.OptClientFQDN); ok {
		if _, name, err := dhcp6.ParseFQDN(o.Data); err == nil {
			b.Host = name
		}
	}
	return b
}

// agentInfo returns key=value pairs from an ra-logger agent Vendor Class.
func (r *Registrar) agentInfo(m *dhcp6.Message) (map[string]string, bool) {
	opt, ok := m.Options.Get(dhcp6.OptVendorClass)
	if !ok {
		return nil, false
	}
	vc, err := dhcp6.ParseVendorClass(opt.Data)
	if err != nil || vc.Enterprise != r.PEN || len(vc.Data) == 0 || !bytes.HasPrefix(vc.Data[0], []byte(AgentPrefix)) {
		return nil, false
	}
	kv := map[string]string{"agent": string(vc.Data[0])}
	for _, d := range vc.Data[1:] {
		if k, val, ok := strings.Cut(string(d), "="); ok {
			kv[k] = val
		}
	}
	return kv, true
}

func validMAC(s string) string {
	if s == "" {
		return ""
	}
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return ""
	}
	return m.String()
}

// materialChange reports changes worth a reg.change event. A change of via
// alone is not one: topology C delivers each registration both ways.
func materialChange(old, nb store.Binding) bool {
	if old.MAC != nb.MAC || old.Link != nb.Link || old.Host != nb.Host || old.Origin != nb.Origin {
		return true
	}
	if nb.Valid != dhcp6.Infinity {
		slack := time.Duration(nb.Valid) * time.Second / 100
		if old.ExpiresAt.Sub(nb.ExpiresAt) > slack {
			return true // lifetime shortened, e.g. renumbering
		}
	}
	return false
}

func eventFor(typ string, b store.Binding, now time.Time) event.Event {
	e := event.New(typ, now)
	e.Addr = b.Addr.String()
	e.DUID = b.DUID
	e.MAC = b.MAC
	e.MACSrc = b.MACSrc
	e.Origin = b.Origin
	e.Host = b.Host
	e.Via = b.Via
	e.Link = b.Link
	return e
}

func (r *Registrar) reject(ctx context.Context, req *Request, reason string, now time.Time) {
	r.Stats.Rejected.Add(1)
	if !r.rejectLog.AllowN(now, 1) {
		r.suppressed.Add(1)
		return
	}
	e := event.New(event.RegReject, now)
	e.Reason = reason
	e.Via = req.Via
	e.Link = req.IfName
	e.Src = req.Src.Addr().String()
	if m := req.Msg; m != nil {
		e.XID = hex.EncodeToString(m.XID[:])
		if cid, ok := m.Options.Get(dhcp6.OptClientID); ok && len(cid.Data) <= MaxDUIDLen {
			e.DUID = dhcp6.FormatHex(cid.Data)
		}
		if o, ok := m.Options.Get(dhcp6.OptIAAddr); ok {
			if ia, err := dhcp6.ParseIAAddress(o.Data); err == nil {
				e.Addr = ia.Addr.String()
			}
		}
	}
	if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}}); err != nil {
		r.Log.Error("registrar: record reject", "err", err)
	}
}

// Sweep expires bindings past their lifetime and emits reject summaries.
// The collector calls it every minute.
func (r *Registrar) Sweep(ctx context.Context) {
	now := r.Now()
	r.mu.Lock()
	expired, err := r.Bindings.ExpiredBindings(ctx, now)
	if err != nil {
		r.Log.Error("registrar: list expired", "err", err)
	}
	for _, b := range expired {
		e := eventFor(event.RegExpire, b, now)
		if d, err := dhcp6.ParseHex(b.DUID); err == nil {
			e.DUIDType = dhcp6.DUIDTypeName(d)
		}
		e.FirstSeen = event.TimePtr(b.FirstSeen)
		e.LastSeen = event.TimePtr(b.LastSeen)
		if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}, Delete: []netip.Addr{b.Addr}}); err != nil {
			r.Log.Error("registrar: record expire", "addr", b.Addr, "err", err)
		}
	}
	r.mu.Unlock()
	r.summary(ctx, now, ReasonSuppressed, r.suppressed.Swap(0))
	r.summary(ctx, now, ReasonRateLimited, r.limitedSinceSweep.Swap(0))
}

func (r *Registrar) summary(ctx context.Context, now time.Time, reason string, n uint64) {
	if n == 0 {
		return
	}
	e := event.New(event.RegReject, now)
	e.Reason = reason
	e.Count = n
	if err := r.Rec.Record(ctx, store.Change{Events: []event.Event{e}}); err != nil {
		r.Log.Error("registrar: record summary", "err", err)
	}
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/collector/registrar/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/registrar
git commit -m "feat(registrar): bindings, ADDR-REG-REPLY, conflicts, dereg, expiry, bounded reject logging"
```

---

### Task 9: Responder (Information-Request → option 148)

**Files:**
- Create: `internal/collector/responder/responder.go`
- Test: `internal/collector/responder/responder_test.go`

**Interfaces:**
- Consumes: `dhcp6.Message`, option constants (Task 1)
- Produces: `type Responder struct{ServerID []byte}`; `(*Responder) Handle(*dhcp6.Message) *dhcp6.Message` (nil = no reply)

- [ ] **Step 1: Write the failing tests**

`internal/collector/responder/responder_test.go`:

```go
package responder

import (
	"bytes"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

var sid = []byte{0, 4, 1, 2, 3, 4}

func infoReq(opts ...dhcp6.Option) *dhcp6.Message {
	return &dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: [3]byte{9, 8, 7}, Options: opts}
}

var (
	cid      = dhcp6.Option{Code: dhcp6.OptClientID, Data: []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}}
	oro148   = dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 23, 0, 0x94}}
	oroOther = dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 23}}
)

func TestRepliesWithOption148(t *testing.T) {
	r := &Responder{ServerID: sid}
	reply := r.Handle(infoReq(cid, oro148))
	if reply == nil || reply.Type != dhcp6.MsgReply || reply.XID != [3]byte{9, 8, 7} {
		t.Fatalf("reply = %+v", reply)
	}
	if _, ok := reply.Options.Get(dhcp6.OptAddrRegEnable); !ok {
		t.Fatal("option 148 missing")
	}
	if s, ok := reply.Options.Get(dhcp6.OptServerID); !ok || !bytes.Equal(s.Data, sid) {
		t.Fatal("server id missing")
	}
	if c, ok := reply.Options.Get(dhcp6.OptClientID); !ok || !bytes.Equal(c.Data, cid.Data) {
		t.Fatal("client id not echoed")
	}
	if _, err := reply.Marshal(); err != nil {
		t.Fatal(err)
	}
}

func TestIgnores(t *testing.T) {
	r := &Responder{ServerID: sid}
	cases := map[string]*dhcp6.Message{
		"no oro":            infoReq(cid),
		"oro without 148":   infoReq(cid, oroOther),
		"odd-length oro":    infoReq(cid, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94, 0}[:1]}),
		"other server id":   infoReq(cid, oro148, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 9}}),
		"not info-request":  {Type: dhcp6.MsgAddrRegInform, Options: dhcp6.Options{cid, oro148}},
		"nil":               nil,
	}
	for name, m := range cases {
		if r.Handle(m) != nil {
			t.Errorf("%s: unexpected reply", name)
		}
	}
	if r.Handle(infoReq(cid, oro148, dhcp6.Option{Code: dhcp6.OptServerID, Data: sid})) == nil {
		t.Error("request addressed to our server id was ignored")
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/collector/responder/`
Expected: FAIL with `undefined: Responder`.

- [ ] **Step 3: Implement**

`internal/collector/responder/responder.go`:

```go
// Package responder answers DHCPv6 Information-Request with OPTION_ADDR_REG_ENABLE
// (148) on links that have no other DHCPv6 server, so RFC 9686 clients start registering.
package responder

import (
	"bytes"
	"encoding/binary"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// Responder builds Reply messages for Information-Request.
type Responder struct {
	ServerID []byte
}

// Handle returns a Reply, or nil when the request should be ignored: wrong
// type, addressed to another server, or not requesting option 148.
func (r *Responder) Handle(m *dhcp6.Message) *dhcp6.Message {
	if m == nil || m.Type != dhcp6.MsgInformationRequest {
		return nil
	}
	if s, ok := m.Options.Get(dhcp6.OptServerID); ok && !bytes.Equal(s.Data, r.ServerID) {
		return nil
	}
	oro, ok := m.Options.Get(dhcp6.OptORO)
	if !ok || !oroHas(oro.Data, dhcp6.OptAddrRegEnable) {
		return nil
	}
	opts := dhcp6.Options{{Code: dhcp6.OptServerID, Data: r.ServerID}}
	if c, ok := m.Options.Get(dhcp6.OptClientID); ok {
		opts = append(opts, c)
	}
	opts = append(opts, dhcp6.Option{Code: dhcp6.OptAddrRegEnable})
	return &dhcp6.Message{Type: dhcp6.MsgReply, XID: m.XID, Options: opts}
}

func oroHas(data []byte, code uint16) bool {
	for i := 0; i+1 < len(data); i += 2 {
		if binary.BigEndian.Uint16(data[i:]) == code {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/collector/responder/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/responder
git commit -m "feat(responder): answer Information-Request with option 148"
```

---

### Task 10: Listener (packet dispatch, relay unwrap/wrap, UDP socket)

**Files:**
- Create: `internal/collector/listener/dispatch.go`, `internal/collector/listener/socket.go` (`//go:build !windows`)
- Test: `internal/collector/listener/dispatch_test.go`, `internal/collector/listener/socket_test.go` (`//go:build !windows`)

**Interfaces:**
- Consumes: `registrar.Request`, `registrar.RelayInfo`, `registrar.Via*` (Task 7); `dhcp6.*` (Tasks 1–2)
- Produces:
  - `type Packet struct{Data []byte; Src netip.AddrPort; Dst netip.Addr; IfIndex int; IfName string}`
  - `type RegHandler interface{ Handle(ctx, *registrar.Request) *dhcp6.Message }`
  - `type InfoHandler interface{ Handle(*dhcp6.Message) *dhcp6.Message }`
  - `type Dispatcher struct{Reg RegHandler; Resp InfoHandler; ResponderIfaces map[int]bool; Dropped atomic.Uint64}`; `(*Dispatcher) Dispatch(ctx, Packet) []byte`
  - `const MaxRelayDepth = 8`
  - Socket: `Listen(ctx, addr string, ifaces []string, log *slog.Logger) (*Conn, error)`; `(*Conn) LocalAddr() net.Addr`; `(*Conn) Serve(ctx, *Dispatcher) error`; `(*Conn) Close() error`

- [ ] **Step 1: Add the dependency**

Run: `go get golang.org/x/net@latest`

- [ ] **Step 2: Write the failing tests**

`internal/collector/listener/dispatch_test.go`:

```go
package listener

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

var ctx = context.Background()

type fakeReg struct {
	mu    sync.Mutex
	reqs  []*registrar.Request
	reply bool
}

func (f *fakeReg) Handle(_ context.Context, r *registrar.Request) *dhcp6.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	if !f.reply {
		return nil
	}
	return &dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: r.Msg.XID}
}

func (f *fakeReg) last() *registrar.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		return nil
	}
	return f.reqs[len(f.reqs)-1]
}

type fakeResp struct{}

func (fakeResp) Handle(m *dhcp6.Message) *dhcp6.Message {
	return &dhcp6.Message{Type: dhcp6.MsgReply, XID: m.XID}
}

var (
	client = netip.MustParseAddr("2001:db8:10::5")
	linkA  = netip.MustParseAddr("2001:db8:10::1")
)

func informBytes(t *testing.T) []byte {
	t.Helper()
	m, err := dhcp6.NewAddrRegInform([3]byte{1, 2, 3}, []byte{0, 4, 1}, dhcp6.IAAddress{Addr: client, Valid: 60})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func relayForw(t *testing.T, inner []byte, link, peer netip.Addr, opts ...dhcp6.Option) []byte {
	t.Helper()
	rm := &dhcp6.RelayMessage{Type: dhcp6.MsgRelayForw, LinkAddr: link, PeerAddr: peer,
		Options: append(dhcp6.Options(opts), dhcp6.Option{Code: dhcp6.OptRelayMsg, Data: inner})}
	b, err := rm.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pkt(data []byte, dst netip.Addr) Packet {
	return Packet{Data: data, Src: netip.AddrPortFrom(client, 546), Dst: dst, IfIndex: 2, IfName: "eth0"}
}

func TestDispatchMulticastAndUnicast(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg}
	out := d.Dispatch(ctx, pkt(informBytes(t), dhcp6.AllRelayAgentsAndServers))
	if len(out) == 0 || out[0] != dhcp6.MsgAddrRegReply {
		t.Fatalf("out = %x", out)
	}
	if r := reg.last(); r.Via != registrar.ViaMulticast || r.IfName != "eth0" || r.Src.Addr() != client {
		t.Fatalf("req = %+v", r)
	}
	d.Dispatch(ctx, pkt(informBytes(t), linkA))
	if r := reg.last(); r.Via != registrar.ViaUnicast {
		t.Fatalf("via = %s", r.Via)
	}
}

func TestDispatchInfoRequest(t *testing.T) {
	ir, _ := (&dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: [3]byte{4, 4, 4}}).Marshal()
	d := &Dispatcher{Reg: &fakeReg{}, Resp: fakeResp{}, ResponderIfaces: map[int]bool{2: true}}
	if out := d.Dispatch(ctx, pkt(ir, dhcp6.AllRelayAgentsAndServers)); len(out) == 0 || out[0] != dhcp6.MsgReply {
		t.Fatalf("responder iface: out = %x", out)
	}
	other := pkt(ir, dhcp6.AllRelayAgentsAndServers)
	other.IfIndex = 3
	if out := d.Dispatch(ctx, other); out != nil {
		t.Fatal("replied on a non-responder interface")
	}
	if out := d.Dispatch(ctx, pkt(ir, linkA)); out != nil {
		t.Fatal("replied to a unicast Information-Request")
	}
	if out := (&Dispatcher{Reg: &fakeReg{}}).Dispatch(ctx, pkt(ir, dhcp6.AllRelayAgentsAndServers)); out != nil {
		t.Fatal("replied with responder disabled")
	}
}

func TestDispatchRelayUnwrapAndWrap(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg}
	ifid := dhcp6.Option{Code: dhcp6.OptInterfaceID, Data: []byte("eth7")}
	cllao := dhcp6.Option{Code: dhcp6.OptClientLinkLayerAddr, Data: []byte{0, 1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}}
	inner := relayForw(t, informBytes(t), linkA, client, ifid, cllao)
	outer := relayForw(t, inner, netip.MustParseAddr("2001:db8:20::1"), netip.MustParseAddr("2001:db8:ffff::2"))
	p := pkt(outer, netip.MustParseAddr("2001:db8:ffff::9"))
	p.Src = netip.AddrPortFrom(netip.MustParseAddr("2001:db8:ffff::2"), 547)

	out := d.Dispatch(ctx, p)
	r := reg.last()
	if r == nil || r.Via != registrar.ViaRelay || r.Relay.PeerAddr != client || r.Relay.LinkAddr != linkA ||
		string(r.Relay.InterfaceID) != "eth7" || r.Relay.CLLAO.String() != "02:aa:bb:cc:dd:ee" {
		t.Fatalf("req = %+v relay=%+v", r, r.Relay)
	}
	o, err := dhcp6.ParseRelay(out)
	if err != nil || o.Type != dhcp6.MsgRelayRepl || o.PeerAddr != netip.MustParseAddr("2001:db8:ffff::2") {
		t.Fatalf("outer reply %+v %v", o, err)
	}
	im, _ := o.Options.Get(dhcp6.OptRelayMsg)
	in, err := dhcp6.ParseRelay(im.Data)
	if err != nil || in.PeerAddr != client || in.LinkAddr != linkA {
		t.Fatalf("inner reply %+v %v", in, err)
	}
	if id, ok := in.Options.Get(dhcp6.OptInterfaceID); !ok || string(id.Data) != "eth7" {
		t.Fatal("interface-id not echoed")
	}
	cm, _ := in.Options.Get(dhcp6.OptRelayMsg)
	if len(cm.Data) == 0 || cm.Data[0] != dhcp6.MsgAddrRegReply {
		t.Fatalf("client reply = %x", cm.Data)
	}
}

func TestDispatchDropsHostileInput(t *testing.T) {
	reg := &fakeReg{reply: true}
	d := &Dispatcher{Reg: reg}
	deep := informBytes(t)
	for i := 0; i < MaxRelayDepth+1; i++ {
		deep = relayForw(t, deep, linkA, client)
	}
	sol, _ := (&dhcp6.Message{Type: 1}).Marshal()
	cases := map[string][]byte{
		"empty":             {},
		"garbage type":      {0xff, 1, 2, 3},
		"truncated inform":  {dhcp6.MsgAddrRegInform, 1},
		"bad option length": {dhcp6.MsgAddrRegInform, 1, 2, 3, 0, 1, 0xff, 0xff},
		"too deep":          deep,
		"relay of solicit":  relayForw(t, sol, linkA, client),
		"relay no msg":      func() []byte { b, _ := (&dhcp6.RelayMessage{Type: dhcp6.MsgRelayForw, LinkAddr: linkA, PeerAddr: client}).Marshal(); return b }(),
	}
	for name, data := range cases {
		before := d.Dropped.Load()
		if out := d.Dispatch(ctx, pkt(data, dhcp6.AllRelayAgentsAndServers)); out != nil {
			t.Errorf("%s: produced a reply", name)
		}
		if d.Dropped.Load() != before+1 {
			t.Errorf("%s: not counted as dropped", name)
		}
	}
	if len(reg.reqs) != 0 {
		t.Fatalf("registrar called for hostile input: %d", len(reg.reqs))
	}
}

func FuzzDispatch(f *testing.F) {
	f.Add([]byte{dhcp6.MsgAddrRegInform, 1, 2, 3})
	f.Add([]byte{dhcp6.MsgRelayForw})
	d := &Dispatcher{Reg: &fakeReg{reply: true}, Resp: fakeResp{}, ResponderIfaces: map[int]bool{2: true}}
	f.Fuzz(func(t *testing.T, b []byte) {
		d.Dispatch(ctx, pkt(b, dhcp6.AllRelayAgentsAndServers))
	})
}
```

`internal/collector/listener/socket_test.go`:

```go
//go:build !windows

package listener

import (
	"context"
	"log/slog"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func TestServeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := Listen(ctx, "[::1]:0", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	reg := &fakeReg{reply: true}
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, &Dispatcher{Reg: reg}) }()

	cl, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	m, _ := dhcp6.NewAddrRegInform([3]byte{7, 7, 7}, []byte{0, 4, 1}, dhcp6.IAAddress{Addr: netip.MustParseAddr("::1"), Valid: 60})
	b, _ := m.Marshal()
	if _, err := cl.WriteTo(b, c.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cl.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	reply, err := dhcp6.ParseMessage(buf[:n])
	if err != nil || reply.Type != dhcp6.MsgAddrRegReply || reply.XID != [3]byte{7, 7, 7} {
		t.Fatalf("reply = %+v %v", reply, err)
	}
	if r := reg.last(); r.Via != registrar.ViaUnicast || r.Src.Addr() != netip.MustParseAddr("::1") {
		t.Fatalf("req = %+v", r)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/collector/listener/`
Expected: FAIL with `undefined: Dispatcher`, `undefined: Listen`.

- [ ] **Step 4: Implement**

`internal/collector/listener/dispatch.go`:

```go
// Package listener receives DHCPv6 packets on UDP 547 and routes them to the
// registrar or responder, unwrapping and re-wrapping relay messages.
package listener

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// MaxRelayDepth is HOP_COUNT_LIMIT from RFC 8415 §7.6.
const MaxRelayDepth = 8

// Packet is one received datagram.
type Packet struct {
	Data    []byte
	Src     netip.AddrPort
	Dst     netip.Addr
	IfIndex int
	IfName  string
}

// RegHandler is satisfied by *registrar.Registrar.
type RegHandler interface {
	Handle(ctx context.Context, req *registrar.Request) *dhcp6.Message
}

// InfoHandler is satisfied by *responder.Responder.
type InfoHandler interface {
	Handle(m *dhcp6.Message) *dhcp6.Message
}

// Dispatcher routes packets. Resp may be nil to disable the responder.
type Dispatcher struct {
	Reg             RegHandler
	Resp            InfoHandler
	ResponderIfaces map[int]bool
	Log             *slog.Logger
	Dropped         atomic.Uint64
}

// Dispatch returns the bytes to send back to pkt.Src, or nil.
func (d *Dispatcher) Dispatch(ctx context.Context, pkt Packet) []byte {
	if len(pkt.Data) == 0 {
		return d.drop()
	}
	switch pkt.Data[0] {
	case dhcp6.MsgAddrRegInform:
		m, err := dhcp6.ParseMessage(pkt.Data)
		if err != nil {
			return d.drop()
		}
		via := registrar.ViaUnicast
		if pkt.Dst == dhcp6.AllRelayAgentsAndServers {
			via = registrar.ViaMulticast
		}
		return marshal(d.Reg.Handle(ctx, &registrar.Request{Msg: m, Src: pkt.Src, IfName: pkt.IfName, Via: via}))
	case dhcp6.MsgInformationRequest:
		if d.Resp == nil || !d.ResponderIfaces[pkt.IfIndex] || pkt.Dst != dhcp6.AllRelayAgentsAndServers {
			return d.drop()
		}
		m, err := dhcp6.ParseMessage(pkt.Data)
		if err != nil {
			return d.drop()
		}
		reply := d.Resp.Handle(m)
		if reply != nil && d.Log != nil {
			d.Log.Debug("responder: info.reply", "src", pkt.Src, "iface", pkt.IfName)
		}
		return marshal(reply)
	case dhcp6.MsgRelayForw:
		return d.relay(ctx, pkt)
	}
	return d.drop()
}

func (d *Dispatcher) relay(ctx context.Context, pkt Packet) []byte {
	var chain []*dhcp6.RelayMessage
	data := pkt.Data
	for len(data) > 0 && data[0] == dhcp6.MsgRelayForw {
		if len(chain) == MaxRelayDepth {
			return d.drop()
		}
		rm, err := dhcp6.ParseRelay(data)
		if err != nil {
			return d.drop()
		}
		inner, ok := rm.Options.Get(dhcp6.OptRelayMsg)
		if !ok {
			return d.drop()
		}
		chain = append(chain, rm)
		data = inner.Data
	}
	if len(data) == 0 || data[0] != dhcp6.MsgAddrRegInform {
		return d.drop()
	}
	m, err := dhcp6.ParseMessage(data)
	if err != nil {
		return d.drop()
	}
	in := chain[len(chain)-1]
	ri := &registrar.RelayInfo{LinkAddr: in.LinkAddr, PeerAddr: in.PeerAddr}
	if o, ok := in.Options.Get(dhcp6.OptInterfaceID); ok {
		ri.InterfaceID = o.Data
	}
	if o, ok := in.Options.Get(dhcp6.OptClientLinkLayerAddr); ok {
		if mac, ok := dhcp6.ParseCLLAO(o.Data); ok {
			ri.CLLAO = mac
		}
	}
	reply := d.Reg.Handle(ctx, &registrar.Request{Msg: m, Src: pkt.Src, IfName: pkt.IfName, Via: registrar.ViaRelay, Relay: ri})
	out := marshal(reply)
	if out == nil {
		return nil
	}
	for i := len(chain) - 1; i >= 0; i-- {
		rf := chain[i]
		var opts dhcp6.Options
		if o, ok := rf.Options.Get(dhcp6.OptInterfaceID); ok {
			opts = append(opts, o)
		}
		opts = append(opts, dhcp6.Option{Code: dhcp6.OptRelayMsg, Data: out})
		rr := &dhcp6.RelayMessage{Type: dhcp6.MsgRelayRepl, HopCount: rf.HopCount, LinkAddr: rf.LinkAddr, PeerAddr: rf.PeerAddr, Options: opts}
		if out, err = rr.Marshal(); err != nil {
			return d.drop()
		}
	}
	return out
}

func (d *Dispatcher) drop() []byte {
	d.Dropped.Add(1)
	return nil
}

func marshal(m *dhcp6.Message) []byte {
	if m == nil {
		return nil
	}
	b, err := m.Marshal()
	if err != nil {
		return nil
	}
	return b
}
```

`internal/collector/listener/socket.go`:

```go
//go:build !windows

package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv6"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

// Conn is the collector's UDP 547 socket.
type Conn struct {
	pc    net.PacketConn
	p     *ipv6.PacketConn
	log   *slog.Logger
	mu    sync.Mutex
	names map[int]string
}

// Listen binds addr (e.g. "[::]:547") and joins ff02::1:2 on each interface.
func Listen(ctx context.Context, addr string, ifaces []string, log *slog.Logger) (*Conn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp6", addr)
	if err != nil {
		return nil, fmt.Errorf("listener: %w", err)
	}
	p := ipv6.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		pc.Close()
		return nil, fmt.Errorf("listener: enable control messages: %w", err)
	}
	group := &net.UDPAddr{IP: net.IP(dhcp6.AllRelayAgentsAndServers.AsSlice())}
	for _, name := range ifaces {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("listener: %w", err)
		}
		if err := p.JoinGroup(ifi, group); err != nil {
			pc.Close()
			return nil, fmt.Errorf("listener: join ff02::1:2 on %s: %w", name, err)
		}
	}
	return &Conn{pc: pc, p: p, log: log, names: map[int]string{}}, nil
}

// LocalAddr returns the bound address.
func (c *Conn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

// Close closes the socket.
func (c *Conn) Close() error { return c.pc.Close() }

// Serve reads packets until ctx is cancelled, dispatching each and sending replies.
func (c *Conn) Serve(ctx context.Context, d *Dispatcher) error {
	stop := context.AfterFunc(ctx, func() { c.pc.Close() })
	defer stop()
	buf := make([]byte, 65535)
	for {
		n, cm, src, err := c.p.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			c.log.Warn("listener: read", "err", err)
			continue
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		pkt := Packet{Data: buf[:n], Src: netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())}
		if cm != nil {
			pkt.IfIndex = cm.IfIndex
			if dst, ok := netip.AddrFromSlice(cm.Dst); ok {
				pkt.Dst = dst.Unmap()
			}
			pkt.IfName = c.ifName(cm.IfIndex)
		}
		out := d.Dispatch(ctx, pkt)
		if out == nil {
			continue
		}
		if _, err := c.p.WriteTo(out, &ipv6.ControlMessage{IfIndex: pkt.IfIndex}, ua); err != nil {
			c.log.Debug("listener: write reply", "dst", ua, "err", err)
		}
	}
}

func (c *Conn) ifName(idx int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.names[idx]; ok {
		return n
	}
	ifi, err := net.InterfaceByIndex(idx)
	if err != nil {
		return ""
	}
	c.names[idx] = ifi.Name
	return ifi.Name
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go mod tidy && go test -race ./internal/collector/listener/ && go test -run='^$' -fuzz='^FuzzDispatch$' -fuzztime=10s ./internal/collector/listener/`
Expected: PASS. `TestServeRoundTrip` passes, or is skipped only if `[::1]` can't be bound.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/collector/listener
git commit -m "feat(listener): dispatch, relay unwrap/wrap, UDP 547 socket with ff02::1:2"
```

---

### Task 11: Config, on-link prefixes, server DUID

**Files:**
- Create: `internal/collector/config/config.go`, `internal/collector/netinfo/netinfo.go`, `internal/collector/serverid/serverid.go`
- Test: `internal/collector/config/config_test.go`, `internal/collector/netinfo/netinfo_test.go`, `internal/collector/serverid/serverid_test.go`

**Interfaces:**
- Consumes: `logger.ParseFacility` (Task 5); `dhcp6.NewDUIDUUID`, `dhcp6.ParseHex`, `dhcp6.FormatHex` (Task 2)
- Produces:
  - Config types: `config.Config{StateDir, ListenAddr string; RetentionDays int; Interfaces []Interface; Registrar Registrar; Vendor Vendor; Log Log}`; `config.Interface{Name string; Roles, Prefixes []string}` with `(Interface) Has(role string) bool`; `config.Registrar{AllowedPrefixes, RelayPrefixes []string}`; `config.Vendor{EnterpriseNumber uint32}`; `config.Log{Facility string; Outputs []Output}`; `config.Output{Type, Address, CAFile, ServerName string}`
  - Config functions and constants: `RoleListen, RoleResponder, RoleSniff`; `config.Load(path) (*Config, error)`; `(*Config) Validate() error`; `config.ParsePrefixes([]string) ([]netip.Prefix, error)`
  - netinfo: `netinfo.NewPrefixes(static map[string][]netip.Prefix, ttl time.Duration) *Prefixes`; `(*Prefixes) For(ifname string) []netip.Prefix`; `netinfo.InterfacePrefixes(name string) ([]netip.Prefix, error)`
  - serverid: `serverid.LoadOrCreate(dir string) ([]byte, error)`

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/BurntSushi/toml@latest`

- [ ] **Step 2: Write the failing tests**

`internal/collector/config/config_test.go`:

```go
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

func TestParsePrefixesMasks(t *testing.T) {
	p, err := ParsePrefixes([]string{"2001:db8:10::5/64"})
	if err != nil || p[0].String() != "2001:db8:10::/64" {
		t.Fatalf("got %v %v", p, err)
	}
}
```

`internal/collector/netinfo/netinfo_test.go`:

```go
package netinfo

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPrefixesMergeAndCache(t *testing.T) {
	static := map[string][]netip.Prefix{"eth0": {netip.MustParsePrefix("2001:db8:1::/64")}}
	p := NewPrefixes(static, 30*time.Second)
	calls := 0
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	p.lookup = func(string) ([]netip.Prefix, error) {
		calls++
		return []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/64")}, nil
	}
	if got := p.For("eth0"); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	p.For("eth0")
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1 within TTL", calls)
	}
	now = now.Add(31 * time.Second)
	p.For("eth0")
	if calls != 2 {
		t.Fatalf("lookup calls = %d, want 2 after TTL", calls)
	}
}

func TestPrefixesLookupErrorKeepsStatic(t *testing.T) {
	static := map[string][]netip.Prefix{"eth0": {netip.MustParsePrefix("2001:db8:1::/64")}}
	p := NewPrefixes(static, time.Second)
	p.lookup = func(string) ([]netip.Prefix, error) { return nil, errors.New("no such interface") }
	if got := p.For("eth0"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestInterfacePrefixesUnknown(t *testing.T) {
	if _, err := InterfacePrefixes("definitely-not-an-interface0"); err == nil {
		t.Fatal("expected error")
	}
}
```

`internal/collector/serverid/serverid_test.go`:

```go
package serverid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 18 || a[0] != 0 || a[1] != 4 {
		t.Fatalf("not a DUID-UUID: %x", a)
	}
	b, err := LoadOrCreate(dir)
	if err != nil || string(a) != string(b) {
		t.Fatalf("DUID changed across loads: %x vs %x (%v)", a, b, err)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("corrupt server-duid silently replaced")
	}
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/collector/config/ ./internal/collector/netinfo/ ./internal/collector/serverid/`
Expected: FAIL with `undefined: Load`, `undefined: NewPrefixes`, `undefined: LoadOrCreate`.

- [ ] **Step 4: Implement**

`internal/collector/config/config.go`:

```go
// Package config loads and validates the collector's TOML configuration.
package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
)

// Interface roles.
const (
	RoleListen    = "listen"
	RoleResponder = "responder"
	RoleSniff     = "sniff"
)

var (
	validRoles   = map[string]bool{RoleListen: true, RoleResponder: true, RoleSniff: true}
	validOutputs = map[string]bool{"unix": true, "tcp": true, "tls": true, "stdout": true}
)

type Config struct {
	StateDir      string      `toml:"state_dir"`
	ListenAddr    string      `toml:"listen_addr"`
	RetentionDays int         `toml:"retention_days"`
	Interfaces    []Interface `toml:"interface"`
	Registrar     Registrar   `toml:"registrar"`
	Vendor        Vendor      `toml:"vendor"`
	Log           Log         `toml:"log"`
}

type Interface struct {
	Name     string   `toml:"name"`
	Roles    []string `toml:"roles"`
	Prefixes []string `toml:"prefixes"`
}

// Has reports whether the interface has role.
func (i Interface) Has(role string) bool { return slices.Contains(i.Roles, role) }

type Registrar struct {
	AllowedPrefixes []string `toml:"allowed_prefixes"`
	RelayPrefixes   []string `toml:"relay_prefixes"`
}

type Vendor struct {
	EnterpriseNumber uint32 `toml:"enterprise_number"`
}

type Log struct {
	Facility string   `toml:"facility"`
	Outputs  []Output `toml:"output"`
}

type Output struct {
	Type       string `toml:"type"` // unix | tcp | tls | stdout
	Address    string `toml:"address"`
	CAFile     string `toml:"ca_file"`
	ServerName string `toml:"server_name"`
}

// Load reads, defaults and validates the file at path. Unknown keys are errors.
func Load(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/ra-logger"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "[::]:547"
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 400
	}
	if c.Vendor.EnterpriseNumber == 0 {
		c.Vendor.EnterpriseNumber = 32473 // RFC 5612 documentation PEN; replace before production
	}
	if c.Log.Facility == "" {
		c.Log.Facility = "local5"
	}
	if len(c.Log.Outputs) == 0 {
		c.Log.Outputs = []Output{{Type: "unix", Address: "/dev/log"}}
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for i, ifc := range c.Interfaces {
		if ifc.Name == "" {
			return fmt.Errorf("config: interface[%d]: name is required", i)
		}
		if seen[ifc.Name] {
			return fmt.Errorf("config: interface %s listed twice", ifc.Name)
		}
		seen[ifc.Name] = true
		for _, r := range ifc.Roles {
			if !validRoles[r] {
				return fmt.Errorf("config: interface %s: unknown role %q", ifc.Name, r)
			}
		}
		if ifc.Has(RoleResponder) && !ifc.Has(RoleListen) {
			return fmt.Errorf("config: interface %s: role %q requires %q", ifc.Name, RoleResponder, RoleListen)
		}
		if _, err := ParsePrefixes(ifc.Prefixes); err != nil {
			return fmt.Errorf("config: interface %s: %w", ifc.Name, err)
		}
	}
	if _, err := ParsePrefixes(c.Registrar.AllowedPrefixes); err != nil {
		return fmt.Errorf("config: registrar.allowed_prefixes: %w", err)
	}
	if _, err := ParsePrefixes(c.Registrar.RelayPrefixes); err != nil {
		return fmt.Errorf("config: registrar.relay_prefixes: %w", err)
	}
	if _, err := logger.ParseFacility(c.Log.Facility); err != nil {
		return fmt.Errorf("config: log.facility: %w", err)
	}
	for i, o := range c.Log.Outputs {
		if !validOutputs[o.Type] {
			return fmt.Errorf("config: log.output[%d]: unknown type %q", i, o.Type)
		}
		if o.Type != "stdout" && o.Address == "" {
			return fmt.Errorf("config: log.output[%d]: address is required for type %q", i, o.Type)
		}
	}
	if c.RetentionDays < 1 {
		return fmt.Errorf("config: retention_days must be at least 1")
	}
	return nil
}

// ParsePrefixes parses IPv6 prefixes and masks them to their network address.
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("%s is not an IPv6 prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
```

`internal/collector/netinfo/netinfo.go`:

```go
// Package netinfo reports the IPv6 prefixes configured on local interfaces.
package netinfo

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type cached struct {
	at  time.Time
	pfx []netip.Prefix
}

// Prefixes merges static per-interface prefixes with prefixes learned from
// the interface's addresses, refreshing learned ones after ttl.
type Prefixes struct {
	static map[string][]netip.Prefix
	ttl    time.Duration
	lookup func(string) ([]netip.Prefix, error)
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]cached
}

// NewPrefixes returns a Prefixes using InterfacePrefixes for learning.
func NewPrefixes(static map[string][]netip.Prefix, ttl time.Duration) *Prefixes {
	return &Prefixes{static: static, ttl: ttl, lookup: InterfacePrefixes, now: time.Now, cache: map[string]cached{}}
}

// For returns static plus learned prefixes for ifname.
func (p *Prefixes) For(ifname string) []netip.Prefix {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	c, ok := p.cache[ifname]
	if !ok || now.Sub(c.at) > p.ttl {
		learned, err := p.lookup(ifname)
		if err != nil {
			learned = nil
		}
		c = cached{at: now, pfx: learned}
		p.cache[ifname] = c
	}
	return append(slices.Clone(p.static[ifname]), c.pfx...)
}

// InterfacePrefixes returns the global/ULA IPv6 prefixes on interface name.
func InterfacePrefixes(name string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		ones, bits := ipn.Mask.Size()
		if !addr.Is6() || !addr.IsGlobalUnicast() || bits != 128 {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out, nil
}
```

`internal/collector/serverid/serverid.go`:

```go
// Package serverid persists the collector's DHCPv6 Server Identifier.
package serverid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

const fileName = "server-duid"

// LoadOrCreate returns the DUID stored in dir, creating a random DUID-UUID on
// first use. A corrupt file is an error rather than being silently replaced.
func LoadOrCreate(dir string) ([]byte, error) {
	path := filepath.Join(dir, fileName)
	b, err := os.ReadFile(path)
	if err == nil {
		d, perr := dhcp6.ParseHex(strings.TrimSpace(string(b)))
		if perr != nil || len(d) < 2 {
			return nil, fmt.Errorf("serverid: %s is corrupt; remove it to generate a new server DUID", path)
		}
		return d, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("serverid: %w", err)
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return nil, err
	}
	u[6] = (u[6] & 0x0f) | 0x40 // UUID version 4
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	d := dhcp6.NewDUIDUUID(u)
	tmp, err := os.CreateTemp(dir, ".server-duid-*")
	if err != nil {
		return nil, fmt.Errorf("serverid: %w", err)
	}
	if _, err := tmp.WriteString(dhcp6.FormatHex(d) + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("serverid: %w", err)
	}
	return d, nil
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go mod tidy && go test -race ./internal/collector/config/ ./internal/collector/netinfo/ ./internal/collector/serverid/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/collector/config internal/collector/netinfo internal/collector/serverid
git commit -m "feat(collector): TOML config, on-link prefix discovery, persistent server DUID"
```

---

### Task 12: Collector binary (`run`)

**Files:**
- Create: `cmd/collector/main.go`, `cmd/collector/run.go`
- Test: `cmd/collector/run_test.go`
- All three files start with `//go:build !windows`.

**Interfaces:**
- Consumes:
  - Task 11: `config.*`, `netinfo.NewPrefixes`, `serverid.LoadOrCreate`
  - Task 4: `store.Open`
  - Tasks 5–6: `logger.*` (sinks, Forwarder), `recorder.Recorder`
  - Tasks 8–10: `registrar.New`, `registrar.PrefixPolicy`, `responder.Responder`, `listener.Listen`, `listener.Dispatcher`
  - Task 3: `event.New`, `event.Stats`
- Produces:
  - `run(ctx, *config.Config, *slog.Logger, ready func(net.Addr)) error`
  - `buildSinks(config.Log, logger.Facility) ([]logger.Sink, []string, error)` (sinks plus matching cursor names)
  - `main()` subcommands `run`, `query` (Task 13), `version`
  - `var version = "dev"`

- [ ] **Step 1: Write the failing test**

`cmd/collector/run_test.go`:

```go
//go:build !windows

package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

func readFrame(r *bufio.Reader) (string, error) {
	n, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func TestRunRecordsAndForwards(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frames := make(chan string, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			f, err := readFrame(r)
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	dir := t.TempDir()
	cfg := &config.Config{
		StateDir: dir, ListenAddr: "[::1]:0", RetentionDays: 400,
		Vendor: config.Vendor{EnterpriseNumber: 32473},
		Log:    config.Log{Facility: "local5", Outputs: []config.Output{{Type: "tcp", Address: ln.Addr().String()}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a net.Addr) { ready <- a })
	}()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Skipf("collector could not start (no IPv6 loopback?): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not become ready")
	}

	// ::1 is not a global address, so this must be rejected with reason "scope".
	cl, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	m, _ := dhcp6.NewAddrRegInform([3]byte{5, 5, 5}, []byte{0, 4, 1, 2}, dhcp6.IAAddress{Addr: netip.MustParseAddr("::1"), Valid: 60})
	b, _ := m.Marshal()
	if _, err := cl.WriteTo(b, addr); err != nil {
		t.Fatal(err)
	}

	select {
	case f := <-frames:
		if !strings.Contains(f, `"event":"reg.reject"`) || !strings.Contains(f, `"reason":"scope"`) || !strings.Contains(f, " ra-logger ") {
			t.Fatalf("forwarded frame = %s", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event forwarded to the TCP syslog sink")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	ro, err := store.OpenReadOnly(filepath.Join(dir, "ra-logger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	evs, err := ro.EventsAfter(context.Background(), 0, 10)
	if err != nil || len(evs) == 0 || evs[0].Event.Type != event.RegReject {
		t.Fatalf("stored events = %+v %v", evs, err)
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./cmd/collector/`
Expected: FAIL with `undefined: run`.

- [ ] **Step 3: Implement**

`cmd/collector/main.go`:

```go
//go:build !windows

// Command collector is the ipv6-ra-logger RFC 9686 registration server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `usage: collector <command> [flags]

commands:
  run      run the collector (default config /etc/ra-logger/collector.toml)
  query    look up an address, MAC or DUID in the collector database
  version  print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "query":
		err = queryCmd(os.Args[2:], os.Stdout)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "collector:", err)
		os.Exit(1)
	}
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/ra-logger/collector.toml", "configuration file")
	debug := fs.Bool("debug", false, "enable debug logging")
	if err := fs.Parse(args); err != nil {
		return err
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, cfg, log, nil)
}
```

`cmd/collector/run.go`:

```go
//go:build !windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/config"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/listener"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/logger"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/netinfo"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/recorder"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/registrar"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/responder"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/serverid"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// run starts every collector component and blocks until ctx is cancelled.
// ready, if non-nil, receives the bound UDP address once listening.
func run(ctx context.Context, cfg *config.Config, log *slog.Logger, ready func(net.Addr)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.StateDir, "ra-logger.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	sid, err := serverid.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return err
	}
	fac, err := logger.ParseFacility(cfg.Log.Facility)
	if err != nil {
		return err
	}
	sinks, cursors, err := buildSinks(cfg.Log, fac)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range sinks {
			s.Close()
		}
	}()
	rec := &recorder.Recorder{Store: st, Fallback: sinks, Log: log}

	static := map[string][]netip.Prefix{}
	var listenIfaces []string
	respIfaces := map[int]bool{}
	for _, ifc := range cfg.Interfaces {
		pfx, err := config.ParsePrefixes(ifc.Prefixes)
		if err != nil {
			return err
		}
		static[ifc.Name] = pfx
		if ifc.Has(config.RoleListen) {
			listenIfaces = append(listenIfaces, ifc.Name)
		}
		if ifc.Has(config.RoleResponder) {
			ifi, err := net.InterfaceByName(ifc.Name)
			if err != nil {
				return err
			}
			respIfaces[ifi.Index] = true
		}
		if ifc.Has(config.RoleSniff) {
			log.Warn("role \"sniff\" is not implemented in this build; ignoring", "iface", ifc.Name)
		}
	}
	allowed, err := config.ParsePrefixes(cfg.Registrar.AllowedPrefixes)
	if err != nil {
		return err
	}
	relay, err := config.ParsePrefixes(cfg.Registrar.RelayPrefixes)
	if err != nil {
		return err
	}
	onLink := netinfo.NewPrefixes(static, 30*time.Second)
	reg := registrar.New(st, rec, &registrar.PrefixPolicy{OnLink: onLink.For, Relay: relay, Unicast: allowed}, sid, cfg.Vendor.EnterpriseNumber)
	reg.Log = log
	disp := &listener.Dispatcher{Reg: reg, Log: log}
	if len(respIfaces) > 0 {
		disp.Resp = &responder.Responder{ServerID: sid}
		disp.ResponderIfaces = respIfaces
	}

	conn, err := listener.Listen(ctx, cfg.ListenAddr, listenIfaces, log)
	if err != nil {
		return err
	}
	if ready != nil {
		ready(conn.LocalAddr())
	}

	var wg sync.WaitGroup
	for i, s := range sinks {
		f := &logger.Forwarder{Name: cursors[i], Src: st, Sink: s, Log: log}
		wg.Go(func() { f.Run(ctx) })
	}
	wg.Go(func() { periodic(ctx, time.Minute, func() { reg.Sweep(ctx) }) })
	wg.Go(func() {
		periodic(ctx, 24*time.Hour, func() {
			n, err := st.PurgeEventsBefore(ctx, time.Now().AddDate(0, 0, -cfg.RetentionDays))
			if err != nil {
				log.Error("retention sweep failed", "err", err)
				return
			}
			log.Info("retention sweep", "purged", n)
		})
	})
	wg.Go(func() {
		periodic(ctx, 15*time.Minute, func() {
			e := event.New(event.Stats, time.Now())
			e.Counters = reg.Stats.Snapshot()
			e.Counters["dropped"] = disp.Dropped.Load()
			_ = rec.Record(ctx, store.Change{Events: []event.Event{e}})
		})
	})

	log.Info("collector started", "listen", conn.LocalAddr().String(), "interfaces", listenIfaces, "version", version)
	err = conn.Serve(ctx, disp)
	cancel()
	wg.Wait()
	return err
}

// buildSinks returns one sink per output plus a stable cursor name for each.
func buildSinks(lc config.Log, fac logger.Facility) ([]logger.Sink, []string, error) {
	host, _ := os.Hostname()
	var sinks []logger.Sink
	var cursors []string
	for _, o := range lc.Outputs {
		var s logger.Sink
		switch o.Type {
		case "unix":
			s = logger.NewUnixSink(o.Address, fac)
		case "tcp":
			s = logger.NewTCPSink(o.Address, fac, host)
		case "tls":
			conf := &tls.Config{ServerName: o.ServerName, MinVersion: tls.VersionTLS12}
			if conf.ServerName == "" {
				h, _, err := net.SplitHostPort(o.Address)
				if err != nil {
					return nil, nil, fmt.Errorf("tls output %q: %w", o.Address, err)
				}
				conf.ServerName = h
			}
			if o.CAFile != "" {
				pem, err := os.ReadFile(o.CAFile)
				if err != nil {
					return nil, nil, err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return nil, nil, fmt.Errorf("tls output: no certificates in %s", o.CAFile)
				}
				conf.RootCAs = pool
			}
			s = logger.NewTLSSink(o.Address, conf, fac, host)
		case "stdout":
			s = logger.NewWriterSink("stdout", os.Stdout)
		default:
			return nil, nil, fmt.Errorf("unknown output type %q", o.Type)
		}
		sinks = append(sinks, s)
		cursors = append(cursors, o.Type+":"+o.Address)
	}
	return sinks, cursors, nil
}

func periodic(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
```

Also create a temporary `cmd/collector/query.go` so the package compiles. Task 13 replaces it completely:

```go
//go:build !windows

package main

import (
	"errors"
	"io"
)

func queryCmd(args []string, w io.Writer) error { return errors.New("query: implemented in Task 13") }
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go vet ./... && go test -race ./cmd/collector/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/collector
git commit -m "feat(collector): run command wiring store, forwarders, registrar, responder, listener"
```

---

### Task 13: Query (who held an address, when)

**Files:**
- Create: `internal/collector/query/query.go`
- Replace: `cmd/collector/query.go`
- Test: `internal/collector/query/query_test.go`, `cmd/collector/query_test.go` (`//go:build !windows`)

**Interfaces:**
- Consumes: `store.OpenReadOnly`, `EventsWhere`, `BindingsWhere`, `store.StoredEvent`, `store.Binding` (Task 4); `event.*` (Task 3); `dhcp6.ParseHex`, `dhcp6.FormatHex` (Task 2)
- Produces:
  - `query.Holder{DUID, MAC, Host string; Since time.Time; Evidence []store.StoredEvent}`
  - `query.HolderAt(events []store.StoredEvent, at time.Time) (Holder, bool)`
  - `queryCmd(args []string, w io.Writer) error` with flags `-db -addr -mac -duid -at -from -to -json`

- [ ] **Step 1: Write the failing tests**

`internal/collector/query/query_test.go`:

```go
package query

import (
	"testing"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func se(id int64, typ, duid, mac string, ts time.Time) store.StoredEvent {
	e := event.New(typ, ts)
	e.DUID, e.MAC = duid, mac
	return store.StoredEvent{ID: id, Event: e}
}

func TestHolderAt(t *testing.T) {
	evs := []store.StoredEvent{
		se(1, event.RegAdd, "A", "m1", t0),
		se(2, event.RegChange, "A", "m2", t0.Add(time.Hour)),
		se(3, event.RegConflict, "B", "m3", t0.Add(2*time.Hour)),
		se(4, event.RegExpire, "B", "m3", t0.Add(3*time.Hour)),
	}
	cases := []struct {
		at   time.Time
		held bool
		duid string
		mac  string
	}{
		{t0.Add(-time.Minute), false, "", ""},
		{t0.Add(30 * time.Minute), true, "A", "m1"},
		{t0.Add(90 * time.Minute), true, "A", "m2"},
		{t0.Add(150 * time.Minute), true, "B", "m3"},
		{t0.Add(4 * time.Hour), false, "B", "m3"},
	}
	for _, tc := range cases {
		h, held := HolderAt(evs, tc.at)
		if held != tc.held || (tc.duid != "" && (h.DUID != tc.duid || h.MAC != tc.mac)) {
			t.Errorf("at %v: held=%v holder=%+v", tc.at, held, h)
		}
	}
	h, _ := HolderAt(evs, t0.Add(90*time.Minute))
	if len(h.Evidence) != 2 || !h.Since.Equal(t0) {
		t.Errorf("evidence/since wrong: %+v", h)
	}
}
```

`cmd/collector/query_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/collector/query/ ./cmd/collector/`
Expected: FAIL with `undefined: HolderAt`, and `TestQueryCmd` fails with "implemented in Task 13".

- [ ] **Step 3: Implement**

`internal/collector/query/query.go`:

```go
// Package query answers forensic questions from stored events.
package query

import (
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

// Holder is who held an address at a point in time.
type Holder struct {
	DUID     string
	MAC      string
	Host     string
	Since    time.Time
	Evidence []store.StoredEvent
}

// HolderAt replays one address's events (ordered by time) up to at.
func HolderAt(events []store.StoredEvent, at time.Time) (Holder, bool) {
	var h Holder
	held := false
	for _, se := range events {
		e := se.Event
		if e.TS.After(at) {
			break
		}
		switch e.Type {
		case event.RegAdd, event.RegConflict:
			h = Holder{DUID: e.DUID, MAC: e.MAC, Host: e.Host, Since: e.TS, Evidence: []store.StoredEvent{se}}
			held = true
		case event.RegChange:
			if held && e.DUID == h.DUID {
				h.MAC, h.Host = e.MAC, e.Host
				h.Evidence = append(h.Evidence, se)
			}
		case event.RegDereg, event.RegExpire:
			if held && e.DUID == h.DUID {
				h.Evidence = append(h.Evidence, se)
				held = false
			}
		}
	}
	return h, held
}
```

`cmd/collector/query.go` (replaces the stub):

```go
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
	"text/tabwriter"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/collector/query"
	"github.com/buraglio/ipv6-ra-logger/internal/collector/store"
	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
	"github.com/buraglio/ipv6-ra-logger/internal/event"
)

type holderOut struct {
	At    time.Time `json:"at"`
	Held  bool      `json:"held"`
	DUID  string    `json:"duid,omitempty"`
	MAC   string    `json:"mac,omitempty"`
	Host  string    `json:"host,omitempty"`
	Since time.Time `json:"since,omitzero"`
}

type queryResult struct {
	Bindings []store.Binding `json:"bindings"`
	Events   []event.Event   `json:"events"`
	Holder   *holderOut      `json:"holder,omitempty"`
}

func queryCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	db := fs.String("db", "/var/lib/ra-logger/ra-logger.db", "collector database")
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
	res := queryResult{Bindings: bs, Events: make([]event.Event, len(evs))}
	for i, se := range evs {
		res.Events[i] = se.Event
	}
	if field == "addr" && !at.IsZero() {
		h, held := query.HolderAt(evs, at)
		res.Holder = &holderOut{At: at, Held: held, DUID: h.DUID, MAC: h.MAC, Host: h.Host, Since: h.Since}
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	return writeText(w, res)
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
			fmt.Fprintf(tw, "Holder at %s: duid=%s mac=%s host=%s since=%s\n", ts(h.At), h.DUID, dash(h.MAC), dash(h.Host), ts(h.Since))
		} else {
			fmt.Fprintf(tw, "No holder at %s\n", ts(h.At))
		}
	}
	return tw.Flush()
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/collector/query/ ./cmd/collector/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/query cmd/collector/query.go cmd/collector/query_test.go
git commit -m "feat(collector): query command with holder-at-time reconstruction"
```

---

### Task 14: `regsend` test sender

**Files:**
- Create: `cmd/regsend/build.go`, `cmd/regsend/main.go`
- Test: `cmd/regsend/build_test.go`

**Interfaces:**
- Consumes: `dhcp6.NewAddrRegInform`, `VendorClass`, `EncodeFQDN`, `NewDUIDLL`, `NewDUIDUUID`, `ParseHex`, `RandomXID`, `ParseMessage` (Tasks 1–2)
- Produces:
  - Command line: `regsend` with flags `-mode inform|info -iface -addr -ia-addr -to -port -sport -duid -valid -preferred -host -agent -pen -mutate -wait`
  - Exit codes: 0 = expected reply; 3 = no reply; 4 = unexpected reply; 1 = error; 2 = usage
  - `buildInform(params, [3]byte) (pkt, iaData []byte, err error)`; `buildInfoRequest(duid []byte, xid [3]byte) ([]byte, error)`; `checkReply(b []byte, wantType uint8, xid [3]byte, iaData []byte) (string, bool)`

- [ ] **Step 1: Write the failing tests**

`cmd/regsend/build_test.go`:

```go
package main

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func baseParams() params {
	a := netip.MustParseAddr("2001:db8:10::100")
	return params{Addr: a, IAAddr: a, DUID: []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}, Valid: 86400, Preferred: 14400, PEN: 32473, IfName: "veth-h"}
}

func TestBuildInformDefault(t *testing.T) {
	pkt, ia, err := buildInform(baseParams(), [3]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	m, err := dhcp6.ParseMessage(pkt)
	if err != nil || m.Type != dhcp6.MsgAddrRegInform || m.Options.Count(dhcp6.OptClientID) != 1 || m.Options.Count(dhcp6.OptIAAddr) != 1 {
		t.Fatalf("message %+v %v", m, err)
	}
	o, _ := m.Options.Get(dhcp6.OptIAAddr)
	if !bytes.Equal(o.Data, ia) {
		t.Fatal("returned iaData does not match the message")
	}
}

func TestBuildInformAgentAndHost(t *testing.T) {
	p := baseParams()
	p.Agent, p.Host, p.MAC = true, "h1.example.com", net.HardwareAddr{2, 0, 0, 0, 0, 1}
	pkt, _, err := buildInform(p, [3]byte{})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dhcp6.ParseMessage(pkt)
	vo, ok := m.Options.Get(dhcp6.OptVendorClass)
	if !ok {
		t.Fatal("vendor class missing")
	}
	vc, _ := dhcp6.ParseVendorClass(vo.Data)
	if vc.Enterprise != 32473 || !strings.HasPrefix(string(vc.Data[0]), "ra-logger-agent/") || string(vc.Data[len(vc.Data)-1]) != "mac=02:00:00:00:00:01" {
		t.Fatalf("vendor class %+v", vc)
	}
	if _, ok := m.Options.Get(dhcp6.OptClientFQDN); !ok {
		t.Fatal("fqdn missing")
	}
}

func TestMutations(t *testing.T) {
	check := map[string]func(*dhcp6.Message, error) bool{
		"no-client-id": func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptClientID) == 0 },
		"server-id":    func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptServerID) == 1 },
		"oro":          func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptORO) == 1 },
		"two-ia":       func(m *dhcp6.Message, err error) bool { return err == nil && m.Options.Count(dhcp6.OptIAAddr) == 2 },
		"truncate":     func(m *dhcp6.Message, err error) bool { return err != nil },
	}
	for name, ok := range check {
		p := baseParams()
		p.Mutate = name
		pkt, _, err := buildInform(p, [3]byte{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ok(dhcp6.ParseMessage(pkt)) {
			t.Errorf("%s: mutation not applied", name)
		}
	}
	p := baseParams()
	p.Mutate = "explode"
	if _, _, err := buildInform(p, [3]byte{}); err == nil {
		t.Error("unknown mutation accepted")
	}
}

func TestCheckReply(t *testing.T) {
	ia := []byte{1, 2, 3}
	good, _ := (&dhcp6.Message{Type: dhcp6.MsgAddrRegReply, XID: [3]byte{1, 1, 1}, Options: dhcp6.Options{{Code: dhcp6.OptIAAddr, Data: ia}}}).Marshal()
	if desc, ok := checkReply(good, dhcp6.MsgAddrRegReply, [3]byte{1, 1, 1}, ia); !ok || !strings.Contains(desc, "type=37") {
		t.Fatalf("good reply: %s %v", desc, ok)
	}
	if _, ok := checkReply(good, dhcp6.MsgAddrRegReply, [3]byte{9, 9, 9}, ia); ok {
		t.Fatal("xid mismatch accepted")
	}
	info, _ := (&dhcp6.Message{Type: dhcp6.MsgReply, Options: dhcp6.Options{{Code: dhcp6.OptAddrRegEnable}}}).Marshal()
	if desc, ok := checkReply(info, dhcp6.MsgReply, [3]byte{}, nil); !ok || !strings.Contains(desc, "addr_reg_enable=true") {
		t.Fatalf("info reply: %s %v", desc, ok)
	}
	if _, ok := checkReply([]byte{1}, dhcp6.MsgReply, [3]byte{}, nil); ok {
		t.Fatal("garbage accepted")
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./cmd/regsend/`
Expected: FAIL with `undefined: params`, `undefined: buildInform`.

- [ ] **Step 3: Implement**

`cmd/regsend/build.go`:

```go
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

type params struct {
	Addr, IAAddr     netip.Addr
	DUID             []byte
	Valid, Preferred uint32
	Host             string
	Agent            bool
	PEN              uint32
	IfName           string
	MAC              net.HardwareAddr
	Mutate           string
}

var mutations = []string{"no-client-id", "server-id", "oro", "two-ia", "truncate"}

// buildInform returns the encoded ADDR-REG-INFORM and its IA Address payload.
func buildInform(p params, xid [3]byte) ([]byte, []byte, error) {
	ia := dhcp6.IAAddress{Addr: p.IAAddr, Preferred: p.Preferred, Valid: p.Valid}
	iaData, err := ia.Marshal()
	if err != nil {
		return nil, nil, err
	}
	var extra []dhcp6.Option
	if p.Agent {
		data := [][]byte{[]byte("ra-logger-agent/regsend"), []byte("os=" + runtime.GOOS), []byte("if=" + p.IfName)}
		if len(p.MAC) > 0 {
			data = append(data, []byte("mac="+p.MAC.String()))
		}
		vc, err := dhcp6.VendorClass{Enterprise: p.PEN, Data: data}.Marshal()
		if err != nil {
			return nil, nil, err
		}
		extra = append(extra, dhcp6.Option{Code: dhcp6.OptVendorClass, Data: vc})
	}
	if p.Host != "" {
		f, err := dhcp6.EncodeFQDN(dhcp6.FQDNFlagN, p.Host)
		if err != nil {
			return nil, nil, err
		}
		extra = append(extra, dhcp6.Option{Code: dhcp6.OptClientFQDN, Data: f})
	}
	m, err := dhcp6.NewAddrRegInform(xid, p.DUID, ia, extra...)
	if err != nil {
		return nil, nil, err
	}
	switch p.Mutate {
	case "", "truncate":
	case "no-client-id":
		m.Options = m.Options[1:] // Client ID is always first
	case "server-id":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptServerID, Data: []byte{0, 4, 0xde, 0xad}})
	case "oro":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptORO, Data: []byte{0, 0x94}})
	case "two-ia":
		m.Options = append(m.Options, dhcp6.Option{Code: dhcp6.OptIAAddr, Data: iaData})
	default:
		return nil, nil, fmt.Errorf("unknown -mutate %q (valid: %s)", p.Mutate, strings.Join(mutations, ", "))
	}
	b, err := m.Marshal()
	if err != nil {
		return nil, nil, err
	}
	if p.Mutate == "truncate" {
		b = b[:len(b)-5]
	}
	return b, iaData, nil
}

// buildInfoRequest returns an Information-Request asking for option 148.
func buildInfoRequest(duid []byte, xid [3]byte) ([]byte, error) {
	m := &dhcp6.Message{Type: dhcp6.MsgInformationRequest, XID: xid, Options: dhcp6.Options{
		{Code: dhcp6.OptClientID, Data: duid},
		{Code: dhcp6.OptORO, Data: []byte{0, 0x94}},
	}}
	return m.Marshal()
}

// checkReply describes b and reports whether it is the expected reply.
func checkReply(b []byte, wantType uint8, xid [3]byte, iaData []byte) (string, bool) {
	m, err := dhcp6.ParseMessage(b)
	if err != nil {
		return fmt.Sprintf("unparseable reply: %v", err), false
	}
	desc := fmt.Sprintf("reply: type=%d xid=%x", m.Type, m.XID)
	ok := m.Type == wantType && m.XID == xid
	switch wantType {
	case dhcp6.MsgAddrRegReply:
		o, has := m.Options.Get(dhcp6.OptIAAddr)
		echo := has && bytes.Equal(o.Data, iaData)
		desc += fmt.Sprintf(" ia_echo=%t", echo)
		ok = ok && echo
	case dhcp6.MsgReply:
		_, has := m.Options.Get(dhcp6.OptAddrRegEnable)
		desc += fmt.Sprintf(" addr_reg_enable=%t", has)
		ok = ok && has
	}
	return desc, ok
}
```

`cmd/regsend/main.go`:

```go
// Command regsend sends RFC 9686 ADDR-REG-INFORM (or Information-Request)
// messages, valid or deliberately malformed, for testing collectors.
// It is a developer tool and is not shipped in releases.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/buraglio/ipv6-ra-logger/internal/dhcp6"
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("regsend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "inform", "inform (ADDR-REG-INFORM) or info (Information-Request for option 148)")
	iface := fs.String("iface", "", "interface for link-local destinations; also supplies the default DUID MAC")
	addrS := fs.String("addr", "", "address to register; also the UDP source (mode=inform)")
	iaS := fs.String("ia-addr", "", "IA address placed in the message (default: -addr)")
	toS := fs.String("to", "ff02::1:2", "destination address")
	port := fs.Int("port", dhcp6.ServerPort, "destination port")
	sport := fs.Int("sport", 0, "source port (0 = ephemeral; 546 needs privileges)")
	duidS := fs.String("duid", "", "client DUID in hex (default: DUID-LL from -iface MAC, else random DUID-UUID)")
	valid := fs.Uint64("valid", 86400, "valid lifetime (seconds)")
	pref := fs.Uint64("preferred", 14400, "preferred lifetime (seconds)")
	host := fs.String("host", "", "FQDN to include (option 39)")
	agent := fs.Bool("agent", false, "include the ra-logger agent Vendor Class")
	pen := fs.Uint64("pen", 32473, "Vendor Class enterprise number")
	mutate := fs.String("mutate", "", "malform the message: no-client-id | server-id | oro | two-ia | truncate")
	wait := fs.Duration("wait", 2*time.Second, "how long to wait for a reply")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usageErr := func(msg string) int { fmt.Fprintln(stderr, "regsend:", msg); return 2 }
	if *valid > math.MaxUint32 || *pref > math.MaxUint32 || *pen > math.MaxUint32 {
		return usageErr("-valid, -preferred and -pen must fit in 32 bits")
	}
	to, err := netip.ParseAddr(*toS)
	if err != nil {
		return usageErr("bad -to: " + err.Error())
	}
	zone := ""
	if to.IsLinkLocalMulticast() || to.IsLinkLocalUnicast() {
		if *iface == "" {
			return usageErr("-iface is required for a link-local destination")
		}
		zone = *iface
	}
	var mac net.HardwareAddr
	if *iface != "" {
		ifi, err := net.InterfaceByName(*iface)
		if err != nil {
			return usageErr(err.Error())
		}
		mac = ifi.HardwareAddr
	}
	duid, err := chooseDUID(*duidS, mac)
	if err != nil {
		return usageErr(err.Error())
	}
	xid, err := dhcp6.RandomXID()
	if err != nil {
		fmt.Fprintln(stderr, "regsend:", err)
		return 1
	}

	var pkt, iaData []byte
	var laddr *net.UDPAddr
	var wantType uint8
	switch *mode {
	case "inform":
		addr, err := netip.ParseAddr(*addrS)
		if err != nil {
			return usageErr("-addr is required in mode=inform: " + err.Error())
		}
		ia := addr
		if *iaS != "" {
			if ia, err = netip.ParseAddr(*iaS); err != nil {
				return usageErr("bad -ia-addr: " + err.Error())
			}
		}
		p := params{Addr: addr, IAAddr: ia, DUID: duid, Valid: uint32(*valid), Preferred: uint32(*pref),
			Host: *host, Agent: *agent, PEN: uint32(*pen), IfName: *iface, MAC: mac, Mutate: *mutate}
		if pkt, iaData, err = buildInform(p, xid); err != nil {
			return usageErr(err.Error())
		}
		laddr = &net.UDPAddr{IP: addr.AsSlice(), Port: *sport}
		wantType = dhcp6.MsgAddrRegReply
	case "info":
		if pkt, err = buildInfoRequest(duid, xid); err != nil {
			fmt.Fprintln(stderr, "regsend:", err)
			return 1
		}
		laddr = &net.UDPAddr{IP: net.IPv6unspecified, Port: *sport}
		wantType = dhcp6.MsgReply
	default:
		return usageErr("-mode must be inform or info")
	}

	conn, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		fmt.Fprintln(stderr, "regsend:", err)
		return 1
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: to.AsSlice(), Port: *port, Zone: zone}
	if _, err := conn.WriteToUDP(pkt, dst); err != nil {
		fmt.Fprintln(stderr, "regsend: send:", err)
		return 1
	}
	fmt.Fprintf(stdout, "sent: mode=%s xid=%x to=%s bytes=%d\n", *mode, xid, dst, len(pkt))
	_ = conn.SetReadDeadline(time.Now().Add(*wait))
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			fmt.Fprintln(stdout, "no reply")
			return 3
		}
		fmt.Fprintln(stderr, "regsend: receive:", err)
		return 1
	}
	desc, ok := checkReply(buf[:n], wantType, xid, iaData)
	fmt.Fprintln(stdout, desc)
	if !ok {
		return 4
	}
	return 0
}

func chooseDUID(hexDUID string, mac net.HardwareAddr) ([]byte, error) {
	if hexDUID != "" {
		return dhcp6.ParseHex(hexDUID)
	}
	if len(mac) == 6 {
		return dhcp6.NewDUIDLL(mac), nil
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return nil, err
	}
	return dhcp6.NewDUIDUUID(u), nil
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go vet ./cmd/regsend/ && go test -race ./cmd/regsend/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/regsend
git commit -m "feat(regsend): developer tool for valid and malformed registrations"
```

---

### Task 15: Packaging, Linux end-to-end test, CI job, README

**Files:**
- Create: `packaging/systemd/ra-logger-collector.service`, `packaging/systemd/ra-logger.sysusers`, `packaging/rsyslog/30-ra-logger.conf`, `packaging/collector.example.toml`
- Create: `internal/collector/config/example_test.go`
- Create: `test/e2e/e2e_linux_test.go` (`//go:build e2e && linux`)
- Modify: `.github/workflows/ci.yml` (add the `e2e-linux` job)
- Modify: `README.md` (read it first; replace the content)

**Interfaces:**
- Consumes: the `collector` binary (`run`, `query`), the `regsend` binary and its exit codes, `config.Load`

- [ ] **Step 1: Write the example config and the test that loads it**

`packaging/collector.example.toml`:

```toml
# ipv6-ra-logger collector configuration
state_dir      = "/var/lib/ra-logger"
listen_addr    = "[::]:547"
retention_days = 400

# One block per interface. Roles:
#   listen    - join ff02::1:2 and accept RFC 9686 registrations
#   responder - answer Information-Request with option 148 (only on links
#               with NO other DHCPv6 server; the router's RA needs the O flag)
#   sniff     - passive ND/RA sniffer (not implemented in this build)
[[interface]]
name  = "eth0"
roles = ["listen", "responder"]
# prefixes = ["2001:db8:10::/64"]   # optional; on-link prefixes are learned

[registrar]
allowed_prefixes = []   # required for direct unicast registrations; empty = deny
relay_prefixes   = []   # prefixes reachable through DHCPv6 relays

[vendor]
enterprise_number = 32473   # RFC 5612 documentation PEN - replace before production

[log]
facility = "local5"

[[log.output]]
type    = "unix"
address = "/dev/log"

# [[log.output]]
# type    = "tls"
# address = "rsyslog.example.net:6514"
# ca_file = "/etc/ra-logger/ca.pem"
```

`internal/collector/config/example_test.go`:

```go
package config

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "..", "packaging", "collector.example.toml"))
	if err != nil {
		t.Fatalf("shipped example config is invalid: %v", err)
	}
	if c.Vendor.EnterpriseNumber != 32473 || len(c.Interfaces) != 1 {
		t.Fatalf("unexpected example config: %+v", c)
	}
}
```

Run: `go test ./internal/collector/config/`
Expected: PASS.

- [ ] **Step 2: Write the systemd and rsyslog files**

`packaging/systemd/ra-logger-collector.service`:

```ini
[Unit]
Description=ipv6-ra-logger collector (RFC 9686 registration server)
Documentation=https://github.com/buraglio/ipv6-ra-logger
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ra-logger-collector run -config /etc/ra-logger/collector.toml
User=ra-logger
Group=ra-logger
StateDirectory=ra-logger
StateDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

`packaging/systemd/ra-logger.sysusers`:

```
u ra-logger - "ipv6-ra-logger" /var/lib/ra-logger
```

`packaging/rsyslog/30-ra-logger.conf`:

```
# /etc/rsyslog.d/30-ra-logger.conf
# Parses ra-logger's @cee: JSON and writes one JSON object per line.
module(load="mmjsonparse")

template(name="ra_logger_json" type="list") {
  property(name="$!all-json")
  constant(value="\n")
}

if $programname == "ra-logger" then {
  action(type="mmjsonparse" cookie="@cee:")
  if $parsesuccess == "OK" then {
    action(type="omfile" file="/var/log/ra-logger/events.json" template="ra_logger_json")
  }
  # Forward to a SIEM or central rsyslog over TLS:
  # action(type="omfwd" target="siem.example.net" port="6514" protocol="tcp"
  #        StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name")
  stop
}
```

If `rsyslogd` is installed locally, check the file with `rsyslogd -N1 -f packaging/rsyslog/30-ra-logger.conf`. Expected: no errors, apart from a possible warning that `/var/log/ra-logger` is missing. If rsyslogd isn't installed, skip this check and say so in the commit message.

- [ ] **Step 3: Write the end-to-end test**

`test/e2e/e2e_linux_test.go`:

```go
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

func startCollector(t *testing.T, state string) (*exec.Cmd, *lineLog) {
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
	stdout, stderr := &lineLog{}, &lineLog{}
	cmd := exec.Command("ip", "netns", "exec", "ral-c", filepath.Join(binDir, "collector"), "run", "-config", cfgPath)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	stderr.waitFor(t, 5*time.Second, "collector started")
	return cmd, stdout
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
	cmd, stdout := startCollector(t, state)

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
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		out := sh(t, filepath.Join(binDir, "collector"), "query", "-db", filepath.Join(state, "ra-logger.db"), "-addr", "2001:db8:10::100")
		if !strings.Contains(out, "reg.add") || !strings.Contains(out, "2001:db8:10::100") {
			t.Fatalf("query output:\n%s", out)
		}
	})
}
```

- [ ] **Step 4: Run the end-to-end test**

On a Linux machine or VM with root, run: `sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e`
Expected: PASS for all five subtests.

On macOS, run `go vet -tags e2e ./test/e2e` instead. It reports that build constraints exclude every file, which is expected. The test itself runs in CI (next step). Say in the commit message whether it was run locally.

- [ ] **Step 5: Add the CI job**

Append to `.github/workflows/ci.yml` under `jobs:`:

```yaml
  e2e-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - name: Build static binaries and the e2e test
        run: |
          mkdir -p bin
          CGO_ENABLED=0 go build -o bin/collector ./cmd/collector
          CGO_ENABLED=0 go build -o bin/regsend ./cmd/regsend
          go test -c -tags e2e -o bin/e2e.test ./test/e2e
      - name: Run end-to-end tests in network namespaces
        run: sudo RAL_BIN_DIR="$PWD/bin" ./bin/e2e.test -test.v
```

- [ ] **Step 6: Rewrite the README**

Read `README.md`, then replace its contents with:

````markdown
# ipv6-ra-logger

Forensic mapping of **DUID ↔ MAC ↔ IPv6 address** over time, built on
[RFC 9686](https://datatracker.ietf.org/doc/rfc9686/) (Registering
Self-Generated IPv6 Addresses Using DHCPv6), with rsyslog integration.

Design: [docs/superpowers/specs/2026-11-08-ipv6-ra-logger-design.md](docs/superpowers/specs/2026-11-08-ipv6-ra-logger-design.md)

## Status

| Component | State |
|---|---|
| `collector`: RFC 9686 server, option-148 responder, SQLite store, syslog forwarding, query | implemented |
| `agent`: cross-platform RFC 9686 client (macOS, Windows, Linux) | planned |
| ND/RA sniffer for hosts that can't run the agent | planned |
| Release packaging | planned |

## Build

```sh
CGO_ENABLED=0 go build -o bin/ra-logger-collector ./cmd/collector
CGO_ENABLED=0 go build -o bin/regsend ./cmd/regsend   # developer test tool
```

## Run the collector

1. Copy `packaging/collector.example.toml` to `/etc/ra-logger/collector.toml` and edit the interfaces.
2. Install `packaging/systemd/ra-logger.sysusers` to `/usr/lib/sysusers.d/`, then install `packaging/systemd/ra-logger-collector.service`.
3. Install `packaging/rsyslog/30-ra-logger.conf` to `/etc/rsyslog.d/`, then restart rsyslog.
4. If the link has no other DHCPv6 server, give the interface the `responder` role and **set the O flag in the router's RAs**. Native RFC 9686 clients only register after a DHCPv6 server returns option 148.

Look up an address:

```sh
ra-logger-collector query -addr 2001:db8:10::5 -at 2026-11-08T21:00:00Z
```

## Test

```sh
go test -race ./...                                        # unit tests (any OS)
sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e     # Linux network-namespace end-to-end test
```

## Vendor Class enterprise number

The agent identifies itself with a Vendor Class option (16). The default
enterprise number is **32473**, the RFC 5612 documentation PEN. Replace it with
a real [IANA PEN](https://pen.iana.org/pen/PenApplication.page) before production use.
````

- [ ] **Step 7: Full verification**

Run: `go vet ./... && go test -race ./... && CGO_ENABLED=0 go build ./...`
Expected: everything passes, and the static build succeeds.

- [ ] **Step 8: Commit**

```bash
git add packaging internal/collector/config/example_test.go test/e2e .github/workflows/ci.yml README.md
git commit -m "feat: systemd/rsyslog packaging, Linux netns end-to-end test, e2e CI job, README"
```
