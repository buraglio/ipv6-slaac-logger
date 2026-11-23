# ARP Sniffer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend sniff mode to capture ARP frames and record MAC→IPv4 sightings alongside existing MAC→IPv6 sightings, enabling complete L2/L3 forensic mapping on dual-stacked networks.

**Architecture:** Extend the existing BPF filter to also accept ethertype `0x0806`. Add a new `arpobserve.go` parser that emits the same `Observation` struct the ND path already uses, feeding into the existing `Tracker` and `sightings` table unchanged. Teach the Tracker to derive the event-type family (`nd` vs `arp`) from the observation `Kind` already stored on each entry, so `arp.new`, `arp.conflict`, and `arp.expire` are emitted instead of `nd.*` events for ARP observations.

**Tech Stack:** Go, `golang.org/x/net/bpf` (BPF assembler), `golang.org/x/sys/unix` (AF_PACKET), `net/netip` (IPv4 addresses already supported), Linux only (build tag `linux`).

**Spec:** `docs/superpowers/specs/2026-11-09-sniffer.md`

## Global Constraints

- Linux-only: all new ARP capture code carries the `//go:build linux` tag, matching `capture_linux.go`.
- No schema changes: `sightings.addr` is `TEXT`; IPv4 addresses stored as their canonical string (e.g. `"192.168.1.5"`). `netip.ParseAddr` accepts them in queries.
- ARP capture is **opt-out**: enabled by default when `roles = ["sniff"]`; suppressed by `log_arp = false` in `[sniffer]`.
- The `Tracker`'s `proxy_suspect` threshold and `idle_timeout` apply identically to IPv4 sightings.
- New counters must appear in `Counters()` and in the periodic `stats` event.
- Gratuitous ARP (op=request, sender IP == target IP) is recorded as `kind = "garp"`.
- ARP probes (sender IP == `0.0.0.0`) are dropped before reaching the Tracker.
- Non-IPv4-over-Ethernet ARP (hardware type ≠ 1, protocol type ≠ `0x0800`) is dropped.

## Review Focus

1. **VLAN-tagged ARP**: A SPAN carrying 802.1Q-tagged traffic must have both the untagged and tagged BPF paths accepting `0x0806`. A tagged ARP frame that falls through to `notARP` silently loses IPv4 sightings for that VLAN. → Covered by Task 1 filter tests with `vlans: []uint16{10}`.
2. **Proxy-ARP at the SPAN uplink**: A router answering for downstream hosts sends ARP replies with its own MAC for many IPs. The `proxy_suspect` threshold (default 32) suppresses events but continues recording sightings. The counter `arp_sightings` still increments. No special handling needed; covered by existing Tracker proxy logic.
3. **ARP for link-local IPv4 (169.254.x.x)**: APIPA addresses appear on the wire and should be recorded unless `log_arp_link_local = false` is added later. For now they are recorded — `quiet()` only checks IPv6 link-local. Covered by Task 2 observe test.
4. **IPv4 address string format in queries**: `query -addr 192.168.1.5` calls `netip.ParseAddr`, which returns a pure-IPv4 `netip.Addr`. The sightings table stores `"192.168.1.5"` (not `"::ffff:192.168.1.5"`). The `SightingsWhere` query compares `addr.String()` against the stored text — these must match. Covered by Task 4 store round-trip check.
5. **Counters naming in stats event**: `run.go` pulls named counters from `Tracker.Counters()` into the periodic stats log line. A counter added to `Counters()` but not referenced in `run.go`'s stats map is silently absent from syslog. The existing pattern hardcodes counter names; the new `arp_sightings` counter must be added explicitly. Covered by the existing `run_test.go` counter assertion list (Task 5).

---

### Task 1: Extend BPF filter to accept ARP frames

**Files:**
- Modify: `internal/collector/sniffer/filter.go`
- Modify: `internal/collector/sniffer/filter_test.go`

**Interfaces:**
- Produces: `Filter() ([]bpf.RawInstruction, error)` — unchanged signature; now also passes ARP frames.

- [ ] **Step 1: Add failing filter tests for ARP**

Add to the `tests` table in `TestFilterProgram`:

```go
{"arp reply untagged",    arpFrame(nil,      "aa:bb:cc:dd:ee:ff", "192.168.1.1"), true},
{"arp request untagged",  arpFrame(nil,      "aa:bb:cc:dd:ee:ff", "192.168.1.2"), true},
{"arp reply vlan 10",     arpFrame([]uint16{10}, "aa:bb:cc:dd:ee:ff", "192.168.1.1"), true},
{"arp non-ipv4 hw type",  arpFrameRaw(nil, 2, 0x0800), false}, // hardware type 2 = not Ethernet
```

Add helper `arpFrame(vlans []uint16, senderMAC, senderIP string) []byte` and `arpFrameRaw(vlans []uint16, hwType, protoType uint16) []byte` to `testutil_test.go`. An ARP frame is: dst MAC (6B) + src MAC (6B) + [optional VLAN tags] + ethertype `0x0806` (2B) + 28-byte ARP payload (htype=1, ptype=0x0800, hlen=6, plen=4, op=2, sender MAC, sender IP, target MAC, target IP).

- [ ] **Step 2: Run filter tests to confirm new cases fail**

```
go test ./internal/collector/sniffer/ -run TestFilterProgram -v
```
Expected: the four new sub-tests FAIL (ARP frames not accepted yet).

- [ ] **Step 3: Extend `Filter()` to accept ethertype `0x0806`**

Add `etherARP = 0x0806` constant. Restructure the BPF program so that after the initial ethertype load:
- If ethertype == `etherIPv6` → existing ICMPv6 path (untagged).
- If ethertype == `etherARP` → `RetConstant{acceptAll}`.
- If ethertype == `etherVLAN` → check inner ethertype:
  - If inner == `etherIPv6` → existing ICMPv6 path (tagged).
  - If inner == `etherARP` → `RetConstant{acceptAll}`.
- If ethertype == `etherQinQ` → same two-branch inner check.
- Otherwise → `RetConstant{0}`.

All existing ICMPv6 type-range checks (133–136) remain. Jump offsets must be recomputed after inserting the two ARP accept instructions.

- [ ] **Step 4: Run all filter tests**

```
go test ./internal/collector/sniffer/ -run TestFilterProgram -v
```
Expected: all existing and new sub-tests PASS.

- [ ] **Step 5: Commit**

```
git add internal/collector/sniffer/filter.go internal/collector/sniffer/filter_test.go internal/collector/sniffer/testutil_test.go
git commit -m "feat(sniffer): extend BPF filter to accept ARP frames (ethertype 0x0806)"
```

---

### Task 2: ARP frame parser

**Files:**
- Create: `internal/collector/sniffer/arpobserve.go` (`//go:build linux`)
- Create: `internal/collector/sniffer/arpobserve_test.go`

**Interfaces:**
- Produces: `ARPObservations(frame []byte, vlan uint16, link string) []Observation`
  - Returns one `Observation` or nil.
  - `Observation.Kind` is one of: `"arp-request"`, `"arp-reply"`, `"garp"`.
  - Uses existing `KindDAD`/`KindNS`/`KindNA`/`KindRS` pattern — add new constants in `observe.go`:
    ```go
    KindARPRequest = "arp-request"
    KindARPReply   = "arp-reply"
    KindGARP       = "garp"
    ```
- Consumes: `Observation` struct from `observe.go`.

- [ ] **Step 1: Write failing tests**

```go
func TestARPObservations(t *testing.T) {
    link := "eth0"
    mac  := "aa:bb:cc:dd:ee:ff"
    ip   := "192.168.1.5"

    // ARP reply → arp-reply observation
    obs := ARPObservations(arpFrame(nil, mac, ip), 0, link)  // use test helper from Task 1
    if len(obs) != 1 || obs[0].Kind != KindARPReply || obs[0].Addr.String() != ip {
        t.Fatalf("reply: %+v", obs)
    }
    // Gratuitous ARP (sender IP == target IP) → garp
    // ARP probe (sender IP 0.0.0.0) → nil
    // Non-IPv4-over-Ethernet (hwtype != 1) → nil
    // VLAN 10 ARP reply → obs[0].VLAN == 10
    // Frame too short → nil
}
```

Write all sub-cases. The `arpFrame` helper from Task 1 is reused here.

- [ ] **Step 2: Run to confirm failure**

```
go test ./internal/collector/sniffer/ -run TestARPObservations -v
```
Expected: FAIL (function undefined).

- [ ] **Step 3: Implement `ARPObservations`**

ARP payload offsets for an untagged frame (after ethertype at byte 12):
- Byte 14: hardware type high (expect 0x00)
- Byte 15: hardware type low (expect 0x01)
- Byte 16: protocol type high (expect 0x08)
- Byte 17: protocol type low (expect 0x00)
- Byte 20: op high (0x00)
- Byte 21: op low (0x01 = request, 0x02 = reply)
- Bytes 22–27: sender MAC
- Bytes 28–31: sender IP
- Bytes 32–37: target MAC
- Bytes 38–41: target IP

For VLAN-tagged frames, all offsets shift by 4 (one tag) or 8 (QinQ). The function receives the raw Ethernet frame; detect the tag depth from bytes 12–13 (ethertype field).

Logic:
1. Bounds-check: frame must be at least 42 bytes (untagged) or 46/50 for tagged.
2. Detect VLAN tags and compute payload offset.
3. Check hardware type == 1 and protocol type == 0x0800; return nil otherwise.
4. Extract op, sender MAC (6 bytes), sender IP (4 bytes).
5. If sender IP == `0.0.0.0`: return nil (ARP probe).
6. Determine kind: if sender IP == target IP → `KindGARP`; op==2 → `KindARPReply`; op==1 → `KindARPRequest`.
7. Return `[]Observation{{MAC: senderMAC, Addr: netip.AddrFrom4([4]byte{...}), Link: link, VLAN: vlan, Kind: kind}}`.

- [ ] **Step 4: Run all sniffer tests**

```
go test ./internal/collector/sniffer/ -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```
git add internal/collector/sniffer/arpobserve.go internal/collector/sniffer/arpobserve_test.go internal/collector/sniffer/observe.go
git commit -m "feat(sniffer): add ARP frame parser emitting arp-request/arp-reply/garp observations"
```

---

### Task 3: Tracker event-family routing

**Files:**
- Modify: `internal/collector/sniffer/tracker.go`
- Modify: `internal/event/event.go`
- Modify: `internal/collector/sniffer/tracker_test.go`

**Interfaces:**
- Consumes: `Observation.Kind` (already stored on `entry` via `store.Sighting.Kind`).
- Produces: `event.ARPNew`, `event.ARPConflict`, `event.ARPExpire` constants; `Tracker.Counters()["arp_sightings"]`.

- [ ] **Step 1: Add event constants and failing tracker test**

In `event.go` add:
```go
ARPNew      = "arp.new"
ARPConflict = "arp.conflict"
ARPExpire   = "arp.expire"
```
Add to `Severity()` switch:
```go
case ARPConflict:
    return SevNotice
// ARPNew and ARPExpire fall through to SevInfo
```

Add test in `tracker_test.go`:

```go
func TestTrackerARPEvents(t *testing.T) {
    // First observation for (mac, 192.168.1.5, eth0, 0) → arp.new
    // Second observation with different MAC → arp.conflict
    // After idle_timeout → arp.expire
    // All three recorded events must have Type matching arp.new/arp.conflict/arp.expire
}
```

Follow the existing tracker test helper pattern (fake `Recorder`, fake clock).

- [ ] **Step 2: Run to confirm failure**

```
go test ./internal/collector/sniffer/ -run TestTrackerARPEvents -v
```
Expected: FAIL (events have type `nd.new` etc.)

- [ ] **Step 3: Add `eventFamily` helper and wire into Tracker**

In `tracker.go` add:
```go
func eventFamily(kind string) string {
    if len(kind) >= 3 && kind[:3] == "arp" {
        return "arp"
    }
    return "nd"
}
```

Replace the three hardcoded event-type references:
- `event.NDNew` → `eventFamily(o.Kind) + ".new"`
- `event.NDConflict` → `eventFamily(prevKind) + ".conflict"` (use the new entry's kind)
- `event.NDExpire` → `eventFamily(e.Kind) + ".expire"`

Add `arp_sightings uint64` field alongside `sightings`. Increment it in `Observe()` when `eventFamily(o.Kind) == "arp"`. Expose in `Counters()`:
```go
"arp_sightings": t.arpSightings,
```

- [ ] **Step 4: Run all sniffer and event tests**

```
go test ./internal/collector/sniffer/ ./internal/event/ -v
```
Expected: all PASS, including pre-existing ND tracker tests.

- [ ] **Step 5: Commit**

```
git add internal/event/event.go internal/collector/sniffer/tracker.go internal/collector/sniffer/tracker_test.go
git commit -m "feat(sniffer): route ARP observations to arp.new/conflict/expire events via eventFamily"
```

---

### Task 4: Wire ARP into Sniffer dispatch and config

**Files:**
- Modify: `internal/collector/sniffer/run.go`
- Modify: `internal/collector/config/config.go`
- Modify: `packaging/collector.example.toml`
- Modify: `internal/collector/sniffer/run_test.go`

**Interfaces:**
- Consumes: `ARPObservations(frame []byte, vlan uint16, link string) []Observation` from Task 2.
- Consumes: `config.Sniffer.LogARP bool` (new field, default `true`).
- Consumes: `Tracker.Counters()["arp_sightings"]` from Task 3.

- [ ] **Step 1: Add `LogARP` to config and failing dispatch test**

In `config.go`, add `LogARP bool \`toml:"log_arp"\`` to `Sniffer` struct. In `applyDefaults()`, set `c.Sniffer.LogARP = true` if the key was not explicitly defined (use the existing `md.IsDefined` pattern for boolean defaults: check `md.IsDefined("sniffer", "log_arp")` and set `true` only when absent).

Add to `TrackerConfig`: `LogARP bool` (passed through from `config.Sniffer.LogARP`). In `Tracker.quiet()`:
```go
// existing: e.Addr.IsLinkLocalUnicast() && !t.cfg.LogLinkLocal
// add:
|| (eventFamily(e.Kind) == "arp" && !t.cfg.LogARP)
```

Add a test in `run_test.go` that verifies an ARP frame dispatched through `Sniffer.dispatch()` calls `Tracker.Observe()` with an ARP observation (Kind == `"arp-reply"`). Use the `arpFrame` test helper.

Also add a store round-trip check: commit a sighting with `Addr = netip.MustParseAddr("192.168.1.5")`, then call `SightingsWhere(ctx, "addr", "192.168.1.5")` and confirm one result. This pins Task 4's Review Focus item 4.

- [ ] **Step 2: Run to confirm failure**

```
go test ./internal/collector/sniffer/ ./internal/collector/store/ -run "TestDispatch|TestSightings" -v
```
Expected: FAIL on new test cases.

- [ ] **Step 3: Implement dispatch routing**

In `Sniffer.dispatch()`, detect ARP before calling `nd.Parse`. Minimal detection: check `len(frame) >= 14` and bytes 12–13:

```go
func etherType(frame []byte) uint16 {
    if len(frame) < 14 {
        return 0
    }
    et := uint16(frame[12])<<8 | uint16(frame[13])
    if et == 0x8100 || et == 0x88a8 {
        if len(frame) >= 18 {
            return uint16(frame[16])<<8 | uint16(frame[17])
        }
        return 0
    }
    return et
}
```

In `dispatch()`, before `nd.Parse`:
```go
if etherType(frame) == 0x0806 {
    if s.Tracker != nil {
        for _, o := range ARPObservations(frame, vlan, s.Link) {
            s.Tracker.Observe(ctx, o)
        }
    }
    return
}
```

Add `LogARP: cfg.Sniffer.LogARP` where `TrackerConfig` is built in `cmd/collector/run.go`.

- [ ] **Step 4: Document `log_arp` in example config**

In `packaging/collector.example.toml`, under `[sniffer]`, add:
```toml
# log_arp = true    # false: ARP (MAC→IPv4) sightings go to the database only, with no arp.* events.
```

- [ ] **Step 5: Run all affected tests**

```
go test ./internal/collector/sniffer/ ./internal/collector/store/ ./internal/collector/config/ -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```
git add internal/collector/sniffer/run.go internal/collector/config/config.go packaging/collector.example.toml internal/collector/sniffer/run_test.go
git commit -m "feat(sniffer): wire ARP dispatch, add log_arp config option (default true)"
```

---

### Task 5: Stats counter and query integration

**Files:**
- Modify: `cmd/collector/run.go`
- Modify: `cmd/collector/run_test.go`

**Interfaces:**
- Consumes: `Tracker.Counters()["arp_sightings"]` from Task 3.

- [ ] **Step 1: Add `arp_sightings` to the stats counter assertion**

In `run_test.go`, the existing test asserts that specific counter keys appear in the stats event. Add `"arp_sightings"` to that list. This test should currently FAIL because `run.go` does not yet pass `arp_sightings` to the stats event.

- [ ] **Step 2: Run to confirm failure**

```
go test ./cmd/collector/ -run TestStats -v
```

- [ ] **Step 3: Add `arp_sightings` to `run.go` stats map**

Find the section in `run.go` that builds the stats counters map from `tracker.Counters()` and passes them into the `stats` event. Add `"arp_sightings"` alongside the existing `"nd_sightings"` entry.

- [ ] **Step 4: Run full test suite**

```
go test ./... 2>&1 | tail -20
```
Expected: all packages PASS.

- [ ] **Step 5: Final commit**

```
git add cmd/collector/run.go cmd/collector/run_test.go
git commit -m "feat(sniffer): expose arp_sightings counter in periodic stats event"
```
