# ipv6-ra-logger — Design Spec

- **Date:** 2026-11-08
- **Status:** Draft, awaiting review
- **Language:** Go (pure Go, `CGO_ENABLED=0` for all release builds)

## 1. Intent

### Goal

Produce forensic records that map **DUID ↔ MAC ↔ IPv6 address over time** for every host on a network, including hosts that use SLAAC and hosts with no DHCPv6 at all.

### What it must do

1. **Support RFC 9686** (Registering Self-Generated IPv6 Addresses Using DHCPv6) wherever the conditions exist. Native clients (Android, a future systemd-networkd) register with our collector as they would with any RFC 9686 server.
2. **Cover hosts that don't support RFC 9686:**
   - A small cross-platform **agent** (macOS, Windows, Linux) acts as a user-space RFC 9686 client.
   - A passive **sniffer** covers devices that can't run the agent (IoT, printers). Those get MAC↔address only, with no DUID.
3. **Be lightweight, secure and daemon-friendly.** Logs integrate with **rsyslog**.

### Success criterion

For any IPv6 address seen during a time window, an operator can answer: which DUID, MAC(s) and hostname held it, from when to when, and what evidence each claim rests on.

### Existing work (surveyed 2026-11-08)

| Project | Status |
|---|---|
| **Kea DHCPv6** | Implements the RFC 9686 server side since 2.7.7. It stores "registered" leases. Since 3.1.4 `allow-address-registration` turns the feature on or off; it is on by default. Kea accepts an Option Request in ADDR-REG-INFORM and does not check delegated prefixes. |
| **systemd-networkd** | Client support is in PR #43323, which is open and marked needs-rework. Off by default. |
| **Android** | Rollout announced September 2025. Not confirmed. |
| dnsmasq, odhcpd/odhcp6c, ISC dhcpd, dhcpcd, NetworkManager, Windows, macOS | No known support. |

None of these combines an RFC 9686 server, a cross-platform client agent, ND sniffing and syslog-oriented forensic output. This project fills that gap. Kea remains a valid interop target and an alternative server where it is already deployed.

## 2. Architecture

```
  Native RFC 9686 clients ─┐
  Agents (mac/win/linux) ──┼── multicast ff02::1:2:547 ──┐
                           ├── unicast collector:547 ────┼──> collector ──> SQLite (truth) ──> syslog/rsyslog
  Remote links ── relay ───┴── Relay-Forward ────────────┘        ^
  All hosts (incl. IoT) ── ND/RA on the wire ── SPAN/trunk ── sniffer
```

There is one Go module that builds two shipped binaries:

- **`agent`:** a user-space RFC 9686 client. Runs on Linux, macOS and Windows.
- **`collector`:** the RFC 9686 server plus a stateless responder, ND/RA sniffer, store, logger and query CLI. Linux only in v1.

A developer-only binary, **`regsend`**, crafts valid and malformed registrations for testing. It is not shipped.

### Topology

The topology is **"both" (option C)**:
- The agent sends link-local multicast as the RFC specifies.
- It also sends unicast to a configured collector when one is set.
- The collector accepts direct multicast, direct unicast and relayed messages.

## 3. Data model and record format

### 3.1 Events

Everything the system learns becomes an event.

| Source | Event types |
|---|---|
| Registrar | `reg.add`, `reg.change` (lifetime changed by more than 1%, or the address moved to a new link), `reg.dereg`, `reg.expire`, `reg.conflict` (the address now belongs to a different DUID), `reg.reject` (failed validation or rate limit; rate-limit rejects are summarized at most once per minute) |
| Sniffer | `nd.new`, `nd.expire` (not seen for the configured idle time, default 24 h), `nd.conflict` (the address now belongs to a different MAC) |
| RA monitor | `ra.seen` (new combination of router, prefix and flags), `ra.change` (flags or prefixes changed) |
| Responder | `info.reply`: debug level only |
| System | `stats` (every 15 min), `store.error`, `duid.regenerated` (agent side, logged locally) |

Refreshes and repeat sightings update `last_seen` in the database only. They do **not** produce syslog lines.

### 3.2 Record shape

Each record is JSON, emitted with an `@cee:` prefix so rsyslog's `mmjsonparse` can parse it:

```json
{"ts":"2026-11-08T21:14:03.412Z","event":"reg.add","addr":"2001:db8:10::5c1e:9aff:fe3b:21aa",
 "duid":"00:03:00:01:5c:1e:9a:3b:21:aa","duid_type":"LL","mac":"5c:1e:9a:3b:21:aa",
 "mac_src":"duid","origin":"agent","host":"lab-mbp","via":"multicast","link":"en0/2001:db8:10::/64",
 "preferred_lft":14400,"valid_lft":86400,"xid":"a1b2c3"}
```

| Field | Values |
|---|---|
| `mac_src` | `duid` (from a DUID-LL/LLT), `cllao` (relay option 79), `l2` (Ethernet source on the collector's link), `nd` (matched from a sniffer sighting), `vendor` (agent-reported in Vendor Class) |
| `origin` | `native`, `agent`, `sniffer`. **Advisory**: the agent marks itself with a Vendor Class option, which anyone can spoof. |
| `via` | `multicast`, `unicast`, `relay`, `sniff` |
| `host` | From the FQDN option (39) when present |

The fields present depend on the event type. Sniffer events carry `mac`, `addr`, `link`, `vlan` and the signal `kind` (`dad`, `ns`, `na`, `rs`). RA events carry the router MAC and link-local address, the M/O flags, prefixes and router lifetime.

### 3.3 Correlation and retention

- The `hosts` view joins `bindings` and `sightings` on address and MAC.
- `collector query --addr|--mac|--duid [--at T | --from T --to T] [--json]` returns the DUID, MACs, hostname, time window and evidence (source events).
- SQLite retention is configurable and defaults to **400 days**. syslog retention is left to rsyslog.

### 3.4 Scope decisions

- **All** addresses are registered and logged, **including temporary/privacy addresses**.
- Vendor Class (option 16) uses enterprise number **32473** (the RFC 5612 documentation PEN) as a **configurable placeholder**. It must be replaced with a real IANA PEN before production use.

## 4. Agent

### 4.1 Finding addresses

Each OS has its own implementation behind one Go interface. It returns `{addr, ifname, ifindex, origin, preferred, valid, state}` and sends change events.

| OS | Listing and origin | Change notification |
|---|---|---|
| Linux | netlink `RTM_GETADDR`. `IFA_PROTO` (kernel ≥5.18, `kernel_ra` = SLAAC), `IFA_F_TEMPORARY` and `IFA_F_PERMANENT`. On older kernels, a /128 with finite lifetimes is treated as DHCPv6. | netlink address multicast group |
| macOS | `SIOCGIFAFLAG_IN6` (`AUTOCONF`, `TEMPORARY`, `DYNAMIC` = DHCPv6, `TENTATIVE`, `DUPLICATED`) and `SIOCGIFALIFETIME_IN6`, via `x/sys/unix`, no cgo | `PF_ROUTE` socket (`RTM_NEWADDR`, `RTM_DELADDR`) |
| Windows | `GetAdaptersAddresses`: `PrefixOrigin`, `SuffixOrigin`, lifetimes, `DadState` | `NotifyUnicastIpAddressChange` |

A full re-scan runs every 5 minutes as a safety net. If notifications fail, the agent falls back to polling.

- **Registered:** global-scope addresses (ULA included) with origin SLAAC, temporary or static, and duplicate address detection complete.
- **Excluded:** DHCPv6-assigned, link-local, loopback, tentative and duplicate addresses.
- Interfaces can be filtered with include and exclude glob patterns.

### 4.2 DUID

The agent chooses its DUID in this order:
1. A DUID set in the config.
2. The OS's own DUID, so records correlate with DHCPv6 server logs:
   - Windows: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Dhcpv6DUID`
   - macOS: `/var/db/dhcpclient/DUID_IA.plist`
   - Linux: dhclient or NetworkManager lease files, or systemd-networkd's machine-id-derived DUID
3. A generated **DUID-LLT** from the first hardware MAC, saved in the agent's state file.

The DUID must stay stable across MAC randomization and restarts. If the state file is corrupt, it is backed up before any regeneration, and the regeneration is logged loudly.

The **Vendor Class (16)** data strings are:
- `ra-logger-agent/<version>`
- `os=<goos>`
- `if=<ifname>`
- `mac=<current interface MAC>`

The FQDN option (39) carries the hostname.

### 4.3 Sending

- **One message per address.** Each ADDR-REG-INFORM carries a Client ID, exactly one IA Address, Vendor Class and FQDN. It never carries a Server ID or an Option Request. The UDP source is the address being registered.
- **Multicast** goes to `ff02::1:2:547` on that address's interface. It is enabled on a link when one of these is true:
  - (a) the agent's own Information-Request (asking for option 148) gets a reply that includes option 148, or
  - (b) `multicast = "always"` is set.

  The agent deliberately does **not** check RA M/O flags, because they can't be read portably.
- **Unicast** to each configured collector happens always, whatever discovery found.
- **Timers:**
  - Retransmit: initial timeout 1 s, maximum 3 tries, same transaction ID, lifetimes updated on each try.
  - Refresh at `min(0.8 × valid × rand[0.9, 1.1], heartbeat)`, with a new transaction ID each time.
  - Static or infinite-lifetime addresses refresh every 4 h, capped by the heartbeat.
  - A lifetime change of more than 1% triggers a reschedule.
  - **The heartbeat defaults to 1 h.** This is a deliberate departure from the RFC: it bounds forensic uncertainty about when an address stopped being used.
- **Source port:** the agent tries to bind 546 with address/port reuse, then falls back to a random port. A missing reply only causes retransmits.
- **No de-registration in v1.** This is a deliberate departure from the RFC:
  - Once the OS reports an address removed, it can't be used as a source.
  - De-registering when the agent stops would falsely claim the host stopped using the address.

  The end of use is inferred from `last_seen` plus expiry.

### 4.4 Running as a service

`kardianos/service` provides `agent install|uninstall|start|stop|run`.

| OS | Runs as |
|---|---|
| Linux | systemd, dedicated user, `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| macOS | launchd daemon, root |
| Windows | Windows Service, LocalService |

Configuration is a small TOML file. The targets are a binary under 10 MB and memory use under 20 MB.

## 5. Collector (Linux, v1)

### 5.1 Process and privileges

- A single process runs as a dedicated user with `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` only.
- The systemd unit adds `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes` and `SystemCallFilter=@system-service`, plus a state directory for SQLite.
- **Interface roles** are configured per interface:

```toml
[[interface]]
name = "eth0"
roles = ["listen", "responder", "sniff"]
prefixes = ["2001:db8:10::/64"]   # optional; on-link prefixes are learned automatically

[registrar]
allowed_prefixes = ["2001:db8::/32"]  # required for direct unicast; default deny

[vendor]
enterprise_number = 32473             # placeholder; replace with real PEN
```

### 5.2 Listener

- Listens on UDP `[::]:547` and joins `ff02::1:2` on each `listen` interface. `IPV6_PKTINFO` gives the arrival interface and destination address.
- Accepts only:
  - **36** ADDR-REG-INFORM
  - **11** Information-Request (only when the responder is on)
  - **12** Relay-Forward, unwrapped to record the link address, peer address, interface-id and Client Link-Layer Address (option 79)
- Anything else is dropped and counted.
- **Sharing a host with another DHCPv6 server is unsupported.** On Linux, `SO_REUSEPORT` load-balances unicast between sockets.

### 5.3 Responder

- For links with no DHCPv6 server: answers Information-Request with a Reply (7) containing the Server ID (the collector's DUID), the client's Client ID and option **148**. Nothing else.
- Native clients only send Information-Request when the router's **RA has the O flag set**. This operational requirement must be documented.
- When another DHCPv6 server exists on the link, turn the responder off and configure that server to send option 148.

### 5.4 Registrar

The rules are applied strictly, following RFC 9686 §5:

| Check | Failure action |
|---|---|
| Client ID present, exactly one IA Address, no Server ID, **no Option Request** (stricter than Kea) | drop, `reg.reject` |
| IA address == source address (direct) or == the relay's peer address | drop, `reg.reject` |
| Global scope or ULA. Inside the link's prefixes (direct multicast), the prefixes configured for the relay link, or `allowed_prefixes` (direct unicast; deny by default) | drop, `reg.reject` |
| Token-bucket rate limits per source /64, per DUID and globally | drop, summarized `reg.reject` at most once per minute |

- **Binding:** keyed by address, holding DUID, MAC, `mac_src`, origin, link, lifetimes, `first_seen`, `last_seen` and `expires_at`. If a different DUID registers the same address, log `reg.conflict` and update the binding.
- A registration with zero lifetimes produces `reg.dereg` and removes the binding. Expiry produces `reg.expire`.
- **Reply:** ADDR-REG-REPLY (37) with the same transaction ID and an identical IA Address option. It goes to the source address and port, or comes back inside a Relay-Reply (13).
- The reply means only "stop retransmitting". It is never treated as validation of the address.

### 5.5 Sniffer

- Uses `AF_PACKET` via `mdlayher/packet` with a kernel BPF filter (`x/net/bpf`) for ICMPv6 types 133–136. Pure Go, no libpcap.
- Reads 802.1Q tags so it works on trunk and SPAN ports. Sightings record the interface and VLAN.
- **Deployment note:** with MLD snooping enabled on switches, an access port misses most DAD and solicited-node traffic. On managed networks a SPAN/mirror port or trunk is required.

| Signal | Mapping |
|---|---|
| DAD NS (source `::`) | target ↔ Ethernet source MAC. The strongest SLAAC signal. |
| NS with source and source link-layer option | source ↔ link-layer option MAC |
| NA | target ↔ target link-layer option, or Ethernet source MAC |
| RS with source link-layer option | source ↔ MAC |
| RA | router MAC and link-local address, M/O flags, prefixes, router lifetime |

- Sightings are collapsed in memory per (MAC, address, link). The database is written at most every 5 minutes per key. `nd.expire` fires after 24 h idle (configurable).
- Link-local sightings go to the **database only** by default (`log_link_local = false`).
- Any MAC seen with more than N addresses (configurable, default 32) is marked `proxy_suspect`, so routers doing proxy ND don't produce misleading host records.

### 5.6 Store

- `modernc.org/sqlite` (pure Go) in WAL mode, with a single writer goroutine that batches writes.
- Tables: `events` (append-only), `bindings`, `sightings`, `routers`, and `forwarder_state`.
- A daily retention sweep runs.

### 5.7 Logger and forwarder

- **SQLite is the source of truth.** Every event is committed to `events` first.
- The forwarder works through `events` and saves the last event ID it sent. After an outage it reconnects with backoff and replays, so syslog delivery is **at-least-once**.
- If the database can't be written, events go directly to syslog and a `store.error` event is raised.
- Outputs (one or more):
  - local syslog over `/dev/log`
  - remote over TCP or TLS, RFC 5424 with octet-counted framing (RFC 6587)
  - stdout, for journald or containers
- The facility is configurable and defaults to `local5`.
- Severity:
  - info: `*.add`, `*.new`, `ra.seen`
  - notice: `*.conflict`, `ra.change`, `*.expire`
  - warning: reject summaries, `store.error`
- `packaging/rsyslog/ra-logger.conf` ships a sample config: `mmjsonparse`, a dedicated JSON log file, and an optional forwarding rule.

### 5.8 Not in v1

- Active probing (pinging `ff02::1`). Windows doesn't answer multicast echo.
- Snooping DHCPv6 assignments from other servers.
- A BSD or macOS sniffer.
- Prometheus metrics. The `stats` event covers this need for now.

## 6. Error handling summary

- Every parser of network input checks all lengths and offsets and is fuzz-tested. Malformed input increments a counter and never panics.
- Interfaces and addresses fail independently. A broken interface is retried with backoff.
- Agent:
  - `EADDRNOTAVAIL` on send means the address is gone, so its state is dropped.
  - An unreachable collector gets backoff, with retries at each refresh.
- DUID continuity is protected as described in §4.2.

## 7. Testing

| Layer | Approach |
|---|---|
| `internal/dhcp6` and `internal/nd` codecs | Table tests on known-good packets (hand-built from the RFC, plus Kea interop captures in `testdata/`). Round-trip tests. **Go native fuzzing** of every decoder. |
| Registrar | Table tests for every rejection rule, conflicts, rate limits, relay unwrap, expiry |
| Agent address origin | Unit tests with fake OS data. Real runs on GitHub's Ubuntu, macOS and Windows runners check that loopback and link-local are excluded and that origin classification is sane. |
| End-to-end (Linux) | Network namespaces with virtual Ethernet pairs and `radvd`. The agent gets SLAAC addresses, and the collector must record bindings, ND sightings and the expected syslog lines. Covers the multicast, unicast and relay paths. |
| Interop | Agent → Kea ≥2.7.7 (ISC packages or Docker image), checking the registered lease. A manual Android test procedure is documented. |
| Negative | `cmd/regsend` sends malformed and spoofed registrations, which must produce the expected `reg.reject` events |

## 8. Repository layout

```
cmd/agent  cmd/collector  cmd/regsend
internal/dhcp6                      # codec: msgs 7,11,12,13,36,37; opts 1,2,5,6,15,16,39,79,148
internal/nd                         # RS/RA/NS/NA parsing
internal/event                      # shared event schema (§3)
internal/agent/addrsrc              # addrsrc_linux.go / _darwin.go / _windows.go
internal/agent/duid                 # per-OS DUID discovery + generation
internal/agent/sched                # retransmit/refresh/heartbeat timers
internal/collector/{listener,responder,registrar,sniffer,store,logger,query}
packaging/{systemd,launchd,windows,rsyslog}
testdata/  docs/
.github/workflows/{ci.yml,release.yml}
```

## 9. CI/CD (GitHub Actions)

- **`ci.yml`** runs on push and PR, on an `ubuntu-latest`, `macos-latest` and `windows-latest` matrix:
  - `go vet`, `staticcheck`, `govulncheck`, `go test -race ./...`
  - Linux only: the namespace end-to-end tests (with sudo), a short fuzz run on each fuzz target, and the Kea interop job
- **`release.yml`** runs on `v*` tags and uses GoReleaser with `CGO_ENABLED=0` and `-trimpath`.

  | Binary | Targets |
  |---|---|
  | agent | linux/amd64, linux/arm64, darwin universal (amd64+arm64), windows/amd64, windows/arm64 |
  | collector | linux/amd64, linux/arm64, linux/armv7 |

  - Artifacts: `.deb`/`.rpm` (nfpm, including systemd units), `.tar.gz`/`.zip`, checksums, SBOM, GitHub build-provenance attestations.
- **Workflow hardening:** actions pinned by commit SHA, minimal `permissions:`, Dependabot for Go modules and actions.
- **Code signing is deferred.** A signed, notarized macOS `.pkg` and an Authenticode-signed MSI need an Apple Developer ID and a code-signing certificate. They will be a later, separate job. Unsigned binaries can be deployed via MDM or GPO.

## 10. Open items to verify during implementation

1. **Port 546.** How do Kea and native stacks reply when the ADDR-REG-INFORM source port isn't 546? Can the agent bind 546 next to the OS DHCPv6 client on macOS (`configd`) and Windows (the DHCP service)?
2. **Linux DUID sources.** Settle which DUID sources (networkd, NetworkManager, dhclient) are reliable enough to read, versus always generating one.
3. **Vendor Class options.** Confirm that Kea accepts ADDR-REG-INFORM messages carrying Vendor Class (16) and FQDN (39).
4. **PEN.** Replace 32473 with a real IANA PEN before production.
