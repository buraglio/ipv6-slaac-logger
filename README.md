# ipv6-ra-logger

Forensic mapping of **DUID ↔ MAC ↔ IPv6 address** over time, built on
[RFC 9686](https://datatracker.ietf.org/doc/rfc9686/) (Registering
Self-Generated IPv6 Addresses Using DHCPv6), with rsyslog integration.

Design: [docs/superpowers/specs/2026-11-08-ipv6-ra-logger-design.md](docs/superpowers/specs/2026-11-08-ipv6-ra-logger-design.md)

## Status

| Component | State |
|---|---|
| `collector`: RFC 9686 server, option-148 responder, SQLite store, syslog forwarding, query | implemented |
| `agent`: cross-platform RFC 9686 client (macOS, Windows, Linux) | implemented |
| `collector`: ND/RA sniffer for hosts that can't run the agent (Linux) | implemented |
| Release packaging | planned |

## Build

```sh
CGO_ENABLED=0 go build -o bin/ra-logger-collector ./cmd/collector
CGO_ENABLED=0 go build -o bin/ra-logger-agent ./cmd/agent
CGO_ENABLED=0 go build -o bin/regsend ./cmd/regsend   # developer test tool
```

## Run the collector

1. Copy `packaging/collector.example.toml` to `/etc/ra-logger/collector.toml` and edit the interfaces.
2. Install `packaging/systemd/ra-logger-sysusers.conf` as `/usr/lib/sysusers.d/ra-logger.conf` and run `systemd-sysusers`, then install `packaging/systemd/ra-logger-collector.service` and run `systemctl daemon-reload`.
3. Create the log directory and install the rsyslog config, then restart rsyslog:

   ```sh
   mkdir -p /var/log/ra-logger
   chown syslog:adm /var/log/ra-logger   # adjust to match your rsyslog user
   install -m 644 packaging/rsyslog/30-ra-logger.conf /etc/rsyslog.d/
   systemctl restart rsyslog
   ```

   Events are written to `/var/log/ra-logger/events.json` (one JSON object per line). rsyslog silently ignores them if the directory is missing.
4. If the link has no other DHCPv6 server, give the interface the `responder` role and **set the O flag in the router's RAs**. Native RFC 9686 clients only register after a DHCPv6 server returns option 148.
5. If registrations arrive through DHCPv6 relays, list the relays' source prefixes in `registrar.trusted_relays` (relayed messages from anyone else are dropped) and their client prefixes in `registrar.relay_prefixes`.

**Two separate log channels.** The collector writes to two independent streams:

- **Process log** (startup, errors, capability problems): always goes to stderr, captured by journald when running as a service. Check it with `journalctl -u ra-logger-collector -f`. This is where "sniffer capturing" or "sniffer capture failed" messages appear.
- **Event log** (`nd.new`, `nd.conflict`, `ra.seen`, `stats`, registrar events): stored in SQLite first, then forwarded to the sinks in `[log]`. With the default config this means `/dev/log` → rsyslog → `/var/log/ra-logger/events.json`.

If you see nothing in syslog, check the process log first. If the sniffer is running, verify events reached the database before suspecting rsyslog:

```sh
# Is the sniffer capturing? (process log)
journalctl -u ra-logger-collector | grep -E "sniffer|capturing|failed"

# Did any sightings reach the database? (bypasses syslog entirely)
ra-logger-collector query -sightings
```

To see events in the terminal without rsyslog, add a `stdout` output:

```toml
[[log.output]]
type = "stdout"
```

**Syslog rate limits.** When `/dev/log` is served by journald or by rsyslog's
`imuxsock`, their rate limits must be disabled or raised for ra-logger.
Otherwise a replayed backlog (or a burst of registrations) can be dropped by
the daemon after the collector has counted it as delivered. The shipped unit
sets `LogRateLimitIntervalSec=0` for journald; for `imuxsock` use
`module(load="imuxsock" ratelimit.interval="0")` (or raise
`ratelimit.burst`).

Look up an address:

```sh
ra-logger-collector query -addr 2001:db8:10::5 -at 2026-11-08T21:00:00Z
```

`query` reads the database in the state directory (mode 0750), so run it as
root or as a member of the `ra-logger` group.

## Agent

The agent runs on each host (Linux, macOS, Windows). It finds the host's
self-generated IPv6 addresses (SLAAC, temporary and static, ULA included) and
registers each one with an ADDR-REG-INFORM message (RFC 9686). It sends to
every configured collector over unicast, and to `ff02::1:2` on links where an
RFC 9686 server answers.

```sh
CGO_ENABLED=0 go build -ldflags "-X main.version=1.0.0" -o ra-logger-agent ./cmd/agent
ra-logger-agent list                 # show local addresses and which would be registered (-json for JSON)
ra-logger-agent -config agent.toml run   # foreground
```

Configuration is optional TOML; start from `packaging/agent.example.toml`. The
default path is `/etc/ra-logger/agent.toml` (Linux),
`/Library/Application Support/ra-logger-agent/agent.toml` (macOS) and
`%ProgramData%\ra-logger-agent\agent.toml` (Windows). A missing file means
all defaults.

Install as a service with `ra-logger-agent [-config PATH] install`, then
`start`. Also available: `stop`, `uninstall`. The service runs
`agent -config <absolute path> run`. Run `install` as root or Administrator.

| OS | Runs as |
|---|---|
| Linux | systemd unit, `DynamicUser=yes`, state in `/var/lib/ra-logger-agent`, only `CAP_NET_BIND_SERVICE` |
| macOS | launchd daemon, root |
| Windows | Windows Service as `NT AUTHORITY\LocalService`; `install` creates the state directory and grants LocalService modify rights with `icacls` |

**Enterprise number.** The agent identifies itself in Vendor Class (16) with
the `enterprise_number` setting (default 32473, the RFC 5612 documentation
PEN). It must match the collector's `[vendor] enterprise_number`; see
[Vendor Class enterprise number](#vendor-class-enterprise-number).

**Multicast needs a server on the link.** In `multicast = "auto"` mode the
agent sends to `ff02::1:2` only on a link where its own Information-Request
for option 148 gets a reply carrying option 148. That needs an RFC 9686
DHCPv6 server on the link, or the collector's `responder` role with the **O
flag set in the router's RAs**. Without one, and with no `collectors`
configured, the agent registers nothing (it logs a warning at start). The
agent does not check the RA M/O flags itself, because they can't be read
portably.

### Limits and platform notes

- **DUID on Linux.** Only dhclient's `default-duid` is read. On
  systemd-networkd and NetworkManager hosts the agent's DUID won't match the
  OS DHCPv6 client's DUID unless `duid` is set in the config. Otherwise the
  agent generates a DUID-LLT, saves it in `agent-state.json` in the state
  directory, and keeps it across restarts and MAC randomization. A corrupt
  state file is backed up before a new DUID is generated.
- **macOS lifetimes** come from `SIOCGIFALIFETIME_IN6` (wall-clock expiry). If
  that ioctl fails, the address is registered as infinite and refreshed every
  heartbeat.
- **Windows** can't distinguish temporary from stable-privacy addresses, so
  both are reported as `slaac`. Both are registered.
- **No de-registration.** The agent never announces that an address is gone;
  the end of use is inferred from `last_seen` plus expiry. This departs from
  the RFC on purpose: once the OS removes an address it can't be used as a
  source, and de-registering at shutdown would falsely claim the host stopped
  using it.
- **Port 546.** If 546 is held by the OS DHCPv6 client, the agent falls back
  to an ephemeral source port. A missing reply only causes retransmits.
- **Registered addresses.** Global-scope addresses (ULA included) with origin
  SLAAC, temporary or static and finished duplicate address detection.
  DHCPv6-assigned, link-local, loopback, tentative and duplicate addresses are
  not registered.
- **Heartbeat.** The default is 1 h, shorter than the RFC's lifetime-based
  refresh, to bound the uncertainty about when an address stopped being used.

## Sniffer

Give an interface the `sniff` role to learn **MAC <-> IPv6 address** pairs, and
the routers advertising on the link, from passive Neighbor Discovery traffic.
This covers devices that cannot run the agent (IoT, printers). Sightings carry
no DUID. The collector needs `CAP_NET_RAW` on that interface.

**Deployment note.** With MLD snooping enabled on the switches, an access port
misses most DAD and solicited-node traffic. On managed networks a SPAN/mirror
port or a trunk is required. A host that never sends ND traffic the sniffer can
see produces no sightings.

Events: `nd.new` (a MAC is seen using an address), `nd.conflict` (an address
now belongs to a different MAC; carries `prev_mac`), `nd.expire` (not seen for
`idle_timeout`), `ra.seen` (a new router) and `ra.change` (its M/O flags or
prefix set changed). Tuning is in the `[sniffer]` block of the example config.
`query` shows sightings and the MACs seen using an address at `-at`.

### Limits

- **Capture.** A raw `AF_PACKET` socket with `PACKET_AUXDATA` (not
  `mdlayher/packet`), so 802.1Q tags that the kernel strips into socket metadata
  are still recorded. The interface is put in **promiscuous mode**. The
  collector's own outgoing frames are included, so a collector that is also the
  router sees its own RAs. Linux only.
- **Extension headers.** ND packets carrying IPv6 extension headers are dropped
  by the kernel filter. ND never uses them, so this is an accepted loss.
- **VLANs and QinQ.** Tags the kernel strips into socket metadata and one
  in-frame 802.1Q/802.1ad tag are read. The kernel filter drops frames with more
  than one in-frame tag. With QinQ only the **outer** tag is recorded as `vlan`.
- **Repeat sightings.** A sighting seen again only updates `last_seen`, and
  never produces a syslog line. `last_seen` is written to the database at most
  every 5 minutes per sighting (and per router), so the database can lag the
  wire by up to 5 minutes. Pending values are written on a clean shutdown.
- **Expiry and reuse.** A sighting not seen for `idle_timeout` is expired: an
  `nd.expire` is logged and the row is kept with `expired = 1` until its
  `last_seen` is older than `retention_days`. If the sighting reappears, the
  same row is reused, `first_seen` is reset and a new `nd.new` is logged. The
  earlier windows remain in the event log.
- **Conflicts.** `nd.conflict` (a new MAC for an address that already has a
  different live MAC) is logged instead of `nd.new` and carries `prev_mac`.
  Both sightings stay live: both MACs may genuinely answer for the address.
- **Flood limits.** At most `max_entries` (default 100000) live sightings are
  held; beyond that new ones are dropped and counted in `sniff_overflow`. Once
  the table is full, genuine new hosts are dropped too, until flooded entries
  expire after `idle_timeout`. `nd.new` and `nd.conflict` events share a token
  bucket of 20/s with a burst of 200; over the cap the sighting is still stored
  but no event is logged (`nd_suppressed`). `nd.expire` is never rate-limited,
  but it is only logged for sightings whose `nd.new` or `nd.conflict` was
  logged (sightings loaded at start-up count as logged), so a suppressed flood
  does not come back as a flood of expiries.
- **Proxy suspects.** A MAC seen with more than `proxy_threshold` (default 32)
  addresses on one link and VLAN is marked `proxy_suspect` (one Warn line in
  the process log). From then on it produces no `nd.*` events and is ignored by
  the `hosts` view and by the registrar's MAC lookup. Its sightings are still
  stored. The flag persists until that MAC's sightings on the link expire.
- **MAC precedence** for registrations: `cllao` > `vendor` > `nd` > `duid`. A
  MAC seen on the wire beats the one embedded in a DUID, which often belongs to
  another interface. An `nd` MAC on a binding is replaced on the next refresh
  once the sniffer no longer confirms it (its sighting expired or turned proxy
  suspect); the binding then falls back to the DUID MAC. `l2` is reserved and
  not implemented.
- **Link-local sightings** go to the database only, with no events, unless
  `log_link_local = true`.
- **`hosts` view.** It joins bindings and sightings on address **and** MAC. A
  sighting whose MAC differs from the binding's MAC is absent from `hosts` but
  shown by `query` under `sightings`. Its `link` column differs by row kind: a
  row backed by a sighting carries the sniffing interface name; a binding-only
  row carries the binding's link (the receiving interface, or
  `relay/<link-address>` for relayed registrations).
- **RA logging.** `ra.seen` fires for a new router (link, VLAN, MAC,
  link-local address) and `ra.change` when its M or O flag or prefix set
  changes. A change in router lifetime alone is stored but not logged. There is
  no `ra.expire`.
- **RA limits.** At most `max_routers` (default 1000) routers are tracked;
  RAs from new routers beyond that are dropped and counted in `ra_overflow`.
  `ra.seen` and `ra.change` share their own token bucket of 2/s with a burst of
  50; over it the router row is still written but no event is logged
  (`ra_suppressed`). A router not seen for `idle_timeout` is dropped from
  memory without an event (its row stays until `retention_days`); if it comes
  back it gets a new `ra.seen`. At start-up only routers seen within
  `idle_timeout` are loaded.
- **Other operating systems.** Capture is Linux only. Elsewhere an interface
  with the `sniff` role logs "sniffing unsupported on this OS" once and does
  nothing; the rest of the collector runs.

### Sniffer counters

The `stats` event carries these counters (cumulative since start) next to the
registrar's. Each name has exactly one owner, and a test enforces that.

| Counter | Meaning |
|---|---|
| `frames` | Frames read from the sniffed interfaces (summed over interfaces). |
| `nd_malformed` | Frames that passed the kernel filter but failed ND parsing or the RFC 4861 §6.1 validity checks: truncated Ethernet, VLAN or IPv6 header, ND message shorter than its minimum length, IP version not 6, payload length beyond the frame, hop limit not 255, bad checksum, nonzero code, bad option lengths, invalid Prefix Information prefix length, multicast NS/NA target, malformed DAD. |
| `nd_not_nd` | Frames that passed the kernel filter but are not Neighbor Discovery. |
| `nd_sightings` | New (MAC, address, link, VLAN) sightings admitted. |
| `nd_suppressed` | `nd.new`/`nd.conflict` events not logged because of the 20/s rate cap. |
| `sniff_overflow` | New sightings dropped because `max_entries` live sightings were held. |
| `ra_seen_total` | Valid RAs observed (link-local source). |
| `ra_overflow` | RAs from new routers dropped because `max_routers` routers were tracked. |
| `ra_suppressed` | `ra.seen`/`ra.change` events not logged because of the 2/s rate cap (the router row is still written). |
| `nd_invalid` | RAs ignored because the source address was not link-local. |

## Test

```sh
go test -race ./...                                        # unit tests (any OS)
sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e     # Linux network-namespace end-to-end test
```

## Interoperability

The CI job `interop-kea` runs the agent against ISC Kea 3.0 in network
namespaces. Kea 3.0 has no `allow-address-registration` key (3.1.4 and later add
it, default on). Do not put Kea and the collector's `responder` role on the same
link, or two servers answer the same registration (see spec §10 item 3). The Android procedure is in
[docs/android-interop.md](docs/android-interop.md).

## Known limitations

- Interfaces with the `listen` or `responder` role must exist when the
  collector starts; startup fails otherwise.
- An interface that is deleted and recreated after startup loses its
  `ff02::1:2` membership until the collector restarts.
- Interfaces with the `sniff` role may be missing at start-up; the sniffer retries opening them with backoff.
- The sniffer captures on Linux only; on other systems the `sniff` role logs a warning once and does nothing.

## Vendor Class enterprise number

The agent identifies itself with a Vendor Class option (16). The default
enterprise number is **32473**, the RFC 5612 documentation PEN. Replace it with
a real [IANA PEN](https://pen.iana.org/pen/PenApplication.page) before production use.

## License

[LICENSE](LICENSE.md)

## AI-Assisted Development Notice

This software contains components generated by Large Language Model (LLM) or machine intelligence platforms. AI tools were used to assist in various stages of the development lifecycle. A human reviewed all AI-generated content. Code generated by LLMs may occasionally contain subtle logical errors or inefficiencies that were not detected during review.