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
| ND/RA sniffer for hosts that can't run the agent | planned |
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
3. Install `packaging/rsyslog/30-ra-logger.conf` to `/etc/rsyslog.d/`, then restart rsyslog.
4. If the link has no other DHCPv6 server, give the interface the `responder` role and **set the O flag in the router's RAs**. Native RFC 9686 clients only register after a DHCPv6 server returns option 148.
5. If registrations arrive through DHCPv6 relays, list the relays' source prefixes in `registrar.trusted_relays` (relayed messages from anyone else are dropped) and their client prefixes in `registrar.relay_prefixes`.

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

## Test

```sh
go test -race ./...                                        # unit tests (any OS)
sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e     # Linux network-namespace end-to-end test
```

## Interoperability

The CI job `interop-kea` runs the agent against ISC Kea 3.0 in network
namespaces. Kea 3.0 has no `allow-address-registration` key (3.1.4 and later add
it, default on). Do not put Kea and the collector's `responder` role on the same
link, or two servers answer the same registration. The Android procedure is in
[docs/android-interop.md](docs/android-interop.md).

## Known limitations

- Interfaces with the `listen` or `responder` role must exist when the
  collector starts; startup fails otherwise.
- An interface that is deleted and recreated after startup loses its
  `ff02::1:2` membership until the collector restarts.
- Per-interface retry is planned together with the ND/RA sniffer work.

## Vendor Class enterprise number

The agent identifies itself with a Vendor Class option (16). The default
enterprise number is **32473**, the RFC 5612 documentation PEN. Replace it with
a real [IANA PEN](https://pen.iana.org/pen/PenApplication.page) before production use.

## License

[LICENSE](LICENSE.md)

## AI-Assisted Development Notice

This software contains components generated by Large Language Model (LLM) or machine intelligence platforms. AI tools were used to assist in various stages of the development lifecycle. A human reviewed all AI-generated content. Code generated by LLMs may occasionally contain subtle logical errors or inefficiencies that were not detected during review.