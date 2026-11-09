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

## Test

```sh
go test -race ./...                                        # unit tests (any OS)
sudo -E env PATH=$PATH go test -tags e2e -v ./test/e2e     # Linux network-namespace end-to-end test
```

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
