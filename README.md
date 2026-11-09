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
| `collector`: ND/RA sniffer for hosts that can't run the agent (Linux) | implemented |
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

`query` reads the database in the state directory (mode 0750), so run it as
root or as a member of the `ra-logger` group.

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
- **Flood limits.** At most `max_entries` (default 100000) live sightings are
  held; beyond that new ones are dropped and counted in `sniff_overflow`.
  `nd.new` and `nd.conflict` events share a token bucket of 20/s with a burst of
  200; over the cap the sighting is still stored but no event is logged
  (`nd_suppressed`). `nd.expire` is never capped. Both counters appear in the
  `stats` event.
- **Proxy suspects.** A MAC seen with more than `proxy_threshold` (default 32)
  addresses on one link and VLAN is marked `proxy_suspect`. From then on it
  produces no `nd.*` events and is ignored by the `hosts` view and by the
  registrar's MAC lookup. Its sightings are still stored.
- **MAC precedence** for registrations: `cllao` > `vendor` > `nd` > `duid`. A
  MAC seen on the wire beats the one embedded in a DUID, which often belongs to
  another interface. `l2` is reserved and not implemented.
- **Link-local sightings** go to the database only, with no events, unless
  `log_link_local = true`.
- **RA logging.** `ra.seen` fires for a new router and `ra.change` when its M or
  O flag or prefix set changes. A change in router lifetime alone is stored but
  not logged.

### Sniffer counters

The `stats` event carries these counters (cumulative since start) next to the
registrar's. Each name has exactly one owner, and a test enforces that.

| Counter | Meaning |
|---|---|
| `frames` | Frames read from the sniffed interfaces (summed over interfaces). |
| `nd_malformed` | Frames that matched the filter but failed to parse as ND. |
| `nd_not_nd` | Frames that passed the kernel filter but are not Neighbor Discovery. |
| `nd_sightings` | New (MAC, address, link, VLAN) sightings admitted. |
| `nd_suppressed` | `nd.new`/`nd.conflict` events not logged because of the 20/s rate cap. |
| `sniff_overflow` | New sightings dropped because `max_entries` live sightings were held. |
| `ra_seen_total` | Valid RAs observed (link-local source). |
| `nd_invalid` | RAs ignored because the source address was not link-local. |

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
- Interfaces with the `sniff` role may be missing at start-up; the sniffer retries opening them with backoff.

## Vendor Class enterprise number

The agent identifies itself with a Vendor Class option (16). The default
enterprise number is **32473**, the RFC 5612 documentation PEN. Replace it with
a real [IANA PEN](https://pen.iana.org/pen/PenApplication.page) before production use.

## License

[LICENSE](LICENSE.md)

## AI-Assisted Development Notice

This software contains components generated by Large Language Model (LLM) or machine intelligence platforms. AI tools were used to assist in various stages of the development lifecycle. A human reviewed all AI-generated content. Code generated by LLMs may occasionally contain subtle logical errors or inefficiencies that were not detected during review.