# Android interoperability test (manual)

Android 16 and later can register SLAAC addresses itself (RFC 9686). This
procedure checks that the collector records such a registration with
`origin:"native"`.

## Setup

1. Use an isolated test VLAN or Wi-Fi SSID with an IPv6 router. The collector
   host needs a leg on that link.
2. Configure the router to send RAs with the **O flag** (other-config) set and
   an autonomous prefix. Android starts its DHCPv6 information exchange only when
   it sees the O flag.
3. Run the collector on that link with the roles `listen` and `responder`:

   ```toml
   [[interface]]
   name = "eth0"        # the test-VLAN interface
   roles = ["listen", "responder"]

   [registrar]
   allowed_prefixes = ["<the VLAN's /64>"]

   [[log.output]]
   type = "stdout"
   ```

   No other DHCPv6 server that answers address registration (for example Kea)
   may share this link.

## Procedure

1. Note the device's Wi-Fi MAC for this network. Android randomizes the MAC per
   network by default, so use the per-network MAC shown in the network's
   details (or set the network to "Use device MAC").
2. Join the Android 16+ device to the test network.
3. Watch the collector output for a `reg.add` event for the device:

   ```
   {"event":"reg.add", ... "origin":"native", ...}
   ```

   `origin` must be `native`. An `agent` value means the registration came from
   the agent, not from Android.
4. Confirm with the database, after stopping the collector or from another
   shell (SQLite allows concurrent readers):

   ```sh
   collector query -db /var/lib/ra-logger/ra-logger.db -mac <device MAC>
   ```

   The output must list the device's SLAAC address with a `reg.add` record.

## Results

Record every device tested.

| Date | Device | Android version | Result (reg.add seen, origin native) | Notes |
|---|---|---|---|---|
| | | | | |
