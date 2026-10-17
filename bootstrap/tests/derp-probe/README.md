# Isolated DERP data probe

This program joins the configured self-hosted Headscale as a temporary peer. It
never creates a host TUN, changes routes or DNS, or uses the production tailscaled
socket. Its tsnet listener accepts only the other uniquely named probe peer on
TCP 18089. Each direction opens a new connection every 2 seconds, echoes 128 KiB of
random data, and verifies SHA-256. Every fifth successful exchange also requests a
DISCO ping and records the actual DERP region. JSONL output includes UTC time,
latency, byte counters, errors and the observed relay.

Build the pinned source outside the server. Go verifies dependencies against the
module checksums. Keep the generated executable outside Git:

```sh
GOTOOLCHAIN=go1.27.1 go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.27.1 \
  go build -trimpath -o /tmp/derp-probe .
```

Create two unique `infra-derp-test-<run>-<site>` names and one temporary Headscale
user. Create exactly two single-use keys with `--ephemeral=true --reusable=false
--expiration 20m`; record their numeric IDs privately. Keep keys in 0600 files,
never command arguments, environment variables, logs or Git. Register both clients
against the same configured HTTPS coordinator. After enrollment, verify both
production VPS netmaps contain the temporary NodeKeys: DERP's existing
`-verify-clients` membership check remains enabled.

Place the executable in its own root-owned directory on an executable filesystem
(for example under `/opt`); keep credentials and transient state under `/run`.
Preserve existing `noexec` mounts. Run each executable in a separate bounded
transient systemd unit with
`DynamicUser=yes`, empty capability sets, `NoNewPrivileges=yes`, private 0700
`RuntimeDirectory`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`MemoryMax=256M`, `MemorySwapMax=0`, `CPUQuota=20%`, `TasksMax=64`, and a
`RuntimeMaxSec` slightly longer than the requested duration. Supply the key through
`LoadCredential=authkey:<private-file>` and point `--auth-key-file` at that unit's
credential file. Delete the source key file once systemd has loaded it. Redirect
stdout/stderr to dedicated root-owned 0600 files and retain them outside Git.

The program requires `TS_DEBUG_ALWAYS_USE_DERP=true` in its own process environment.
It refuses a manual DERP-map override and verifies that both UDP transports were
disabled before emitting `ready`. Cloud log uploads are disabled in-process.
Example program arguments, with values supplied privately:

```text
--control-url=https://YOUR-HEADSCALE-NAME
--hostname=infra-derp-test-RUN-msk
--peer-hostname=infra-derp-test-RUN-fin
--auth-key-file=/run/credentials/UNIT.service/authkey
--state-dir=/run/UNIT
--duration=90m
--interval=2s
```

Require successful 128 KiB exchanges in **both** directions and nonzero DISCO
`path_derp_region_id` before fault injection. A `ready` event or successful HTTPS
connection alone does not prove relay data transfer. The root operator uses the
separate fault harness to stop only one real DERP at a time; this program never
stops a service. Keep the complete two-region coordinator-provided DERP map and
normal region selection. Do not pin a preferred region during the failure test.
Record data failures and reconnection times, including failures that persist until
rollback; two configured relays do not establish successful failover by themselves.
The clients have a 1-minute minimum/2-hour maximum lifetime. Any observation gap
caused by observer termination must remain a gap in the report.

Run DERP and coordinator tests before VPS reboots. These test units and their
in-memory identities intentionally do not restart after reboot; a later run needs
fresh bounded identities and keys.

After testing, stop only the two recorded transient units. Verify exact owner
markers and binary hashes before removing their private temporary directories.
Delete only the recorded temporary node IDs after matching names, user ID and
NodeKeys; ephemeral nodes may already have disappeared. Delete the two recorded
preauth-key IDs, then the empty temporary user by numeric ID. Do not delete by
prefix or use a broad node-cleanup command. Keep probe evidence in the private
run directory. Production tailscaled, coordinator, DERP and host firewall state
are not part of this cleanup.

Pinned implementation references:

- [UDP-disable debug knob](https://github.com/tailscale/tailscale/blob/v1.104.1/wgengine/magicsock/debugknobs.go).
- [tsnet rejects unregistered incoming ports](https://github.com/tailscale/tailscale/blob/v1.104.1/tsnet/tsnet.go).
- [DERP membership verification uses local tailscaled](https://github.com/tailscale/tailscale/blob/v1.104.1/derp/derpserver/derpserver.go).

A plain standalone `tailscaled --tun=userspace-networking` is not substituted:
its default incoming TCP behavior can forward to host loopback services, whereas
this tsnet application rejects unregistered ports.
