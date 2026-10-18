# Enroll an already prepared legacy DNS client

This standalone lifecycle uses the exact owned package preparation and never
runs the unified bootstrap. Keep inventory, inputs, keys and evidence outside
Git. Use a separate `legacy_dns_clients` inventory and one host per run. The
playbook defaults to disabled; explicit enablement installs two immutable
helpers under `/etc/infra-flux/legacy-dns-enroll`. It refuses overwriting them.

Run the installed `legacy-dns-client-enroll.py` with JSON on stdin, or use
`legacy-dns-client-enroll.yml` with `legacy_dns_enroll_enabled: true` and
`legacy_dns_enroll_inputs: {legacy_host: {...}}`. Every mutating input needs
`enabled: true` and the same unique `operation` ID (8–48 lowercase letters,
digits and hyphens). No phase retries an uncertain start or registration.

1. **Inspect:** `action: inspect`, `admin_address`. Save the returned `guard`
   and preparation receipt digest privately. Inspect the intended host through
   the same administration path. This helper action is read-only; installing
   the helper files via the playbook is a separate filesystem change.
2. **Stage:** `action: stage`, `admin_address`, `expected_guard`,
   `prepare_receipt_sha256`, `server_url`, `hostname: legacy-<name>`,
   `rollback_seconds` (300–1800), and `coordinator_evidence_sha256`. The latter
   is the digest of independent evidence that the intended coordinator is
   active, its restricted policy is confirmed, and the client name is unused.
   An optional `relay_ipv4` appends one owned coordinator entry to `/etc/hosts`
   after checking its exact preimage and absence of competing entries. Review
   the existing relay's TLS/SNI path separately. Stage leaves the original
   startup gate in place and arms a persistent systemd calendar deadline.
3. **Start:** `action: start`. This removes only the verified preparation gate
   and starts the exact pinned daemon with its persistent startup configuration.
   It must reach `NeedsLogin` with DNS, route acceptance, netfilter management,
   Tailscale SSH and remote configuration disabled. Boot activation stays off.
4. **Register:** first create a short-lived, single-use, non-ephemeral Headscale
   key with the reviewed reader/writer tags. Pass `action: register` and
   `auth_key` through protected stdin / Ansible `no_log`; never command arguments
   or Git. The helper uses a root-only file under `/run`, removes it in `finally`,
   and records the resulting node identity. The orchestrator must expire the
   key on the coordinator in its own `finally`, even if client registration
   times out. Registration does not alter application endpoints or DNS writers.
5. **Confirm:** independently check the exact node ID/key/IP/tags against
   Headscale; allowed **and denied** application connections; another fresh
   administration session; old public DNS and services; and effective firewall
   and route changes. Host checks do not prove Pod forwarding or SNAT. Submit
   `action: confirm`, the exact `expected_node`, `key_expired: true`, and
   `external_evidence_sha256` for that proof. Confirmation enables boot startup,
   persists the confirmed receipt and disarms the deadline under one lock.

For example, phase inputs are passed with:

```sh
ansible-playbook -i /private/path/legacy-inventory.yml \
  bootstrap/ansible/legacy-dns-client-enroll.yml \
  --limit legacy_host -e @/private/path/legacy-enroll-phase.yml
```

The startup config contains no key. `netfilterMode: off` avoids installing
Tailscale firewall rules, but enrolling still creates an interface and policy
routes. Tailscale's startup/stop cleanup touches its own firewall remnants;
the first-start check therefore refuses existing Tailscale interfaces, routing
table 52 or firewall chains. It never freezes generated Kubernetes rules or
restores an old global firewall. Existing service processes, administration
route, resolver, hosts and unrelated package inventory are checked exactly;
broader network/firewall differences are recorded for independent review.

## Deadline, interruption and rollback

`/etc/infra-flux/legacy-dns-enroll/operation.json` is the private durable receipt.
The persistent rollback timer survives reboot, with boot startup disabled until
confirmation. A crash during confirmation can leave boot activation enabled
temporarily; the still-armed deadline rolls that unconfirmed operation back.
The timer and confirmation share a lock: whichever commits first wins. A queued
rollback sees `confirmed` and becomes a no-op; an expired deadline cannot confirm.

Manual rollback is the same installed helper's `rollback <operation>` subcommand.
It restores the preparation gate **before** stopping and disabling the owned
daemon. It removes only the exact owned hosts line, retaining unrelated hosts
changes, and removes a leftover key file. If the line was never appended or a
previous rollback already removed it, hosts cleanup is a no-op and does not
rewrite the file. Duplicate exact owned lines still refuse cleanup. It keeps the Tailscale node state,
configuration, operation receipt and helper files for diagnosis. It never
uninstalls, resets enrollment, deletes coordinator identities, reboots, or
flushes another service's routes/firewall. Offline peers and changed old service
PIDs cannot block the owned-client stop; package/unit/operation ownership still
must match. Drift is recorded, not repaired.

A partial stage retains its intent and the preparation gate. If staging failed
before all timer files were installed, automatic rollback may not be armed;
the client remains blocked. Inspect the receipt/files before a bounded repair.
Any uncertain stage/start/register/confirm outcome requires readback, not a new
operation ID or deletion of receipts. Rollback is not coordinator-key revocation:
the orchestrator must still expire its key and review any created node.

Configuration fields and network flags are pinned to official
[Tailscale v1.104.1 configuration source](https://github.com/tailscale/tailscale/blob/v1.104.1/ipn/conf.go),
[client flags](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/tailscale/cli/up.go),
and the [vendor service](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/tailscaled/tailscaled.service).
