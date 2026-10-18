# Prepare an inactive VPN client on legacy DNS hosts

This standalone playbook installs only the pinned official Tailscale package.
It does not enroll a host, start its client, alter DNS or routes, edit firewall
rules, or run the unified-cluster preparation. Existing package dependencies
must already be installed; the helper invokes `dpkg` for one reviewed package
and never invokes a dependency resolver or upgrade command.

Keep inventory, addresses, captured baselines and receipts outside Git, with
owner-only permissions. Use a separate `legacy_dns_clients` inventory group;
never add a legacy host to `unified` to make preparation work.

## Inspect and prepare

The helper `files/legacy-dns-client-prepare.py` reads JSON from stdin. Run its
source as root with `action: inspect` and an explicit `admin_address` matching
the administration connection. Inspection is read-only and returns `baseline`
plus `installation`. Preserve the exact output privately; check the node
identity, service processes and administration route against the intended host.
For a fish login shell, transmit the Python source through stdin or use the
Ansible command module; do not embed multiline POSIX quoting in an SSH command.

Create a private variable file with this structure, replacing the example host
name and address and copying the complete inspected baseline into `expected`:

```yaml
legacy_dns_prepare_enabled: true
legacy_dns_prepare_inputs:
  legacy_host:
    action: prepare
    enabled: true
    admin_address: 192.0.2.10
    expected: {} # The complete fresh helper baseline, never an empty object.
```

Run the narrow playbook against one reviewed host at a time:

```sh
ansible-playbook -i /private/path/legacy-inventory.yml \
  bootstrap/ansible/legacy-dns-client-prepare.yml \
  --limit legacy_host -e @/private/path/legacy-prepare.yml
```

Preparation refuses preexisting unmanaged packages, binaries, state or services,
unfinished package transactions, changed identities and changed network/DNS
baselines. It checks the same services, routes, firewall rules, DNS and other
packages immediately before and after installation. Packet counters, address
lifetimes and list ordering do not count as configuration drift.

Temporary firewall changes, including Fail2ban ban expiry, still stop preparation.
Inspect the exact rule difference and confirm whether installation began before
capturing a fresh baseline. Never freeze another service, restore an old ruleset,
or erase an intent receipt merely to make the comparison pass.

The package maintainer script attempts to enable and restart its service. An
owned systemd condition is installed first, requiring the **absent** file
`/etc/infra-flux/legacy-dns-client-start-approved`. Preparation then disables
the service and verifies that its main process has never started. The condition
persists across reboot. Do not create that approval file during preparation.

## Resume and handoff

The root-only receipt is `/etc/infra-flux/legacy-dns-client-preparation.json`.
An exact verified installation is a no-op; it is never adopted or upgraded.
Any interrupted transaction retains its intent and start gate and refuses an
automatic retry. Inspect package state, the service and the receipt before
planning a bounded repair. Do not remove the receipt or use another identity
to bypass this guard. Changes to the captured boot, services or network also
require a fresh review rather than silently updating ownership.

There is deliberately no automatic uninstall or firewall restore: those could
run package cleanup or overwrite concurrent Kubernetes/Docker state. Leave an
interrupted installation inactive behind its gate while diagnosing it.

Enrollment is a separate operation. It must validate this exact ownership,
remove the preparation gate deliberately, preserve the existing administration
path and use the restricted Headscale tags. Its network flags must be explicit;
`--netfilter-mode=off` avoids automatic firewall hooks but still creates a TUN
interface and policy routes. Host connectivity alone does not prove legacy Pod
forwarding or source NAT. Verify those paths before changing DNS writers.

Official package and checksum: [Tailscale stable packages](https://pkgs.tailscale.com/stable/).
Firewall-mode semantics: [Tailscale netfilter modes](https://tailscale.com/docs/reference/netfilter-modes).
