#!/usr/bin/env python3
"""Explicit, single-fault injection with a local systemd rollback timer.

Installing or importing this file does nothing. Only arm/trigger mutate state.
The coordinator lock is never released merely because a timeout has elapsed.
"""
import argparse
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid
from common import ANNOTATION, NAMESPACE, OWNER, command, ensure_namespace, get, identity, kube, owned, require

ROOT = Path('/var/lib/infra-flux-fault-tests')
SCRIPT = Path('/etc/infra-flux/ha-tests/node-fault.py')
GLOBAL = 'active-fault'
UNITS = ('infra-headscale.service', 'infra-derper.service')
NFT = '/usr/sbin/nft'
NFT_PREFIX = 'infra_fault_'
NFT_PRIORITY = -450


def atomic(path, value):
    tmp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with tmp.open('x') as handle:
            os.chmod(tmp, 0o600)
            json.dump(value, handle, sort_keys=True)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def ssh_path_safe():
    fields = os.environ.get('SSH_CONNECTION', '').split()
    require(len(fields) == 4, 'An existing independent SSH session is required')
    client, _, server, _ = fields
    ipaddress.ip_address(client); ipaddress.ip_address(server)
    routes = json.loads(command(['/usr/sbin/ip', '-j', 'route', 'get', client, 'from', server]).stdout)
    require(routes and all(r.get('dev') and r['dev'] != 'tailscale0' for r in routes), 'SSH depends on the VPN being tested')
    return routes[0]['dev']


def recovery_gate(ca):
    spec = importlib.util.spec_from_file_location('recovery_gate', Path(__file__).with_name('recovery-gate.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.check(ca)


def read_state(token=None):
    state = json.loads((ROOT / 'active.json').read_text())
    require(state['owner'] == OWNER and (token is None or state['token'] == token), 'Fault ownership differs')
    identity(state['ca_sha256'], state['node'])
    return state


def global_state():
    return owned(get('configmap', GLOBAL, NAMESPACE))


def acquire_global(state):
    ensure_namespace()
    raw = kube(['get', 'configmap', GLOBAL, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json'])
    data = {'phase': 'active', 'token': state['token'], 'node': state['node'], 'kind': state['kind']}
    if raw.strip():
        current = owned(json.loads(raw))
        require(current['data'].get('phase') == 'free', 'Another fault or unverified recovery holds the global lock')
        current['data'] = data
        # resourceVersion makes competing acquisitions fail atomically.
        obj = json.loads(kube(['replace', '-f', '-', '-o', 'json'], current))
    else:
        obj = json.loads(kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': {'name': GLOBAL, 'namespace': NAMESPACE, 'annotations': {ANNOTATION: OWNER}}, 'data': data}))
    state['global_uid'] = obj['metadata']['uid']


def require_global(state):
    current = global_state()
    require(current['metadata']['uid'] == state['global_uid'] and current['data'].get('token') == state['token'] and current['data'].get('phase') == 'active', 'Global fault lock differs')
    return current


def rules(token):
    comment = 'infra-fault:' + token
    return [('INPUT', ['-i', 'tailscale0']), ('OUTPUT', ['-o', 'tailscale0']),
            ('FORWARD', ['-i', 'tailscale0']), ('FORWARD', ['-o', 'tailscale0'])], ['-m', 'comment', '--comment', comment, '-j', 'DROP']


def legacy_partition_remove(state):
    # Permit safe rollback of state armed by the older reviewed helper only.
    chains, suffix = rules(state['token'])
    for binary in state['firewalls']:
        for chain, interface in chains:
            exact = [chain, *interface, *suffix]
            result = command([binary, '-w', '5', '-C', *exact], check=False)
            require(result.returncode in (0, 1), 'Cannot inspect firewall rule')
            if result.returncode == 0:
                command([binary, '-w', '5', '-D', *exact])


def nft_name(state):
    require(re.fullmatch('[0-9a-f]{32}', state['token']), 'Invalid firewall ownership token')
    return NFT_PREFIX + state['token']


def nft_batch(state):
    table, comment = nft_name(state), 'infra-fault:' + state['token']
    lines = [f'create table inet {table} {{ comment "{comment}"; }}']
    for hook in ('input', 'output', 'forward'):
        lines.append(f'add chain inet {table} {hook} {{ type filter hook {hook} priority {NFT_PRIORITY}; policy accept; }}')
        for direction in (('iifname', 'oifname') if hook == 'forward' else ('iifname',) if hook == 'input' else ('oifname',)):
            lines.append(f'add rule inet {table} {hook} {direction} "tailscale0" counter drop comment "{comment}"')
    return ('\n'.join(lines) + '\n').encode()


def nft_read(state):
    table = nft_name(state)
    tables = json.loads(command([NFT, '-j', 'list', 'tables'], timeout=5).stdout)['nftables']
    if not any(x.get('table', {}).get('name') == table and x['table'].get('family') == 'inet' for x in tables):
        return None
    objects = json.loads(command([NFT, '-j', 'list', 'table', 'inet', table], timeout=5).stdout)['nftables']
    headers = [x['table'] for x in objects if 'table' in x]
    require(len(headers) == 1, 'Unexpected fault-table identity')
    header = headers[0]
    require(header.get('name') == table and header.get('family') == 'inet' and
            header.get('comment') == 'infra-fault:' + state['token'], 'Refusing an unrelated nft table')
    handle = header.get('handle')
    require(type(handle) is int and handle > 0, 'Missing nft table handle')
    require(state.get('partition_table_handle', handle) == handle, 'Fault table was replaced')
    return objects


def nft_shape(state, objects):
    """Validate effective hooks and verdicts, not merely table existence."""
    if objects is None:
        return {'present': False, 'valid': False, 'counters': []}
    table, comment = nft_name(state), 'infra-fault:' + state['token']
    headers = [x['table'] for x in objects if 'table' in x]
    require(len(headers) == 1 and not headers[0].get('flags'), 'Fault table has unexpected flags')
    require(all(set(x) in ({'metainfo'}, {'table'}, {'chain'}, {'rule'}) for x in objects), 'Unexpected object in fault table')
    chains = [x['chain'] for x in objects if 'chain' in x]
    expected = [{'family': 'inet', 'table': table, 'name': hook, 'type': 'filter',
                 'hook': hook, 'prio': NFT_PRIORITY, 'policy': 'accept'} for hook in ('input', 'output', 'forward')]
    actual = [{k: v for k, v in c.items() if k != 'handle'} for c in chains]
    require(sorted(actual, key=lambda c: c.get('name', '')) == sorted(expected, key=lambda c: c['name']), 'Fault chain hooks or priorities changed')
    counters = []
    for hook in ('input', 'output', 'forward'):
        entries = [x['rule'] for x in objects if 'rule' in x and x['rule'].get('chain') == hook]
        directions = ('iifname', 'oifname') if hook == 'forward' else ('iifname',) if hook == 'input' else ('oifname',)
        require(len(entries) == len(directions), 'Fault rule count changed')
        for entry, direction in zip(entries, directions):
            require(entry.get('family') == 'inet' and entry.get('table') == table and entry.get('comment') == comment, 'Fault rule ownership changed')
            expr = entry.get('expr', [])
            require(len(expr) == 3 and expr[0] == {'match': {'op': '==', 'left': {'meta': {'key': direction}}, 'right': 'tailscale0'}} and
                    set(expr[1]) == {'counter'} and expr[2] == {'drop': None}, 'Fault rule no longer exclusively drops tailscale0')
            counter = expr[1]['counter']
            require(set(counter) == {'packets', 'bytes'} and all(type(v) is int and v >= 0 for v in counter.values()), 'Invalid fault counters')
            counters.append({'hook': hook, 'direction': direction, **counter})
    require(sum('rule' in x for x in objects) == 4, 'Unexpected additional rule')
    return {'present': True, 'valid': True, 'table': table, 'handle': headers[0]['handle'], 'counters': counters}


def nft_preflight(state):
    command([NFT, '--version'], timeout=5)
    objects = json.loads(command([NFT, '-j', 'list', 'ruleset'], timeout=10).stdout)['nftables']
    require(not any('flowtable' in x for x in objects), 'Flowtables can bypass the forward hook; refuse this partition test')
    require(not any(x.get('table', {}).get('name', '').startswith(NFT_PREFIX) for x in objects), 'An existing fault table needs explicit recovery first')
    command([NFT, '--check', '--file', '-'], input=nft_batch(state), timeout=5)


def partition(state, remove=False):
    if state.get('partition_backend') != 'nft-inet-v1':
        require(remove and 'firewalls' in state, 'Re-arm with the nft partition helper')
        return legacy_partition_remove(state)
    objects = nft_read(state)
    if remove:
        if objects is not None:
            # A changed rule must not prevent restoration of our owned table.
            # Its name, token comment and (once recorded) handle were checked.
            try: state['partition_before_rollback'] = nft_shape(state, objects)
            except RuntimeError as error: state['partition_before_rollback'] = {'valid': False, 'error': str(error)}
            handle = next(x['table']['handle'] for x in objects if 'table' in x)
            command([NFT, 'delete', 'table', 'inet', 'handle', str(handle)], timeout=5)
            require(nft_read(state) is None, 'Fault table still exists after rollback')
        return
    require(objects is None, 'Fault table already exists; do not overwrite it')
    # create fails on a collision; nft submits the whole batch atomically.
    command([NFT, '--file', '-'], input=nft_batch(state), timeout=5)
    proof = nft_shape(state, nft_read(state))
    require(proof['valid'], 'Partition did not become effective')
    state.update(partition_table_handle=proof['handle'], partition_initial=proof, partition_applied_unix=time.time())
    atomic(ROOT / 'active.json', state)


def status(state):
    result = {**state, 'observed_unix': time.time(), 'current_boot_id': boot_id()}
    if state.get('partition_backend') == 'nft-inet-v1':
        try: result['partition_observation'] = nft_shape(state, nft_read(state))
        except RuntimeError as error: result['partition_observation'] = {'valid': False, 'error': str(error)}
    return result


def rollback(state):
    # A timer already queued behind finish's flock must not reopen a completed test.
    if state['phase'] == 'finished':
        return state
    if state['kind'] == 'vpn-partition':
        partition(state, remove=True)
    elif state['kind'] == 'service-stop':
        command(['/usr/bin/systemctl', 'start', state['unit']], timeout=45)
        command(['/usr/bin/systemctl', 'is-active', '--quiet', state['unit']])
    # Reboot has no software power-on rollback. It must return by normal boot.
    if state['kind'] == 'reboot':
        require(boot_id() != state['boot_id'] or state['phase'] in ('arming', 'armed', 'rolled-back'), 'Node has not completed its reboot')
    # finish restores idempotently too; retain the first completed restoration
    # rather than turning its later verification into the measured outage end.
    state.setdefault('rollback_unix', time.time())
    state.update(phase='rolled-back', current_boot_id=boot_id())
    atomic(ROOT / 'active.json', state)
    return state


def arm(args):
    node = identity(args.ca_sha256, args.node)['node_name']
    require(Path(__file__).resolve() == SCRIPT and SCRIPT.stat().st_uid == 0 and SCRIPT.stat().st_mode & 0o022 == 0, 'Install reviewed root-owned helper at its fixed path first')
    for path in (SCRIPT.parent, SCRIPT.parent / 'common.py', SCRIPT.parent / 'recovery-gate.py'):
        require(not path.is_symlink() and path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0, 'Helper dependencies must remain root-owned and unwritable by other users')
    route = ssh_path_safe()
    if (ROOT / 'active.json').exists():
        require(read_state()['phase'] == 'finished', 'Previous local fault has not passed recovery')
    if args.kind == 'service-stop':
        require(args.unit in UNITS, 'Only the selected overlay services may be stopped')
        command(['/usr/bin/systemctl', 'is-active', '--quiet', args.unit])
        command(['/usr/bin/systemctl', 'is-enabled', '--quiet', args.unit])
        if args.unit == 'infra-headscale.service':
            require(Path('/etc/infra-overlay/active-coordinator').is_file(), 'Only the actual active coordinator is eligible')
    else:
        require(args.unit is None, 'Unit is only valid for service-stop')
    if args.kind == 'reboot':
        require(args.confirm_reboot, 'Reboot requires its explicit confirmation')
        for unit in ('ssh.service', 'tailscaled.service', 'infra-k8s-api-proxy.service', 'kubelet.service'):
            command(['/usr/bin/systemctl', 'is-enabled', '--quiet', unit])
    if args.kind == 'vpn-partition':
        command(['/usr/sbin/ip', 'link', 'show', 'dev', 'tailscale0'])
    proof = recovery_gate(args.ca_sha256)
    token = uuid.uuid4().hex
    state = {'owner': OWNER, 'token': token, 'node': node, 'kind': args.kind, 'unit': args.unit,
             'ca_sha256': args.ca_sha256, 'boot_id': boot_id(), 'ssh_device': route,
             'phase': 'arming', 'armed_unix': time.time(),
             'rollback_after_seconds': args.seconds, 'preflight': proof}
    if args.kind == 'vpn-partition':
        state['partition_backend'] = 'nft-inet-v1'
        nft_preflight(state)
    acquire_global(state)
    atomic(ROOT / 'active.json', state)
    timer = 'infra-fault-rollback-' + token
    state['timer'] = timer
    atomic(ROOT / 'active.json', state)
    try:
        command(['/usr/bin/systemd-run', '--unit=' + timer, '--on-active=' + str(args.seconds) + 's',
                 '--timer-property=AccuracySec=1s', '--property=Type=oneshot', '--property=TimeoutStartSec=60s',
                 '--property=Restart=on-failure', '--property=RestartSec=5s', '--property=StartLimitIntervalSec=0',
                 '/usr/bin/python3', str(SCRIPT), 'rollback', '--token', token])
        command(['/usr/bin/systemctl', 'is-active', '--quiet', timer + '.timer'])
        due = command(['/usr/bin/systemctl', 'show', timer + '.timer', '--property=NextElapseUSecMonotonic', '--value']).stdout.strip()
        require(due and due not in (b'0', b'infinity', b'n/a'), 'Rollback timer is not scheduled')
        state['phase'] = 'armed'; atomic(ROOT / 'active.json', state)
    except BaseException:
        rollback(state)
        raise
    return state


def trigger(state):
    require(state['phase'] == 'armed', 'Fault is not freshly armed')
    require(time.time() - state['armed_unix'] < min(30, state['rollback_after_seconds'] / 2), 'Arm expired; roll back and finish before retrying')
    require(boot_id() == state['boot_id'], 'Node rebooted since arming')
    ssh_path_safe(); require_global(state)
    command(['/usr/bin/systemctl', 'is-active', '--quiet', state['timer'] + '.timer'])
    state.update(phase='triggered', triggered_unix=time.time()); atomic(ROOT / 'active.json', state)
    try:
        if state['kind'] == 'vpn-partition':
            partition(state)
        elif state['kind'] == 'service-stop':
            command(['/usr/bin/systemctl', 'stop', state['unit']], timeout=20)
            require(command(['/usr/bin/systemctl', 'is-active', '--quiet', state['unit']], check=False).returncode != 0, 'Service did not stop')
        else:
            command(['/usr/bin/systemctl', 'reboot', '--no-block'])
    except BaseException:
        rollback(state)
        raise
    return state


def finish(state):
    # A reboot can remove transient systemd units, but the persistent lock remains.
    state = rollback(state)
    proof = recovery_gate(state['ca_sha256'])
    current = require_global(state)
    current['data']['phase'] = 'free'
    kube(['replace', '-f', '-', '-o', 'json'], current)
    command(['/usr/bin/systemctl', 'stop', state['timer'] + '.timer'], check=False)
    state.update(phase='finished', recovery=proof, finished_unix=time.time())
    atomic(ROOT / 'active.json', state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['arm', 'trigger', 'rollback', 'finish', 'status'])
    parser.add_argument('--ca-sha256')
    parser.add_argument('--node', choices=['home', 'msk', 'fin'])
    parser.add_argument('--kind', choices=['service-stop', 'vpn-partition', 'reboot'])
    parser.add_argument('--unit', choices=UNITS)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--confirm-reboot', action='store_true')
    parser.add_argument('--token')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root is required')
    if args.action == 'arm':
        require(args.ca_sha256 and args.node and args.kind and 60 <= args.seconds <= 300, 'Explicit identity/kind and 60–300 second bound required')
        identity(args.ca_sha256, args.node)
    os.umask(0o077)
    require(not ROOT.is_symlink(), 'State directory is a symlink')
    if not ROOT.exists():
        require(args.action == 'arm', 'No armed fault exists')
        ROOT.mkdir(mode=0o700)
        atomic(ROOT / 'owner.json', {'owner': OWNER})
    require(json.loads((ROOT / 'owner.json').read_text()) == {'owner': OWNER}, 'Unrelated state directory')
    require(ROOT.stat().st_uid == 0 and ROOT.stat().st_mode & 0o077 == 0, 'State directory must remain private and root-owned')
    with (ROOT / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'arm':
            require(args.ca_sha256 and args.node and args.kind and 60 <= args.seconds <= 300, 'Explicit identity/kind and 60–300 second bound required')
            result = arm(args)
        else:
            require(args.token, 'Explicit fault token required')
            state = read_state(args.token)
            result = {'trigger': trigger, 'rollback': rollback, 'finish': finish, 'status': status}[args.action](state)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
