#!/usr/bin/env python3
"""Bounded file-policy/SNI maintenance with a durable timed rollback.

No enrollment, route changes, service restart, database access or key rotation.
Apply and confirm use JSON stdin; rollback needs only its owned operation ID.
"""
import argparse
import base64
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid

OWNER = 'infra-flux/overlay-maintenance-v1'
ROOT = Path('/etc/infra-flux/overlay-maintenance')
OVERLAY = Path('/etc/infra-overlay')
HELPER = Path('/etc/infra-flux/overlay-maintenance.py')
SETTINGS = Path('/etc/infra-flux/overlay-settings.py')
HS = ['/usr/local/lib/infra-overlay/headscale-0.29.5', '--config', str(OVERLAY / 'headscale.yaml')]
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=5s']
PATHS = {'relay': OVERLAY / 'haproxy.cfg', 'policy': OVERLAY / 'policy.json'}
SERVICES = {'relay': 'infra-overlay-edge.service', 'policy': 'infra-headscale.service'}
HEADSCALE_SHA256 = 'e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def trusted(path, private=False):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & (0o077 if private else 0o022),
            'Untrusted owned file')
    return path.read_bytes()


def atomic(path, data, mode=0o600):
    require(not path.is_symlink(), 'Refuse symlink')
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def command(argv, payload=None, timeout=25):
    r = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout)
    require(r.returncode == 0, 'Command failed; inspect owned state privately')
    return r.stdout


def module():
    trusted(SETTINGS, True)
    spec = importlib.util.spec_from_file_location('overlay_settings', SETTINGS)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def service(kind):
    raw = command(['systemctl', 'show', SERVICES[kind], '--property=ActiveState,MainPID,ExecMainStartTimestampMonotonic,FragmentPath'])
    data = dict(line.split('=', 1) for line in raw.decode().splitlines())
    require(data['ActiveState'] == 'active' and int(data['MainPID']) > 0, 'Expected active owned service')
    require(data['FragmentPath'] == '/etc/systemd/system/' + SERVICES[kind], 'Service unit differs')
    data['unit_sha256'] = sha(trusted(Path(data['FragmentPath'])))
    process = Path('/proc') / data['MainPID']
    executable = HS[0] if kind == 'policy' else '/usr/sbin/haproxy'
    require(os.readlink(process / 'exe') == executable, 'Running executable differs')
    data['executable_sha256'] = sha(trusted(Path(executable)))
    args = (process / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    if kind == 'policy':
        require(args == HS + ['serve'] and data['executable_sha256'] == HEADSCALE_SHA256, 'Coordinator executable identity differs')
        data['config_sha256'] = sha(trusted(OVERLAY / 'headscale.yaml'))
    else:
        require(any(args[i:i + 2] == ['-f', str(PATHS['relay'])] for i in range(len(args))), 'Router config path differs')
    return data


def health(node):
    def kube(args): return command(KUBE + args)
    nodes = json.loads(kube(['get', 'nodes', '-o', 'json']))['items']
    require(len(nodes) == 3 and {n['metadata']['name'] for n in nodes} == {'home', 'msk', 'fin'}, 'Topology differs')
    addresses = []
    for n in nodes:
        require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions']), 'Node not Ready')
        address = next(a['address'] for a in n['status']['addresses'] if a['type'] == 'InternalIP')
        addresses.append(address)
        require(kube(['--server=https://' + address + ':6443', 'get', '--raw=/readyz']).strip() == b'ok', 'Direct API not ready')
    result = json.loads(kube(['-n', 'kube-system', 'exec', 'etcd-' + node, '--', 'etcdctl',
        '--dial-timeout=3s', '--command-timeout=5s', '--endpoints=' + ','.join('https://' + a + ':2379' for a in sorted(addresses)),
        '--cacert=/etc/kubernetes/pki/etcd/ca.crt', '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt',
        '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key', 'endpoint', 'health', '-w', 'json']))
    require(len(result) == 3 and all(x['health'] is True for x in result), 'etcd not healthy')
    return sorted(addresses)


def identity(settings):
    require(os.geteuid() == 0, 'Root required')
    bootstrap = json.loads(trusted(Path('/etc/infra-flux/kubeadm-state.json')))
    require(bootstrap['managed_by'] == 'infra-flux/ansible/kubeadm' and bootstrap['node_name'] == settings['node'], 'Node identity differs')
    ca = sha(trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(ca == bootstrap['ca_sha256'] == settings['ca_sha256'], 'CA differs')
    ns = json.loads(command(KUBE + ['get', 'namespace', 'kube-system', '-o', 'json']))
    require(ns['metadata']['uid'] == settings['cluster_uid'], 'Cluster identity differs')
    overlay = json.loads(trusted(Path('/etc/infra-flux/overlay.json')))
    require(overlay['owner'] == 'infra-flux/ansible/overlay', 'Overlay ownership differs')
    return overlay


def hs_nodes(require_online=True):
    nodes = json.loads(command(HS + ['nodes', 'list', '--output', 'json']))
    require(len(nodes) == 3, 'Exactly three existing VPN nodes required')
    if require_online:
        require(all(n.get('online') is True for n in nodes), 'Existing VPN nodes must be online')
    return sorted([{'id': n['id'], 'name': n['given_name'], 'ips': sorted(n['ip_addresses']), 'user': n['user']['id']}
                   for n in nodes], key=lambda n: n['id'])


def tls_health(host, address):
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection((address, 443), timeout=8), server_hostname=host)
    c = Connection(host, timeout=8)
    try:
        c.request('GET', '/health'); r = c.getresponse()
        require(r.status == 200 and len(r.read(16385)) <= 16384, 'Coordinator TLS health failed')
    finally: c.close()


def relay_config(before, old_address, new_address):
    old = '    server coordinator ' + old_address + ':8443 check\n'
    new = '    server coordinator ' + new_address + ':443 check\n'
    lines = before.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line == b'backend headscale\n']
    require(len(starts) == 1, 'Expected exactly one Headscale backend')
    start = starts[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i].startswith((b' ', b'\t', b'#'))), len(lines))
    require(sum(line.lstrip().startswith(b'server ') for line in lines[start:end]) == 1
            and lines[start:end].count(old.encode()) == 1
            and before.count(old.encode()) == 1, 'Expected exactly one inactive local coordinator backend')
    # All other frontends/backends remain byte-for-byte unchanged.
    return before.replace(old.encode(), new.encode(), 1)


def policy_shape(policy, core):
    """Only the reviewed three-node mesh and narrow legacy DNS capabilities."""
    require(set(policy) == {'tagOwners', 'acls', 'tests'}, 'Unexpected policy features')
    require(policy['tagOwners'] == {'tag:legacy-pdns-reader': ['infra@'], 'tag:legacy-pdns-writer': ['infra@']}, 'Tag owner differs')
    rules = policy['acls']; require(len(rules) == 4, 'Unexpected policy rules')
    require(set(rules[0]) == {'action', 'src', 'dst'} and rules[0]['action'] == 'accept'
            and sorted(rules[0]['src']) == core and sorted(rules[0]['dst']) == [a + ':*' for a in core], 'Core mesh differs')
    for rule, tag, protocol, port in zip(rules[1:], ['reader', 'reader', 'writer'], ['udp', 'tcp', 'tcp'], [5354, 5354, 18081]):
        require(set(rule) == {'action', 'src', 'dst', 'proto'} and rule['action'] == 'accept'
                and rule['src'] == ['tag:legacy-pdns-' + tag] and rule['proto'] == protocol, 'Legacy capability differs')
        require(len(rule['dst']) == 2 and all(d.rsplit(':', 1)[0] in core and d.endswith(':' + str(port)) for d in rule['dst']), 'Legacy destination differs')
    # Every legacy rule must target the same two distinct edges.
    edges = sorted(d.rsplit(':', 1)[0] for d in rules[1]['dst'])
    require(len(set(edges)) == 2 and all(sorted(d.rsplit(':', 1)[0] for d in r['dst']) == edges for r in rules[2:]), 'Edge membership differs')
    require(isinstance(policy['tests'], list) and policy['tests'], 'Existing-peer tests required')
    return edges


def record_path(token):
    require(re.fullmatch('[0-9a-f]{32}', token), 'Invalid operation ID')
    return ROOT / (token + '.json')


def save(record):
    atomic(record_path(record['id']), canonical(record))


def load(token):
    r = json.loads(trusted(record_path(token), True))
    require(r['owner'] == OWNER and r['id'] == token and r['kind'] in PATHS, 'Operation identity differs')
    require(sha(base64.b64decode(r['before'], validate=True)) == r['before_sha256'] and sha(base64.b64decode(r['after'], validate=True)) == r['after_sha256'], 'Operation content differs')
    return r


def reload(kind):
    if kind == 'relay': command(['systemctl', 'reload', SERVICES[kind]])
    else: command(['systemctl', 'kill', '--kill-whom=main', '--signal=HUP', SERVICES[kind]])


def rollback(record):
    if record['phase'] in ('confirmed', 'rolled-back'):
        return {'phase': record['phase'], 'changed': False}
    kind = record['kind']; current = trusted(PATHS[kind])
    require(sha(current) in (record['before_sha256'], record['after_sha256']), 'Config changed independently; refuse overwrite')
    if kind == 'policy':
        # Never restore an old broad policy after a new client has enrolled.
        require(hs_nodes(require_online=False) == record['vpn_nodes'], 'VPN membership changed; refuse broad-policy rollback')
    require(service(kind) == record['service'], 'Service identity changed; inspect before rollback')
    record['phase'] = 'rolling-back'; save(record)
    if kind == 'relay':
        marker = OVERLAY / 'coordinator-relay.json'
        if marker.exists():
            require(trusted(marker, True) == base64.b64decode(record['relay_record']), 'Relay marker changed')
            marker.unlink()
    atomic(PATHS[kind], base64.b64decode(record['before']), 0o644)
    reload(kind)
    require(service(kind) == record['service'], 'Service identity changed during rollback')
    record['phase'] = 'rolled-back'; save(record)
    return {'phase': record['phase'], 'changed': True}


def apply(settings):
    kind = settings['kind']; require(kind in PATHS, 'Unsupported maintenance kind')
    overlay = identity(settings); node = settings['node']
    require(overlay['coordinator'] is (kind == 'policy'), 'Wrong coordinator role for operation')
    require(sha(trusted(HELPER, True)) == settings['helper_sha256'], 'Helper differs')
    require(sha(trusted(SETTINGS, True)) == settings['settings_sha256'], 'Settings validator differs')
    core = health(node); before = trusted(PATHS[kind])
    require(sha(before) == settings['expected_before_sha256'], 'Reviewed preimage differs')
    r = {'owner': OWNER, 'id': uuid.uuid4().hex, 'kind': kind, 'node': node, 'phase': 'prepared',
         'cluster_uid': settings['cluster_uid'], 'ca_sha256': settings['ca_sha256'],
         'created_at': time.time(), 'service': service(kind), 'before': base64.b64encode(before).decode(), 'before_sha256': sha(before)}
    if kind == 'relay':
        require(not (OVERLAY / 'coordinator-relay.json').exists() and not (OVERLAY / 'active-coordinator').exists(), 'Standby already activated or relay already owned')
        local = json.loads(command(['ip', '-j', '-4', 'address', 'show']))
        local_ips = [a['local'] for iface in local for a in iface.get('addr_info', [])]
        rec = settings['relay_record']
        upstream = module().validate_relay_record(rec, local_host=node, active_host=settings['active_host'], server_url=settings['server_url'],
            local_ipv4=local_ips, namespace_addresses=[overlay['namespace_host'], overlay['namespace_service']], tailnet_prefix=overlay['tailnet_prefix'])
        host = settings['server_url'].removeprefix('https://')
        tls_health(host, upstream)
        after = relay_config(before, overlay['namespace_service'].split('/')[0], upstream)
        r.update(relay_record=base64.b64encode(canonical(rec)).decode(), server_host=host)
        check = ROOT / (r['id'] + '.cfg'); atomic(check, after)
        try: command(['haproxy', '-c', '-f', str(check)])
        finally: check.unlink()
    else:
        require((OVERLAY / 'active-coordinator').is_file(), 'Active coordinator fence absent')
        require(r['service']['config_sha256'] == settings['expected_headscale_config_sha256'], 'Reviewed coordinator configuration differs')
        policy = module().validate_policy(settings['policy']); edges = policy_shape(policy, core)
        # Bind edge destinations to actual VPS node identities, not any two nodes.
        nodes = json.loads(command(KUBE + ['get', 'nodes', '-o', 'json']))['items']
        expected_edges = sorted(next(a['address'] for a in n['status']['addresses'] if a['type']=='InternalIP') for n in nodes if n['metadata']['name'] in ('msk','fin'))
        require(edges == expected_edges, 'Policy targets differ from physical VPS nodes')
        r['vpn_nodes'] = hs_nodes()
        require(sorted(ip for n in r['vpn_nodes'] for ip in n['ips']) == core, 'VPN/cluster membership differs')
        after = canonical(policy)
        checked = command(HS + ['policy', 'check', '--file', '/dev/stdin'], after)
        require(checked.strip() == b'Policy is valid', 'Policy validation did not succeed')
    r.update(after=base64.b64encode(after).decode(), after_sha256=sha(after))
    require(before != after, 'Already configured; no update needed')
    for previous in ROOT.glob('*.json'):
        require(load(previous.stem)['phase'] in ('confirmed', 'rolled-back'), 'An operation remains unresolved')
    save(r)
    command(['systemd-run', '--unit=infra-overlay-rollback-' + r['id'], '--on-active=180s', '--timer-property=AccuracySec=1s',
             '/usr/bin/python3', str(HELPER), 'rollback', '--operation', r['id']])
    require(command(['systemctl', 'is-active', 'infra-overlay-rollback-' + r['id'] + '.timer']).strip() == b'active', 'Rollback timer not armed')
    r['phase'] = 'armed'; save(r)
    try:
        require(sha(trusted(PATHS[kind])) == r['before_sha256'] and service(kind) == r['service'], 'Preimage or service changed before replacement')
        atomic(PATHS[kind], after, 0o644)
        if kind == 'relay': atomic(OVERLAY / 'coordinator-relay.json', base64.b64decode(r['relay_record']))
        reload(kind)
        require(service(kind) == r['service'], 'Main process changed unexpectedly')
        if kind == 'relay': tls_health(r['server_host'], '127.0.0.1')
        r['phase'] = 'applied'; save(r)
    except Exception:
        rollback(r)
        raise
    return {'operation': r['id'], 'phase': r['phase'], 'after_sha256': r['after_sha256'], 'rollback_after_seconds': 180}


def confirm(settings):
    r = load(settings['operation']); identity(settings)
    require(r['node'] == settings['node'] and r['cluster_uid'] == settings['cluster_uid'] and r['ca_sha256'] == settings['ca_sha256'], 'Confirmation identity differs')
    require(r['phase'] in ('applied', 'confirmed') and settings['expected_after_sha256'] == r['after_sha256'] == sha(trusted(PATHS[r['kind']])), 'Unverified operation outcome')
    require(service(r['kind']) == r['service'], 'Service identity changed')
    health(r['node'])
    if r['kind'] == 'policy': require(hs_nodes() == r['vpn_nodes'], 'VPN membership differs')
    else: tls_health(r['server_host'], '127.0.0.1')
    require(sha(trusted(PATHS[r['kind']])) == r['after_sha256'] and service(r['kind']) == r['service'], 'Config or service changed during confirmation')
    if r['kind'] == 'relay':
        require(trusted(OVERLAY / 'coordinator-relay.json', True) == base64.b64decode(r['relay_record'], validate=True), 'Relay marker changed during confirmation')
    # External tests are reviewed before this action. Mark durable confirmation
    # before cancelling the timer; a racing rollback then becomes a no-op.
    r['phase'] = 'confirmed'; r['confirmed_at'] = time.time(); save(r)
    command(['systemctl', 'stop', 'infra-overlay-rollback-' + r['id'] + '.timer'])
    return {'operation': r['id'], 'phase': 'confirmed', 'service_restarted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'confirm', 'rollback'))
    parser.add_argument('--operation')
    args = parser.parse_args(); os.umask(0o077)
    require(os.geteuid() == 0 and not ROOT.is_symlink(), 'Owned root required')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    require(ROOT.stat().st_uid == 0 and not ROOT.stat().st_mode & 0o077, 'Unsafe operation directory')
    fd = os.open(ROOT / 'lock', os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        st = os.fstat(lock.fileno()); require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Unsafe lock')
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = rollback(load(args.operation)) if args.action == 'rollback' else globals()[args.action](json.load(sys.stdin))
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'message': 'Stopped; inspect the owned operation and rollback timer before any retry.'}))
        sys.exit(1)
