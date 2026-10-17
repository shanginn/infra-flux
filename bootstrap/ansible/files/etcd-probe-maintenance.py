#!/usr/bin/env python3
"""Explicit, serial etcd startup-probe maintenance; inspect never writes state."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

OWNER = 'infra-flux/etcd-startup-probe-v1'
FAULT_OWNER = 'infra-flux/ha-tests-v1'
ANNOTATION = 'infra.shanginn.io/managed-by'
NAMESPACE = 'infra-ha-test'
LOCK = 'active-fault'
NODES = {'home', 'msk', 'fin'}
MANIFEST = Path('/etc/kubernetes/manifests/etcd.yaml')
BOOTSTRAP = Path('/etc/infra-flux/kubeadm-state.json')
ROOT = Path('/etc/infra-flux/etcd-probe-maintenance')
FIELDS = ('failureThreshold', 'periodSeconds', 'timeoutSeconds')
NATIVE = {'failureThreshold': 60, 'periodSeconds': 10, 'timeoutSeconds': 15}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted(path, private=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022), 'Untrusted file: ' + str(path))
    return path.read_bytes()


def atomic(path, data):
    # Dot-prefixed staging is ignored by kubelet; backups live outside manifests.
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def save_record(record):
    atomic(ROOT / 'record.json', (json.dumps(record, sort_keys=True) + '\n').encode())


def command(argv, payload=None, timeout=25):
    result = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'Command failed: ' + argv[0])
    return result.stdout


def kube(args, payload=None):
    return command(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=5s', *args],
                   None if payload is None else json.dumps(payload).encode())


def parse_manifest(data):
    # Use the installed Kubernetes decoder; no additional Python package needed.
    return json.loads(command(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=5s',
        'create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json'], data))


def validate_policy(values):
    require(set(values) == set(FIELDS) and all(type(v) is int and v > 0 for v in values.values()), 'Invalid probe settings')
    require(180 <= values['failureThreshold'] * values['periodSeconds'] <= 1800 and
            5 <= values['periodSeconds'] <= 30 and 1 <= values['timeoutSeconds'] <= min(10, values['periodSeconds']), 'Probe timing is outside reviewed bounds')


def validate_manifest(obj, node, vpn_ip, expected):
    require(obj.get('apiVersion') == 'v1' and obj.get('kind') == 'Pod' and obj['metadata'].get('name') == 'etcd' and
            obj['metadata'].get('namespace') == 'kube-system' and obj['metadata'].get('labels', {}).get('component') == 'etcd', 'Not an owned etcd static Pod')
    spec = obj['spec']; containers = spec.get('containers', [])
    require(spec.get('hostNetwork') is True and len(containers) == 1 and containers[0].get('name') == 'etcd' and not spec.get('initContainers'), 'Unexpected etcd container topology')
    container = containers[0]; args = container.get('command', [])
    require(args and args[0] == 'etcd' and args.count('--name=' + node) == 1 and args.count('--data-dir=/var/lib/etcd') == 1 and
            args.count('--listen-peer-urls=https://' + vpn_ip + ':2380') == 1, 'etcd identity, peer listener or data directory differs')
    require(container.get('image', '').startswith('registry.k8s.io/etcd:3.6.8-'), 'Review a new etcd image before changing its probe')
    probe = container.get('startupProbe', {})
    require(set(probe) in ({'httpGet', 'initialDelaySeconds', *FIELDS}, {'httpGet', 'initialDelaySeconds', 'successThreshold', *FIELDS}), 'Unexpected startup-probe fields')
    http = probe['httpGet']
    require(http.get('port') in (2381, 'probe-port') and http == {'host': '127.0.0.1', 'path': '/readyz', 'port': http.get('port'), 'scheme': 'HTTP'}, 'Unexpected startup endpoint')
    require(probe['initialDelaySeconds'] == 10 and probe.get('successThreshold', 1) == 1 and {key: probe[key] for key in FIELDS} == expected, 'Unexpected current probe timing')
    return probe


def patch_text(data, old_obj, values):
    """Preserve all original bytes except the three approved integer values."""
    text = data.decode()
    matches = list(re.finditer(r'^( *)startupProbe:\s*$', text, re.M))
    require(len(matches) == 1, 'Expected exactly one explicit startupProbe block')
    match = matches[0]; indent = len(match.group(1)); start = match.end()
    end = len(text)
    for line in re.finditer(r'^([^\n]*)$', text[start:], re.M):
        value = line.group(1)
        if value.strip() and len(value) - len(value.lstrip(' ')) <= indent:
            end = start + line.start(); break
    block = text[start:end]
    current = old_obj['spec']['containers'][0]['startupProbe']
    for key in FIELDS:
        pattern = re.compile(r'^( {' + str(indent + 2) + '}' + key + r': )([0-9]+)(\s*)$', re.M)
        entries = list(pattern.finditer(block))
        require(len(entries) == 1 and int(entries[0].group(2)) == current[key], 'Unexpected scalar syntax for ' + key)
        block = pattern.sub(lambda m: m.group(1) + str(values[key]) + m.group(3), block)
    return (text[:start] + block + text[end:]).encode()


def validate_only_probe_changed(before, after, values):
    expected = copy.deepcopy(before)
    expected['spec']['containers'][0]['startupProbe'].update(values)
    require(after == expected, 'Candidate changes content outside the three approved fields')


def read_record():
    if not ROOT.exists():
        require(not ROOT.is_symlink(), 'Maintenance directory is a symlink')
        return None
    info = ROOT.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'Maintenance directory is not private/root-owned')
    record = json.loads(trusted(ROOT / 'record.json', True))
    require(record.get('owner') == OWNER and re.fullmatch('[0-9a-f]{32}', record.get('token', '')), 'Unknown maintenance record')
    require(sha(trusted(ROOT / 'manifest.before.yaml', True)) == record['before_sha256'], 'Saved manifest preimage differs')
    require(sha(trusted(ROOT / 'bootstrap.before.json', True)) == record['bootstrap_sha256'], 'Saved bootstrap preimage differs')
    return record


def inspect(node, expected_ca, values):
    validate_policy(values)
    marker_raw = trusted(BOOTSTRAP, True); marker = json.loads(marker_raw)
    require(marker.get('managed_by') == 'infra-flux/ansible/kubeadm' and marker.get('cluster_name') == 'unified' and
            marker.get('node_name') == node and node in NODES, 'Cluster/node ownership mismatch')
    ca = sha(trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(ca == marker.get('ca_sha256') and (expected_ca is None or ca == expected_ca), 'Cluster CA differs')
    data = trusted(MANIFEST, True); record = read_record(); current_sha = sha(data)
    expected = NATIVE
    if record:
        require(record['node'] == node and record['ca_sha256'] == ca and record['bootstrap_sha256'] == sha(marker_raw) and record['values'] == values, 'Maintenance identity or policy changed')
        require(current_sha in (record['before_sha256'], record['after_sha256']), 'Manifest changed outside this maintenance')
        expected = values if current_sha == record['after_sha256'] else NATIVE
    obj = parse_manifest(data)
    validate_manifest(obj, node, marker['vpn_ipv4'], expected)
    candidate = patch_text(data, obj, values)
    validate_only_probe_changed(obj, parse_manifest(candidate), values)
    return {'node': node, 'ca_sha256': ca, 'bootstrap_sha256': sha(marker_raw), 'manifest_sha256': current_sha,
            'candidate_sha256': sha(candidate), 'current': expected, 'desired': values, 'changed': data != candidate}, data, candidate, marker_raw, record


def fault_lock():
    raw = kube(['get', 'configmap', LOCK, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json'])
    if not raw.strip(): return None
    obj = json.loads(raw)
    require(obj['metadata'].get('annotations', {}).get(ANNOTATION) == FAULT_OWNER, 'Unknown cluster maintenance/fault lock')
    return obj


def lock_available(record=None):
    obj = fault_lock()
    require(obj is None or obj['data'].get('phase') == 'free' or
            (record is not None and obj['data'].get('token') == record['token'] and obj['data'].get('kind') == OWNER and
             obj['data'].get('node') == record['node']), 'Another fault or maintenance holds the cluster lock')
    return obj


def acquire(record):
    current = lock_available(record)
    if current and record.get('global_uid'):
        require(current['metadata']['uid'] == record['global_uid'], 'Cluster lock was replaced')
    payload = {'phase': 'active', 'kind': OWNER, 'token': record['token'], 'node': record['node']}
    if current:
        if current['data'].get('token') == record['token'] and current['data'].get('phase') == 'active':
            record['global_uid'] = current['metadata']['uid']; save_record(record)
            return
        current['data'] = payload
        acquired = json.loads(kube(['replace', '-f', '-', '-o', 'json'], current))
    else:
        namespace = json.loads(kube(['get', 'namespace', NAMESPACE, '-o', 'json']))
        require(namespace['metadata'].get('annotations', {}).get(ANNOTATION) == FAULT_OWNER, 'Create the owned HA-test namespace before maintenance')
        acquired = json.loads(kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': LOCK, 'namespace': NAMESPACE, 'annotations': {ANNOTATION: FAULT_OWNER}}, 'data': payload}))
    record['global_uid'] = acquired['metadata']['uid']; save_record(record)


def release(record):
    current = fault_lock()
    require(current is not None and current['metadata'].get('uid') == record.get('global_uid') and current['data'].get('token') == record['token'] and current['data'].get('kind') == OWNER and current['data'].get('node') == record['node'], 'Cluster lock identity changed')
    current['data']['phase'] = 'free'
    kube(['replace', '-f', '-'], current)


def health(node):
    nodes = json.loads(kube(['get', 'nodes', '-o', 'json']))['items']
    require({n['metadata']['name'] for n in nodes} == NODES and len(nodes) == 3, 'Expected exactly three nodes')
    addresses = []
    for entry in nodes:
        require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in entry['status'].get('conditions', [])), 'A node is not Ready')
        address = next(a['address'] for a in entry['status']['addresses'] if a['type'] == 'InternalIP')
        addresses.append('https://' + address + ':2379')
        require(kube(['--server=https://' + address + ':6443', 'get', '--raw=/readyz']).strip() == b'ok', 'A direct API is not ready')
    prefix = ['exec', '-n', 'kube-system', 'etcd-' + node, '--', 'etcdctl', '--dial-timeout=3s', '--command-timeout=5s',
        '--endpoints=' + ','.join(sorted(addresses)), '--cacert=/etc/kubernetes/pki/etcd/ca.crt',
        '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt', '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key']
    endpoints = json.loads(kube(prefix + ['endpoint', 'health', '-w', 'json']))
    require(len(endpoints) == 3 and {e['endpoint'] for e in endpoints} == set(addresses) and all(e['health'] is True for e in endpoints), 'Three healthy etcd endpoints required')
    members = json.loads(kube(prefix + ['member', 'list', '-w', 'json']))['members']
    require(len(members) == 3 and {m['name'] for m in members} == NODES and all(not m.get('isLearner', False) for m in members), 'etcd membership differs')
    return {'nodes_ready': 3, 'api_ready': 3, 'etcd_healthy': 3, 'member_ids': sorted(m['ID'] for m in members)}


def runtime_probe(node, values):
    pod = json.loads(kube(['get', 'pod', 'etcd-' + node, '-n', 'kube-system', '-o', 'json']))
    require(pod['spec'].get('nodeName') == node and pod['metadata'].get('annotations', {}).get('kubernetes.io/config.source') == 'file', 'Unexpected etcd mirror Pod')
    containers = pod['spec'].get('containers', [])
    require(len(containers) == 1 and containers[0]['name'] == 'etcd' and
            {key: containers[0].get('startupProbe', {}).get(key) for key in FIELDS} == values, 'Kubelet has not adopted the new probe')
    statuses = pod['status'].get('containerStatuses', [])
    require(len(statuses) == 1 and statuses[0].get('ready') is True and statuses[0].get('started') is True and
            'running' in statuses[0].get('state', {}), 'Updated etcd container has not passed startup')
    return statuses[0]['containerID']


def apply(args, values):
    proof, before, candidate, marker, record = inspect(args.node, args.ca_sha256, values)
    require(re.fullmatch('[0-9a-f]{64}', args.expected_sha256 or ''), 'A reviewed per-node manifest SHA256 is required')
    require(args.expected_sha256 == proof['manifest_sha256'] or (record is not None and args.expected_sha256 == record['before_sha256']), 'Reviewed manifest preimage differs')
    lock_available(record)
    prior = health(args.node)
    if record is None:
        ROOT.mkdir(mode=0o700)
        atomic(ROOT / 'manifest.before.yaml', before)
        atomic(ROOT / 'bootstrap.before.json', marker)
        record = {'owner': OWNER, 'node': args.node, 'token': uuid.uuid4().hex, 'ca_sha256': proof['ca_sha256'],
                  'bootstrap_sha256': proof['bootstrap_sha256'], 'before_sha256': sha(before), 'after_sha256': sha(candidate),
                  'values': values, 'phase': 'prepared', 'member_ids': prior['member_ids']}
        save_record(record)
    require(record['member_ids'] == prior['member_ids'], 'etcd membership changed since preparation')
    acquire(record)
    # Recheck raw bytes immediately before replacement; never alter bootstrap state.
    require(trusted(MANIFEST, True) == before and trusted(BOOTSTRAP, True) == marker, 'Preimage changed after health checks')
    if before != candidate:
        atomic(MANIFEST, candidate)
    record['phase'] = 'applied'; save_record(record)
    deadline = time.monotonic() + 600
    last_error = None; stable_since = None
    while time.monotonic() < deadline:
        try:
            current, *_ = inspect(args.node, args.ca_sha256, values)
            require(not current['changed'] and current['manifest_sha256'] == record['after_sha256'], 'Applied manifest readback differs')
            after = health(args.node)
            require(after['member_ids'] == record['member_ids'], 'etcd membership changed during maintenance')
            after['container_id'] = runtime_probe(args.node, values)
            if stable_since is None: stable_since = time.monotonic()
            if time.monotonic() - stable_since >= 30:
                release(record)
                record['phase'] = 'verified'; record['verified_unix'] = time.time(); save_record(record)
                return {**current, 'changed': before != candidate, 'health': after, 'stable_seconds': 30}
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            last_error = str(error); stable_since = None
        time.sleep(5)
    raise RuntimeError('Recovery not verified; cluster lock retained. Inspect before retrying: ' + str(last_error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'apply'])
    parser.add_argument('--node', choices=sorted(NODES), required=True)
    parser.add_argument('--ca-sha256')
    parser.add_argument('--expected-sha256')
    parser.add_argument('--threshold', type=int, default=30)
    parser.add_argument('--period', type=int, default=10)
    parser.add_argument('--timeout', type=int, default=5)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Run as root on the owned node')
    values = dict(zip(FIELDS, (args.threshold, args.period, args.timeout)))
    if args.action == 'inspect':
        proof, *_, record = inspect(args.node, args.ca_sha256, values)
        lock_available(record); proof['health'] = health(args.node)
        print(json.dumps(proof, sort_keys=True)); return
    require(args.ca_sha256, 'Apply requires the reviewed cluster CA')
    # Lock a stable existing root-owned file; no unrelated path is created/adopted.
    trusted(BOOTSTRAP, True)
    with BOOTSTRAP.open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(json.dumps(apply(args, values), sort_keys=True))


if __name__ == '__main__': main()
