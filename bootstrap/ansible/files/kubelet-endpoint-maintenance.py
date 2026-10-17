#!/usr/bin/env python3
"""Endpoint-only kubelet maintenance. Inspection is read-only; restart dispatch is never retried."""
import argparse
import base64
import copy
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import time
import types
import uuid

OWNER = 'infra-flux/kubelet-endpoint-v1'
ROOT = Path('/etc/infra-flux/kubelet-endpoint-maintenance')
CONFIG = Path('/etc/kubernetes/kubelet.conf')
BOOTSTRAP = Path('/etc/infra-flux/kubeadm-state.json')
ENDPOINT = 'https://api.unified.internal:7443'
VERSION = 'v1.36.5'
COMMON_SHA = '80c9671bd4c529cf544aca9cd90bc285890428282c2af17eb237331dbdbf0a26'
CERT = '/var/lib/kubelet/pki/kubelet-client-current.pem'
CRI = ['/usr/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock']
common = None


def require(value, message):
    if not value: raise RuntimeError(message)


def sha(value): return hashlib.sha256(value).hexdigest()


def load_common(source):
    # Reuse already reviewed atomic I/O, CAS lock and etcd-health implementation.
    # Never import an arbitrary remote path or silently accept a changed helper.
    global common
    require(sha(source.encode()) == COMMON_SHA, 'Shared helper changed; review its new revision first')
    common = types.ModuleType('reviewed_etcd_maintenance')
    exec(compile(source, '<reviewed-etcd-helper>', 'exec'), common.__dict__)
    common.OWNER = OWNER; common.ROOT = ROOT; common.kube = kube


def command(argv, payload=None, timeout=10):
    return common.command(argv, payload, timeout)


def kube(args, payload=None, node_credentials=False):
    return command(['/usr/bin/kubectl', '--kubeconfig=' + str(CONFIG if node_credentials else '/etc/kubernetes/admin.conf'),
                    '--server=' + ENDPOINT, '--request-timeout=5s', *args],
                   None if payload is None else json.dumps(payload).encode())


def get(kind, name, namespace=None, node_credentials=False):
    return json.loads(kube(['get', kind, name, *(['-n', namespace] if namespace else []), '-o', 'json'], node_credentials=node_credentials))


def decode(raw):
    # --raw is captured in memory only. Never return or log kubeconfig credentials.
    return json.loads(command(['/usr/bin/kubectl', 'config', 'view', '--raw', '--kubeconfig=/dev/stdin', '-o', 'json'], raw))


def config_shape(obj, ca):
    require(obj.get('apiVersion') == 'v1' and obj.get('kind') == 'Config' and
            len(obj.get('clusters', [])) == len(obj.get('users', [])) == len(obj.get('contexts', [])) == 1, 'Unexpected kubeconfig topology')
    cluster = obj['clusters'][0]; user = obj['users'][0]; context = obj['contexts'][0]
    require(obj.get('current-context') == context['name'] and context['context'].get('cluster') == cluster['name'] and
            context['context'].get('user') == user['name'], 'Kubeconfig context does not bind its sole cluster/user')
    require(set(cluster['cluster']) == {'server', 'certificate-authority-data'}, 'Unexpected TLS, proxy or cluster settings')
    require(sha(base64.b64decode(cluster['cluster']['certificate-authority-data'], validate=True)) == ca, 'Kubelet CA differs')
    require(user['user'] == {'client-certificate': CERT, 'client-key': CERT}, 'Preserve the reviewed rotating kubelet certificate paths')
    return cluster['cluster']['server']


def patch_config(raw, before, ca):
    old = config_shape(before, ca)
    pattern = re.compile(rb'^(    server: )([^\r\n]+)(\r?)$', re.M)
    entries = list(pattern.finditer(raw))
    require(len(entries) == 1 and entries[0][2].decode() == old, 'Unexpected server scalar syntax')
    candidate = pattern.sub(lambda m: m[1] + ENDPOINT.encode() + m[3], raw)
    after = decode(candidate); expected = copy.deepcopy(before)
    expected['clusters'][0]['cluster']['server'] = ENDPOINT
    require(after == expected, 'Candidate differs outside the server scalar')
    return candidate


def service(name):
    output = command(['/usr/bin/systemctl', 'show', name, '--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,After,Requires']).decode()
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def process_identity(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    return {'pid': pid, 'start_ticks': int(raw[raw.rfind(')') + 2:].split()[19])}


def validate_kubelet_argv(argv):
    require(not any(a in (b'--kubeconfig', b'--bootstrap-kubeconfig') for a in argv) and
            sum(a.startswith(b'--bootstrap-kubeconfig=') for a in argv) <= 1, 'Duplicate or split kubelet credential arguments')
    require(argv[0] == b'/usr/bin/kubelet' and argv.count(b'--kubeconfig=/etc/kubernetes/kubelet.conf') == 1 and
            not any(a.startswith((b'--kubeconfig=', b'--bootstrap-kubeconfig=')) and a not in
                    (b'--kubeconfig=/etc/kubernetes/kubelet.conf', b'--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf') for a in argv), 'Unexpected kubelet credential arguments')


def kubelet_process():
    unit = service('kubelet.service'); pid = int(unit['MainPID'])
    require(unit['ActiveState'] == 'active' and unit['SubState'] == 'running' and pid > 1, 'Kubelet is not active')
    argv = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
    validate_kubelet_argv(argv)
    require('infra-k8s-api-proxy.service' in unit['After'].split() and 'infra-k8s-api-proxy.service' in unit['Requires'].split(), 'Kubelet is not ordered after the owned API proxy')
    return {**process_identity(pid), 'start_monotonic_us': int(unit['ExecMainStartTimestampMonotonic'])}


def workloads():
    deadline = time.monotonic() + 20
    containers = json.loads(command(CRI + ['ps', '-o', 'json'], timeout=5))['containers']
    require(len(containers) <= 128, 'Review a larger running-container inventory')
    result = {}
    for container in containers:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Running-container inventory exceeded its 20-second bound')
        require(container['state'] == 'CONTAINER_RUNNING', 'Unexpected CRI running-container response')
        obj = json.loads(command(CRI + ['inspect', '-o', 'json', container['id']], timeout=min(3, remaining)))
        pid = int(obj['info']['pid']); result[container['id']] = process_identity(pid)
    require(result, 'No running containers found')
    return result


def lease(node):
    obj = get('lease', node, 'kube-node-lease', node_credentials=True)
    require(obj['spec']['holderIdentity'] == node, 'Unexpected NodeLease holder')
    return {'uid': obj['metadata']['uid'], 'renew_time': obj['spec']['renewTime']}


def lease_time(value): return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def read_record():
    if not ROOT.exists():
        require(not ROOT.is_symlink(), 'Maintenance directory is a symlink'); return None
    st = ROOT.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Untrusted maintenance directory')
    record = json.loads(common.trusted(ROOT / 'record.json', True))
    require(record.get('phase') in ('prepared', 'config-written', 'restart-intent', 'verified'), 'Unknown maintenance phase')
    require(record.get('owner') == OWNER and re.fullmatch('[0-9a-f]{32}', record.get('token', '')), 'Unknown maintenance owner')
    require(sha(common.trusted(ROOT / 'kubelet.before.conf', True)) == record['before_sha256'] and
            sha(common.trusted(ROOT / 'bootstrap.before.json', True)) == record['bootstrap_sha256'], 'Private preimage changed')
    return record


def inspect(node, expected_ca=None):
    marker_raw = common.trusted(BOOTSTRAP, True); marker = json.loads(marker_raw)
    require(marker.get('managed_by') == 'infra-flux/ansible/kubeadm' and marker.get('cluster_name') == 'unified' and
            marker.get('node_name') == node and node in common.NODES, 'Wrong node or bootstrap owner')
    ca = sha(common.trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(marker.get('ca_sha256') == ca and (expected_ca is None or expected_ca == ca), 'Wrong cluster CA')
    require({x[4][0] for x in socket.getaddrinfo('api.unified.internal', 7443, type=socket.SOCK_STREAM)} == {'127.0.0.1'}, 'API name must resolve only to the node-local proxy')
    require(service('infra-k8s-api-proxy.service')['ActiveState'] == 'active', 'Owned API proxy is not active')
    raw = common.trusted(CONFIG, True); config_stat = CONFIG.lstat()
    require(config_stat.st_gid == 0 and stat.S_IMODE(config_stat.st_mode) == 0o600, 'Expected root:root 0600 kubeconfig')
    obj = decode(raw); current = config_shape(obj, ca)
    require(current in (ENDPOINT, 'https://' + marker['vpn_ipv4'] + ':6443'), 'Unexpected current kubelet endpoint')
    cert = Path(CERT); target = cert.resolve(strict=True)
    require(cert.is_symlink() and target.parent == cert.parent and target.name.startswith('kubelet-client-'), 'Unexpected rotating certificate target')
    common.trusted(target, True)
    subject = command(['/usr/bin/openssl', 'x509', '-in', CERT, '-noout', '-subject', '-nameopt', 'RFC2253']).decode().strip()
    require(set(subject.removeprefix('subject=').split(',')) == {'CN=system:node:' + node, 'O=system:nodes'}, 'Kubelet certificate belongs to another identity')
    host = get('node', node, node_credentials=True)  # TLS SAN/CA + existing node credentials, through HAProxy.
    require(any(a['type'] == 'InternalIP' and a['address'] == marker['vpn_ipv4'] for a in host['status']['addresses']), 'Node VPN address differs')
    candidate = patch_config(raw, obj, ca); record = read_record()
    require(record is not None or current != ENDPOINT, 'Target endpoint without an owned record requires explicit adoption review')
    proof = {'node': node, 'node_uid': host['metadata']['uid'], 'machine_id': common.trusted(Path('/etc/machine-id')).decode().strip(),
             'ca_sha256': ca, 'bootstrap_sha256': sha(marker_raw), 'config_sha256': sha(raw), 'candidate_sha256': sha(candidate),
             'server': current, 'desired': ENDPOINT, 'changed': raw != candidate}
    if record:
        for field in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256'):
            require(record[field] == proof[field], 'Maintenance identity differs: ' + field)
        require(record['after_sha256'] == sha(candidate) and sha(raw) in (record['before_sha256'], record['after_sha256']), 'Kubeconfig changed outside this maintenance')
    return proof, raw, candidate, marker_raw, record


def health(node):
    result = common.health(node)
    nodes = json.loads(kube(['get', 'nodes', '-o', 'json']))['items']
    require(all(n['status']['nodeInfo']['kubeletVersion'] == VERSION for n in nodes), 'Review version skew before maintenance')
    for host in nodes:
        ip = next(a['address'] for a in host['status']['addresses'] if a['type'] == 'InternalIP')
        require(json.loads(kube(['--server=https://' + ip + ':6443', 'get', '--raw=/version']))['gitVersion'] == VERSION, 'All API versions must match the reviewed kubelet version')
    require(command(['/usr/bin/kubelet', '--version']).decode().strip() == 'Kubernetes ' + VERSION, 'Local kubelet binary version differs')
    return result


def restart_once(record):
    # Durable intent precedes dispatch. A timeout/SSH loss is an UNKNOWN outcome:
    # resumed calls only observe the PID/lease and NEVER dispatch restart again.
    if record['phase'] == 'config-written':
        require(kubelet_process() == record['kubelet_before'], 'Kubelet changed before restart dispatch')
        record['phase'] = 'restart-intent'; record['dispatch_unix'] = time.time(); common.save_record(record)
        try:
            command(['/usr/bin/systemctl', '--no-block', 'restart', 'kubelet.service'], timeout=8)
            record['dispatch_status'] = 'accepted'
        except (RuntimeError, subprocess.TimeoutExpired):
            record['dispatch_status'] = 'unknown'
        common.save_record(record)


def validate_recovery(record, process, current_lease, current_workloads):
    require(process != record['kubelet_before'] and process['start_monotonic_us'] > record['kubelet_before']['start_monotonic_us'], 'Waiting for a new kubelet process')
    require(current_lease['uid'] == record['lease_before']['uid'] and
            lease_time(current_lease['renew_time']) > max(lease_time(record['lease_before']['renew_time']), record['dispatch_unix']), 'Waiting for the same NodeLease to renew after restart dispatch')
    if record.get('observed_new_process'):
        require(process == record['observed_new_process'] and lease_time(current_lease['renew_time']) >
                lease_time(record['observed_new_lease']['renew_time']), 'Waiting for a lease renewal after observing the new kubelet process')
    require(all(current_workloads.get(cid) == pid for cid, pid in record['workloads_before'].items()), 'A previously running workload exited or changed PID; retain the lock for review')


def validate_review(proof, review_json):
    expected_identity = json.loads(review_json or '{}')
    fields = ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')
    require(set(expected_identity) == set(fields) and all(expected_identity[k] == proof[k] for k in fields), 'Reviewed node/CA/bootstrap identity differs')


def apply(args):
    proof, before, candidate, marker, record = inspect(args.node, args.ca_sha256)
    require(re.fullmatch('[0-9a-f]{64}', args.expected_sha256 or ''), 'Reviewed per-node kubeconfig SHA256 required')
    require(args.expected_sha256 == proof['config_sha256'] or (record and args.expected_sha256 == record['before_sha256']), 'Reviewed kubeconfig preimage differs')
    validate_review(proof, args.review_json)
    common.lock_available(record)
    # On a resumed UNKNOWN dispatch, do not require kubelet to be healthy before observing it.
    prior = health(args.node) if record is None or record['phase'] in ('prepared', 'config-written', 'verified') else None
    if record is None:
        process = kubelet_process(); old_lease = lease(args.node); running = workloads()
        ROOT.mkdir(mode=0o700)
        common.atomic(ROOT / 'kubelet.before.conf', before); common.atomic(ROOT / 'bootstrap.before.json', marker)
        record = {**{k: proof[k] for k in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')},
                  'owner': OWNER, 'token': uuid.uuid4().hex, 'before_sha256': sha(before), 'after_sha256': sha(candidate),
                  'member_ids': prior['member_ids'], 'kubelet_before': process, 'lease_before': old_lease,
                  'workloads_before': running, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'phase': 'prepared'}
        common.save_record(record)
    require(record['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() or record['phase'] == 'verified', 'Host rebooted during unfinished maintenance; manual review required')
    if prior: require(record['member_ids'] == prior['member_ids'], 'etcd membership changed')
    if record['phase'] == 'verified':
        require(before == candidate, 'Verified kubeconfig was reverted; review an explicit new maintenance generation after upgrade')
        held = common.fault_lock()
        if held and held['data'].get('phase') == 'active': common.release(record)
        return {**proof, 'health': prior, 'already_verified': True}
    common.acquire(record)
    require(common.trusted(CONFIG, True) == before and common.trusted(BOOTSTRAP, True) == marker, 'Preimage changed after inspection')
    if record['phase'] == 'prepared':
        if before != candidate: common.atomic(CONFIG, candidate)
        record['phase'] = 'config-written'; common.save_record(record)
    restart_once(record)
    deadline = time.monotonic() + 300; stable_since = None; last_error = None
    while time.monotonic() < deadline:
        try:
            require(common.trusted(CONFIG, True) == candidate and common.trusted(BOOTSTRAP, True) == marker, 'Config or bootstrap changed during recovery')
            process = kubelet_process(); current_lease = lease(args.node)
            validate_recovery(record, process, current_lease, workloads())
            if not record.get('observed_new_process'):
                record['observed_new_process'] = process; record['observed_new_lease'] = current_lease
                common.save_record(record)
                continue
            after = health(args.node); require(after['member_ids'] == record['member_ids'], 'etcd membership changed during recovery')
            if stable_since is None: stable_since = time.monotonic()
            if time.monotonic() - stable_since >= 30:
                record['phase'] = 'verified'; record['verified_unix'] = time.time()
                record['kubelet_after'] = process; record['lease_after'] = current_lease
                # Save proof before releasing; a crash after release is safe to inspect.
                common.save_record(record); common.release(record)
                return {**proof, 'changed': True, 'health': after, 'lease_advanced': True, 'workload_pids_preserved': True, 'stable_seconds': 30}
        except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as error:
            last_error = str(error); stable_since = None
        time.sleep(3)
    raise RuntimeError('Recovery unverified; lock retained, restart will NOT be retried. Inspect before resume: ' + str(last_error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'apply']); parser.add_argument('--node', choices=['home', 'msk', 'fin'], required=True)
    parser.add_argument('--ca-sha256'); parser.add_argument('--expected-sha256'); parser.add_argument('--shared-source', required=True); parser.add_argument('--review-json')
    args = parser.parse_args(); require(os.geteuid() == 0, 'Run as root on the owned node'); load_common(args.shared_source)
    if args.action == 'inspect':
        proof, *_, record = inspect(args.node, args.ca_sha256); common.lock_available(record)
        proof['health'] = health(args.node); proof['kubelet'] = kubelet_process(); proof['lease'] = lease(args.node)
        print(json.dumps(proof, sort_keys=True)); return
    require(args.ca_sha256, 'Apply requires the reviewed cluster CA')
    common.trusted(BOOTSTRAP, True)
    with BOOTSTRAP.open('rb') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(apply(args), sort_keys=True))


if __name__ == '__main__': main()
