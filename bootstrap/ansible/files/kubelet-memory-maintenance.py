#!/usr/bin/env python3
"""One reviewed VPS memory-reservation change; inspect/readback never restart."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import tempfile
import time
import types
import uuid

import yaml

OWNER = 'infra-flux/kubelet-memory-v1'
ROOT = Path('/etc/infra-flux/kubelet-memory-maintenance')
CONFIG = Path('/var/lib/kubelet/config.yaml')
PATCH = Path('/etc/infra-flux/kubeadm/patches/kubeletconfiguration+merge.yaml')
INIT = Path('/etc/infra-flux/kubeadm/init.yaml')
TLS_RECORD = Path('/etc/infra-flux/kubelet-serving-tls/record.json')
BASE_SHA = '93bcb56f662d4b8e56b76235543c62f1465bbc9d5b1350417aa1867f7f6fd7f3'
IDENTITY = ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')
base = common = None


def require(ok, message):
    if not ok: raise RuntimeError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def load_helpers(endpoint_source, shared_source):
    global base, common
    require(sha(endpoint_source.encode()) == BASE_SHA, 'Endpoint helper changed')
    base = types.ModuleType('reviewed_memory_endpoint')
    exec(compile(endpoint_source, '<reviewed-endpoint>', 'exec'), base.__dict__)
    base.load_common(shared_source); common = base.common
    common.ROOT = ROOT; common.OWNER = OWNER


class StrictLoader(yaml.SafeLoader): pass


def mapping(loader, node, deep=False):
    pairs = loader.construct_pairs(node, deep=deep); value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate YAML key')
        value[key] = item
    return value


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def decode(raw):
    value = yaml.load(raw, Loader=StrictLoader)
    require(isinstance(value, dict) and value.get('apiVersion') == 'kubelet.config.k8s.io/v1beta1' and
            value.get('kind') == 'KubeletConfiguration', 'Unexpected kubelet configuration')
    require(value.get('systemReserved') == {'cpu': '1', 'memory': '4Gi'}, 'Expected exactly VPS CPU1/memory4Gi reservation')
    return value


def patch_memory(raw):
    before = decode(raw)
    lines = raw.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip(b'\r\n') == b'systemReserved:']
    require(len(starts) == 1, 'Expected explicit systemReserved mapping')
    start = starts[0] + 1; stop = start
    while stop < len(lines) and (lines[stop].startswith(b' ') or not lines[stop].strip()): stop += 1
    pattern = re.compile(rb'^(  memory: )([\"\x27]?)(4Gi)\2(\r?\n|$)$')
    matches = [(i, pattern.fullmatch(lines[i])) for i in range(start, stop)]
    matches = [(i, m) for i, m in matches if m]
    require(len(matches) == 1, 'Unexpected memory scalar syntax')
    i, match = matches[0]; lines[i] = match[1] + match[2] + b'2Gi' + match[2] + match[4]
    candidate = b''.join(lines); expected = copy.deepcopy(before); expected['systemReserved']['memory'] = '2Gi'
    require(yaml.load(candidate, Loader=StrictLoader) == expected, 'Change outside systemReserved.memory')
    return candidate


def file_info(path):
    raw = common.trusted(path); st = path.lstat()
    require(st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) in (0o600, 0o644), 'Unexpected config ownership/mode')
    return raw, stat.S_IMODE(st.st_mode)


def replace_config(path, raw, mode):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally: Path(name).unlink(missing_ok=True)


def protected():
    paths = [base.BOOTSTRAP, base.CONFIG, INIT, TLS_RECORD]
    manifests = sorted(Path('/etc/kubernetes/manifests').glob('*.yaml'))
    require({p.name for p in manifests} == {'etcd.yaml', 'kube-apiserver.yaml', 'kube-controller-manager.yaml', 'kube-scheduler.yaml'}, 'Unexpected static manifests')
    paths += manifests
    for directory in ('/etc/systemd/system/kubelet.service.d', '/usr/lib/systemd/system/kubelet.service.d'):
        p = Path(directory)
        if p.exists(): paths += sorted(p.glob('*.conf'))
    paths += [Path('/usr/lib/systemd/system/kubelet.service')]
    return {str(p): sha(common.trusted(p)) for p in paths}


def argv_guard(process):
    argv = Path('/proc', str(process['pid']), 'cmdline').read_bytes().split(b'\0')
    require(argv.count(b'--config=/var/lib/kubelet/config.yaml') == 1 and not any(
        a == b'--config' or (a.startswith(b'--config=') and a != b'--config=/var/lib/kubelet/config.yaml') or
        a.startswith((b'--system-reserved', b'--kube-reserved', b'--eviction-', b'--enforce-node-allocatable', b'--config-dir'))
        for a in argv), 'Kubelet reservation/config override present')
    return sha(b'\0'.join(argv))


def configz(node):
    return json.loads(base.kube(['get', '--raw=/api/v1/nodes/' + node + '/proxy/configz']))['kubeletconfig']


def memory_bytes(value):
    match = re.fullmatch(r'([0-9]+)(Ki|Mi|Gi)?', value)
    require(match is not None, 'Unexpected memory quantity')
    return int(match[1]) * {'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3, None: 1}[match[2]]


def node_view(node):
    obj = base.get('node', node)
    return {'uid': obj['metadata']['uid'], 'capacity': obj['status']['capacity'],
            'allocatable': obj['status']['allocatable'], 'addresses': obj['status']['addresses'],
            'node_info': obj['status']['nodeInfo']}


def read_record():
    if not ROOT.exists():
        require(not ROOT.is_symlink(), 'Symlink state directory'); return None
    st = ROOT.lstat(); require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'Unowned state directory')
    record = json.loads(common.trusted(ROOT / 'record.json', True))
    require(record['owner'] == OWNER and re.fullmatch('[0-9a-f]{32}', record['token']), 'Unowned record')
    for key, name in [('before_sha256', 'config.before.yaml'), ('patch_before_sha256', 'patch.before.yaml'), ('bootstrap_sha256', 'bootstrap.before.json')]:
        require(sha(common.trusted(ROOT / name, True)) == record[key], 'Saved preimage changed')
    return record


def inspect(node):
    require(node in ('msk', 'fin'), 'HOME is outside this maintenance')
    prior, _, _, marker, endpoint = base.inspect(node)
    require(endpoint and endpoint['phase'] == 'verified' and prior['server'] == base.ENDPOINT, 'Verified HA endpoint maintenance required')
    require(read_record() is None, 'Existing operation: readback only; never replay apply')
    common.lock_available()
    raw, mode = file_info(CONFIG); patch, patch_mode = file_info(PATCH)
    require(raw.count(b'\n  memory: 4Gi\n') == 1, 'Effective config must match the reviewed TLS descendant scalar')
    candidate = patch_memory(raw); patch_candidate = patch_memory(patch)
    docs = list(yaml.load_all(common.trusted(INIT, True), Loader=StrictLoader))
    init = [x for x in docs if x.get('kind') == 'InitConfiguration']
    require(len(init) == 1 and init[0].get('nodeRegistration', {}).get('name') == node and
            init[0].get('patches') == {'directory': str(PATCH.parent)}, 'Persisted node patch is not referenced by owned kubeadm input')
    require(all('systemReserved' not in x for x in docs), 'Another kubeadm reservation source needs separate review')
    tls = json.loads(common.trusted(TLS_RECORD, True))
    require(tls.get('owner') == 'infra-flux/kubelet-serving-tls-v1' and tls.get('phase') == 'verified' and
            tls.get('after_sha256') == sha(raw) and all(tls.get(k) == prior[k] for k in IDENTITY), 'Original serving TLS proof does not match config/identity')
    process = base.kubelet_process(); argv_sha = argv_guard(process); effective = configz(node)
    require(effective.get('systemReserved') == {'cpu': '1', 'memory': '4Gi'} and
            effective.get('evictionHard') == decode(raw).get('evictionHard') and effective.get('enforceNodeAllocatable') == ['pods'], 'Effective reservation/eviction differs')
    proof = {k: prior[k] for k in IDENTITY}
    proof.update(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 before_sha256=sha(raw), after_sha256=sha(candidate), patch_before_sha256=sha(patch),
                 patch_after_sha256=sha(patch_candidate), config_mode=mode, patch_mode=patch_mode,
                 protected=protected(), configz_before=effective, node_before=node_view(node), argv_sha256=argv_sha)
    require(proof['node_before']['uid'] == proof['node_uid'], 'Node identity changed')
    return proof, raw, candidate, patch, patch_candidate, marker


def validate_review(proof, review):
    require(review == proof, 'Reviewed identity/config/patch/effective preimage differs')


def restart_once(record):
    require(record['phase'] == 'files-written', 'Restart only from new files-written phase')
    require(base.kubelet_process() == record['kubelet_before'], 'Kubelet changed before restart')
    record.update(phase='restart-intent', dispatch_unix=time.time()); common.save_record(record)
    try: base.command(['/usr/bin/systemctl', '--no-block', 'restart', 'kubelet.service'], timeout=8)
    except Exception:
        record['phase'] = 'restart-unknown'; common.save_record(record)
        raise RuntimeError('Restart outcome unknown: readback only, no retry')
    record['phase'] = 'restart-accepted'; common.save_record(record)


def verify_after(record):
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == record['boot_id'], 'Host rebooted')
    require(common.trusted(Path('/etc/machine-id')).decode().strip() == record['machine_id'], 'Machine identity changed')
    require(protected() == record['protected'], 'Protected files changed')
    for p, key, mode in [(CONFIG, 'after_sha256', 'config_mode'), (PATCH, 'patch_after_sha256', 'patch_mode')]:
        raw, current_mode = file_info(p); require(sha(raw) == record[key] and current_mode == record[mode], 'Candidate file/mode differs')
    process = base.kubelet_process(); require(argv_guard(process) == record['argv_sha256'], 'Kubelet arguments changed')
    current_lease = base.lease(record['node']); running = base.workloads()
    base.validate_recovery(record, process, current_lease, running)
    require(running == record['workloads_before'], 'Running container set or process changed')
    desired = copy.deepcopy(record['configz_before']); desired['systemReserved']['memory'] = '2Gi'
    require(configz(record['node']) == desired, 'Effective config changed beyond memory or not loaded')
    actual = node_view(record['node']); expected = copy.deepcopy(record['node_before'])
    expected['allocatable']['memory'] = actual['allocatable']['memory']
    require(actual == expected and memory_bytes(actual['allocatable']['memory']) ==
            memory_bytes(record['node_before']['allocatable']['memory']) + 2 * 1024**3, 'Node/allocatable differs beyond exact +2Gi memory')
    health = base.health(record['node']); require(health['member_ids'] == record['member_ids'], 'etcd membership changed')
    return {'kubelet': process, 'lease': current_lease, 'health': health, 'node': actual, 'configz': desired, 'unchanged_containers': len(running)}


def apply(node, review):
    require(not ROOT.exists() and not ROOT.is_symlink(), 'Existing operation: no replay')
    proof, before, candidate, patch, patch_candidate, marker = inspect(node); validate_review(proof, review)
    health = base.health(node); process = base.kubelet_process(); running = base.workloads(); old_lease = base.lease(node)
    ROOT.mkdir(mode=0o700)
    common.atomic(ROOT / 'config.before.yaml', before); common.atomic(ROOT / 'patch.before.yaml', patch); common.atomic(ROOT / 'bootstrap.before.json', marker)
    record = dict(proof, owner=OWNER, token=uuid.uuid4().hex, phase='prepared', member_ids=health['member_ids'],
                  kubelet_before=process, workloads_before=running, lease_before=old_lease)
    common.save_record(record); common.acquire(record)
    require(file_info(CONFIG) == (before, proof['config_mode']) and file_info(PATCH) == (patch, proof['patch_mode']) and protected() == proof['protected'], 'Preimage changed after acquiring lock')
    record['phase'] = 'files-intent'; common.save_record(record)
    replace_config(PATCH, patch_candidate, proof['patch_mode']); replace_config(CONFIG, candidate, proof['config_mode'])
    record['phase'] = 'files-written'; common.save_record(record)
    require(file_info(CONFIG) == (candidate, proof['config_mode']) and file_info(PATCH) == (patch_candidate, proof['patch_mode']) and protected() == proof['protected'], 'Candidate changed before restart dispatch')
    restart_once(record)
    deadline = time.monotonic() + 180; stable = None; last = None
    while time.monotonic() < deadline:
        try:
            after = verify_after(record)
            if not record.get('observed_new_process'):
                record['observed_new_process'] = after['kubelet']; record['observed_new_lease'] = after['lease']; common.save_record(record)
            else:
                if stable is None: stable = time.monotonic()
                if time.monotonic() - stable >= 15:
                    record.update(phase='verified', verified_unix=time.time(), after=after); common.save_record(record); common.release(record)
                    return {'verified': True, 'record': record, 'changed': True}
        except (RuntimeError, FileNotFoundError) as error: last = str(error); stable = None
        time.sleep(3)
    record['verification_error'] = last; common.save_record(record)
    raise RuntimeError('Recovery unverified; shared lock retained, readback only: ' + str(last))


def readback(node):
    record = read_record(); require(record and record['node'] == node, 'No matching operation')
    # Observation cannot adopt unknown dispatch or release its lock.
    result = {'record': record, 'original_verified': record['phase'] == 'verified', 'adopted': False,
              'current_config_sha256': sha(common.trusted(CONFIG)), 'current_patch_sha256': sha(common.trusted(PATCH)),
              'current_bootstrap_sha256': sha(common.trusted(base.BOOTSTRAP, True)), 'lock': common.fault_lock()}
    if record['phase'] == 'verified':
        held = result['lock']
        require(held and held['metadata']['uid'] == record['global_uid'] and held['data'] ==
                {'phase': 'free', 'kind': OWNER, 'token': record['token'], 'node': node},
                'Verified operation has not released its exact shared lock')
        result['after'] = verify_after(record); result['verified'] = True
    else: result['verified'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'apply', 'readback']); parser.add_argument('--node', choices=['msk', 'fin'], required=True)
    parser.add_argument('--endpoint-source', required=True); parser.add_argument('--shared-source', required=True); parser.add_argument('--review-json')
    args = parser.parse_args(); require(os.geteuid() == 0, 'Run as root'); load_helpers(args.endpoint_source, args.shared_source)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RuntimeError('Bounded maintenance deadline exceeded; inspect retained receipt'))); signal.alarm(420)
    if args.action == 'inspect':
        proof, *_ = inspect(args.node); print(json.dumps({'review': proof, 'health': base.health(args.node)}, sort_keys=True)); return
    if args.action == 'readback': print(json.dumps(readback(args.node), sort_keys=True)); return
    require(args.review_json, 'Apply requires exact inspected review JSON')
    common.trusted(base.BOOTSTRAP, True)
    with base.BOOTSTRAP.open('rb') as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(apply(args.node, json.loads(args.review_json)), sort_keys=True))


if __name__ == '__main__': main()
