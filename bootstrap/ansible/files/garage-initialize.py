#!/usr/bin/env python3
"""Initialize only the declared empty cluster; never replace a node or delete data."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time

KUBECTL = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf']
EXPECTED = {'home', 'msk', 'fin'}
CAPACITY = 24 * 1024**3
STATE = Path('/etc/infra-garage')


def run(args, payload=None):
    result = subprocess.run(args, input=payload, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Command failed; inspect node/Pod and protected local logs')
    return result.stdout


def cli(pod, *args):
    return run(KUBECTL + ['exec', '-n', 'garage', pod, '-c', 'garage', '--', '/garage', *args])


def api(pod, name, payload=None):
    return json.loads(cli(pod, 'json-api', name, json.dumps(payload)))


def role_identity(roles):
    return {x['id']: (x['zone'], x['capacity']) for x in roles}


def save_json(path, value):
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w') as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def initialize():
    pods = json.loads(run(KUBECTL + ['get', 'pods', '-n', 'garage', '-l',
        'app.kubernetes.io/name=garage,app.kubernetes.io/instance=garage', '-o', 'json']))['items']
    assert len(pods) == 3, 'Exactly three Garage Pods are required'
    assert {p['spec'].get('nodeName') for p in pods} == EXPECTED
    roles = []
    for pod in pods:
        assert pod['status']['phase'] == 'Running'
        node = pod['spec']['nodeName']
        assert any(c['name'] == 'garage' and 'running' in c['state'] for c in pod['status'].get('containerStatuses', []))
        node_id = cli(pod['metadata']['name'], 'node', 'id', '--quiet').strip().split('@')[0]
        assert re.fullmatch('[0-9a-f]{64}', node_id), 'Unexpected node ID'
        roles.append({'id': node_id, 'zone': node, 'capacity': CAPACITY, 'tags': [node]})
    assert len({r['id'] for r in roles}) == 3
    primary = next(p['metadata']['name'] for p in pods if p['spec']['nodeName'] == 'msk')
    layout = api(primary, 'GetClusterLayout')
    expected = role_identity(roles)
    marker = STATE / 'layout.json'
    if marker.exists():
        assert role_identity(json.loads(marker.read_text())['roles']) == expected, 'Node identity changed: perform reviewed recovery'
        assert layout['version'] >= 1, 'Recorded layout disappeared: perform reviewed recovery'
    if layout['version'] == 0:
        intent = STATE / 'layout-apply-intent.json'
        assert not intent.exists(), 'Earlier layout apply has unknown outcome: inspect every node; do not apply version 1 twice'
        for pod in pods:
            assert api(pod['metadata']['name'], 'GetClusterLayout')['version'] == 0, 'Nodes disagree on initial layout version'
        assert not layout['roles'], 'Refuse nonempty initial layout'
        staged = layout['stagedRoleChanges']
        assert not staged or role_identity(staged) == expected, 'Unrelated staged changes exist'
        assert layout['stagedParameters'] in (None, {'zoneRedundancy': {'atLeast': 3}}), 'Unrelated staged parameters exist'
        api(primary, 'UpdateClusterLayout', {'roles': roles, 'parameters': {'zoneRedundancy': {'atLeast': 3}}})
        proposal = api(primary, 'PreviewClusterLayoutChanges')
        assert 'error' not in proposal, 'Layout preview failed'
        assert role_identity(proposal['newLayout']['roles']) == expected
        # Durable intent prevents a retry from applying version 1 twice after an
        # ambiguous timeout or process crash. Recovery must inspect all nodes.
        save_json(intent, {'roles': roles, 'version': 1, 'state': 'apply-attempted'})
        api(primary, 'ApplyClusterLayout', {'version': 1})
    for pod in pods:
        observed = None
        for attempt in range(15):
            observed = api(pod['metadata']['name'], 'GetClusterLayout')
            if observed['version'] >= 1 and role_identity(observed['roles']) == expected:
                break
            time.sleep(2)
        assert role_identity(observed['roles']) == expected, 'Layout readback differs'
        assert observed['parameters']['zoneRedundancy'] == {'atLeast': 3}, 'Zone redundancy differs'
    health = api(primary, 'GetClusterHealth')
    assert health['storageNodes'] == 3 and health['storageNodesUp'] == 3
    assert health['partitions'] > 0 and health['partitionsAllOk'] == health['partitions']
    save_json(marker, {'roles': roles, 'version': observed['version']})
    print('Layout verified on three independent nodes; all partitions currently healthy')
    return primary


def buckets(pod, path):
    declared = json.loads(Path(path).read_text())
    assert isinstance(declared, list)
    assert len({x['name'] for x in declared}) == len(declared)
    assert all(re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', x['name']) for x in declared)
    assert all(isinstance(x['maxBytes'], int) and x['maxBytes'] > 0 for x in declared)
    assert sum(x['maxBytes'] for x in declared) <= CAPACITY, 'Aggregate bucket quotas exceed 24 GiB'
    actual = api(pod, 'ListBuckets')
    allowed = {x['name'] for x in declared}
    assert all(len(x['globalAliases']) == 1 and x['globalAliases'][0] in allowed and not x['localAliases'] for x in actual), 'Unmanaged bucket: declare it explicitly; nothing will be deleted'
    mapping = {x['globalAliases'][0]: x['id'] for x in actual}
    for bucket in declared:
        name = bucket['name']
        if name not in mapping:
            mapping[name] = api(pod, 'CreateBucket', {'globalAlias': name})['id']
        info = api(pod, 'GetBucketInfo', {'id': mapping[name]})
        assert info['bytes'] <= bucket['maxBytes'], 'Quota reduction below current data is refused'
        api(pod, 'UpdateBucket', {'id': mapping[name], 'body': {'quotas': {'maxSize': bucket['maxBytes'], 'maxObjects': bucket.get('maxObjects')}}})
        verified = api(pod, 'GetBucketInfo', {'id': mapping[name]})
        assert verified['quotas']['maxSize'] == bucket['maxBytes']
    print('Declared bucket budgets verified; no S3 access keys generated')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--buckets-file')
    args = parser.parse_args()
    with open(STATE / 'bootstrap.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pod = initialize()
        if args.buckets_file:
            buckets(pod, args.buckets_file)


if __name__ == '__main__':
    main()
