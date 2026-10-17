#!/usr/bin/env python3
"""Explicitly provision the owned read-only S3 export key; never called by export."""
import importlib.util
import json
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('garage_stream', Path(__file__).with_name('garage-stream.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
DIRECTORY = Path('/etc/infra-garage')
OWNER = 'infra-flux/garage-macbook-backup'
NAME = 'infra-macbook-backup'


def save_new(path, value):
    with path.open('x') as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    g.require(os.geteuid() == 0 and sys.argv[1:] == ['--provision-read-only-key'], 'Explicit key provisioning flag required')
    g.owned_cluster()
    pods = json.loads(g.command(g.KUBE + ['get', 'pods', '-n', 'garage', '-l', 'app.kubernetes.io/name=garage,app.kubernetes.io/instance=garage', '-o', 'json']))['items']
    ready = [p['metadata']['name'] for p in pods if any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', []))]
    g.require(ready, 'Garage must be Ready')
    pod = sorted(ready)[0]
    target, intent = DIRECTORY / 'backup-key.json', DIRECTORY / 'backup-key-create-intent.json'
    if target.exists():
        g.require(not target.is_symlink() and target.stat().st_mode & 0o077 == 0, 'Unsafe backup key marker')
        state = json.loads(target.read_text())
        g.require(state['managed_by'] == OWNER, 'Unowned backup key')
        key_id = state['accessKeyId']
    else:
        # Record intent before the remote mutation. An ambiguous outcome requires inspection.
        g.require(not intent.exists(), 'Earlier key creation may have succeeded; inspect it before retrying')
        g.require(not any(k['name'] == NAME for k in g.admin_api(pod, 'ListKeys')), 'Matching key exists without ownership; do not adopt it')
        save_new(intent, {'managed_by': OWNER, 'operation': 'CreateKey', 'name': NAME})
        info = g.admin_api(pod, 'CreateKey', {'name': NAME, 'neverExpires': True, 'deny': {'createBucket': True}})
        key_id = info['accessKeyId']
        save_new(target, {'managed_by': OWNER, 'accessKeyId': key_id})
    key = g.admin_api(pod, 'GetKeyInfo', {'id': key_id})
    g.require(key['name'] == NAME and not key['expired'] and not key['permissions']['createBucket'], 'Backup key identity/permissions differ')
    g.require(all(not b['permissions']['write'] and not b['permissions']['owner'] for b in key['buckets']), 'Backup key unexpectedly has write or owner permission')
    buckets = g.admin_api(pod, 'ListBuckets')
    for bucket in buckets:
        g.admin_api(pod, 'AllowBucketKey', {'bucketId': bucket['id'], 'accessKeyId': key_id,
                                        'permissions': {'read': True, 'write': False, 'owner': False}})
    key = g.admin_api(pod, 'GetKeyInfo', {'id': key_id})
    g.require({b['id'] for b in key['buckets']} == {b['id'] for b in buckets} and
              all(b['permissions']['read'] and not b['permissions']['write'] and not b['permissions']['owner'] for b in key['buckets']),
              'Read-only bucket grants did not converge')
    print('Read-only export key verified for every existing bucket; no secret printed')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Backup key provisioning failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
