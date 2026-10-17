#!/usr/bin/env python3
"""Explicit isolated S3 backup/restore check; touches only one new random bucket."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import uuid

spec = importlib.util.spec_from_file_location('garage_stream', Path(__file__).with_name('garage-stream.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def main():
    g.require(os.geteuid() == 0 and sys.argv[1:] == ['--isolated-bucket-roundtrip'], 'Explicit isolated check flag required')
    g.owned_cluster()
    pods = json.loads(g.command(g.KUBE + ['get', 'pods', '-n', 'garage', '-l', 'app.kubernetes.io/name=garage,app.kubernetes.io/instance=garage', '-o', 'json']))['items']
    ready = [p['metadata']['name'] for p in pods if any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', []))]
    g.require(ready, 'Garage must be Ready')
    pod, bucket, bucket_id, key_id = sorted(ready)[0], 'infra-backup-check-' + uuid.uuid4().hex[:24], None, None
    object_key = 'restore-check/../bytes пробел %.bin'
    # This payload stays in RAM and is deliberately bounded, unlike real streaming object exports.
    payload = b'infra-restic-restore-check\x00' + os.urandom(128 * 1024)
    headers = {'content-type': 'application/octet-stream', 'x-amz-meta-backup-check': 'roundtrip', 'cache-control': 'no-store'}
    report = None
    try:
        bucket_id = g.admin_api(pod, 'CreateBucket', {'globalAlias': bucket})['id']
        credentials = g.admin_api(pod, 'CreateKey', {'name': bucket, 'deny': {'createBucket': True}})
        key_id = credentials['accessKeyId']
        g.admin_api(pod, 'AllowBucketKey', {'bucketId': bucket_id, 'accessKeyId': key_id,
                                         'permissions': {'read': True, 'write': True, 'owner': False}})
        with g.forward(pod) as port:
            client = g.S3(port, credentials)
            client.put_validation_object(bucket, object_key, payload, headers)
            admin = {'buckets': [g.admin_api(pod, 'GetBucketInfo', {'id': bucket_id})], 'keys': [credentials]}
            encoded = io.BytesIO()
            g.export_stream(client, admin, {'name': 'isolated-validation'}, encoded, 2 * 1024**2, 1)
            encoded.seek(0)
            report = g.verify_stream(encoded, 2 * 1024**2, 1, 'isolated-validation')
            encoded.seek(0)
            with tarfile.open(fileobj=encoded) as archive:
                restored = archive.extractfile('objects/00000000.bin').read()
                metadata = json.load(archive.extractfile('objects/00000000.json'))
            g.require(restored == payload and metadata['key'] == object_key and metadata['headers'] == headers, 'Restored bytes/metadata differ')
            client.delete_validation_object(bucket, object_key)
            g.require(client.listing(bucket, 1, len(payload)) == [], 'Validation object was not removed before restoration')
            client.put_validation_object(bucket, metadata['key'], restored, metadata['headers'])
            with client.get(bucket, object_key) as response:
                g.require(hashlib.sha256(response.read(len(payload) + 1)).hexdigest() == metadata['sha256'], 'S3 restored checksum differs')
                g.require(all(response.getheader(name) == value for name, value in headers.items()), 'S3 restored metadata differs')
            client.delete_validation_object(bucket, object_key)
    finally:
        # Only exact IDs returned by our own Create calls are eligible for cleanup.
        # A failed operation leaves any unknown-outcome resource for operator inspection.
        if key_id is not None:
            g.admin_api(pod, 'DeleteKey', {'id': key_id})
        if bucket_id is not None:
            g.admin_api(pod, 'DeleteBucket', {'id': bucket_id})
    g.require(report is not None, 'Restore check did not complete')
    report['s3_restore_roundtrip'] = True
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Isolated Garage restore check failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
