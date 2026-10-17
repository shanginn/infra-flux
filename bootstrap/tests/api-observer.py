#!/usr/bin/env python3
"""Bounded API write/read observations using only a dedicated owned ConfigMap."""
import argparse
import json
import time
import uuid
from common import ANNOTATION, NAMESPACE, OWNER, ensure_namespace, get, identity, kube, owned, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca-sha256', required=True)
    parser.add_argument('--duration', type=int, default=600)
    parser.add_argument('--interval', type=float, default=2)
    args = parser.parse_args()
    require(10 <= args.duration <= 3600 and 1 <= args.interval <= 30, 'Invalid observation bounds')
    node = identity(args.ca_sha256)['node_name']
    ensure_namespace()
    name = 'api-observer-' + node + '-' + uuid.uuid4().hex[:12]
    created = json.loads(kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'ConfigMap',
        'metadata': {'name': name, 'namespace': NAMESPACE, 'annotations': {ANNOTATION: OWNER}}, 'data': {}}))
    stop = time.monotonic() + args.duration
    try:
        while time.monotonic() < stop:
            started, timestamp = time.monotonic(), time.time()
            outcome = {'observer': node, 'component': 'api-write-read', 'started_unix': timestamp, 'ok': False}
            try:
                nonce = uuid.uuid4().hex
                kube(['patch', 'configmap', name, '-n', NAMESPACE, '--type=merge', '-p', json.dumps({'data': {'nonce': nonce}})])
                obj = owned(get('configmap', name, NAMESPACE))
                require(obj['metadata']['uid'] == created['metadata']['uid'] and obj['data']['nonce'] == nonce, 'API readback differs')
                outcome['ok'] = True
            except Exception as error:
                outcome['error_type'] = type(error).__name__
            outcome['duration_ms'] = round((time.monotonic() - started) * 1000, 3)
            print(json.dumps(outcome), flush=True)
            time.sleep(max(0, args.interval - (time.monotonic() - started)))
    finally:
        try:
            obj = owned(get('configmap', name, NAMESPACE))
            require(obj['metadata']['uid'] == created['metadata']['uid'], 'Observer identity changed')
            kube(['delete', 'configmap', name, '-n', NAMESPACE, '--wait=false'])
        except Exception:
            print(json.dumps({'observer': node, 'cleanup_pending': name}), flush=True)


if __name__ == '__main__':
    main()
