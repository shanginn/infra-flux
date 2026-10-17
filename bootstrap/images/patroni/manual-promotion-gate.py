#!/usr/bin/env python3
"""Fail closed unless an operator provided one short-lived fencing attestation.

This does not power off another server. That must be independently verified by
the operator before creating the approval. A missing approval denies promotion.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

def main():
    import pathlib
    sa = pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
    namespace = os.environ['POD_NAMESPACE']
    pod_uid = os.environ['POD_UID']
    pod_name = os.environ['POD_NAME']
    host = os.environ['KUBERNETES_SERVICE_HOST']
    port = os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')
    base = f'https://{host}:{port}/api/v1/namespaces/{urllib.parse.quote(namespace, safe="")}/configmaps/'
    url = base + 'unified-postgres-promotion-approval'
    context = ssl.create_default_context(cafile=str(sa / 'ca.crt'))
    headers = {'Authorization': 'Bearer ' + (sa / 'token').read_text().strip()}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), context=context, timeout=5) as r:
        obj = json.load(r)
    approval = obj['data']
    now = time.time()
    assert approval['state'] == 'approved'
    assert approval['candidate_pod'] == pod_name and approval['candidate_uid'] == pod_uid
    assert 0 < float(approval['expires_unix']) - now <= 60
    assert approval['old_primary_verified_off'] == 'true'
    assert approval['fence_evidence'].strip() and approval['operator'].strip()
    # Consume before promotion; a crash after this point requires fresh approval.
    patch = [
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/data/state', 'value': 'approved'},
        {'op': 'replace', 'path': '/data/state', 'value': 'consumed'},
    ]
    headers['Content-Type'] = 'application/json-patch+json'
    req = urllib.request.Request(url, data=json.dumps(patch).encode(), headers=headers, method='PATCH')
    with urllib.request.urlopen(req, context=context, timeout=5):
        pass

try:
    main()
except Exception:
    print('Promotion refused: no valid unused fencing approval for this pod.', flush=True)
    raise SystemExit(1)
