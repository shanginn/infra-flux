"""Shared identity and Kubernetes helpers for explicitly invoked HA tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

OWNER = 'infra-flux/ha-tests-v1'
NAMESPACE = 'infra-ha-test'
ANNOTATION = 'infra.shanginn.io/managed-by'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, *, input=None, timeout=30, check=True):
    result = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    require(not check or result.returncode == 0, 'Command failed: ' + argv[0])
    return result


def identity(expected_ca, expected_node=None):
    require(os.geteuid() == 0, 'Run on the owned node as root')
    state = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    require(state['managed_by'] == 'infra-flux/ansible/kubeadm', 'Unknown cluster owner')
    require(state['ca_sha256'] == expected_ca == hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest(), 'Cluster CA differs')
    require(state['node_name'] in ('home', 'msk', 'fin'), 'Unknown node')
    require(expected_node is None or state['node_name'] == expected_node, 'Wrong SSH destination')
    return state


def kube(args, payload=None, *, timeout=30):
    result = command(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                      '--request-timeout=10s', *args],
                     input=None if payload is None else json.dumps(payload).encode(), timeout=timeout)
    return result.stdout


def get(kind, name=None, namespace=None):
    args = ['get', kind, *([name] if name else []), *(['-n', namespace] if namespace else []), '-o', 'json']
    return json.loads(kube(args))


def owned(obj):
    require(obj['metadata'].get('annotations', {}).get(ANNOTATION) == OWNER, 'Refusing an unrelated test resource')
    return obj


def ensure_namespace():
    raw = kube(['get', 'namespace', NAMESPACE, '--ignore-not-found', '-o', 'json'])
    if raw.strip():
        return owned(json.loads(raw))
    return json.loads(kube(['create', '-f', '-', '-o', 'json'], {
        'apiVersion': 'v1', 'kind': 'Namespace',
        'metadata': {'name': NAMESPACE, 'annotations': {ANNOTATION: OWNER}}}))


def ready(pod_or_node):
    return any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod_or_node['status'].get('conditions', []))
