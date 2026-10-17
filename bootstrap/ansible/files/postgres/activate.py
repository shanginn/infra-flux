#!/usr/bin/env python3
"""Activate one reviewed Flux workload only after explicit runtime guards."""
import ipaddress
import base64
import json
import pathlib
import re
import subprocess
import sys

OWNER = 'infra-flux/ansible/postgres'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']
settings = json.load(sys.stdin)


def kube(args, body=None):
    result = subprocess.run(KUBE + args, input=json.dumps(body) if body else None, text=True,
                            capture_output=True, check=True, timeout=40)
    return json.loads(result.stdout) if result.stdout.strip() else None


assert settings['enabled'] is True and settings['image_smoke_verified'] is True
assert settings['mode'] in ('watchdog', 'manual-verified-off')
assert settings['stage'] in ('bootstrap-home', 'full')
assert re.fullmatch(r'ghcr\.io/shanginn/infra-flux-patroni@sha256:[0-9a-f]{64}', settings['image'])
assert kube(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid'] == settings['cluster_uid']
source = kube(['get', 'gitrepository', 'infra-flux', '-n', 'flux-system', '-o', 'json'])
assert source['spec']['url'] == 'https://github.com/shanginn/infra-flux.git'
assert source['spec']['ref']['branch'] == 'main'
assert settings['host_reset_approved'] is True if settings['mode'] == 'watchdog' else settings['manual_fencing_policy_approved'] is True
networks = {k: ipaddress.ip_network(settings[k]) for k in ('pod_cidr', 'service_cidr', 'vpn_cidr')}
assert all(net.version == 4 for net in networks.values())
assert all(not a.overlaps(b) for ka, a in networks.items() for kb, b in networks.items() if ka < kb)
assert ipaddress.ip_address(kube(['get', 'service', 'kubernetes', '-n', 'default', '-o', 'json'])['spec']['clusterIP']) in networks['service_cidr']
nodes = {n['metadata']['name']: n for n in kube(['get', 'nodes', '-o', 'json'])['items']}
for name in ('msk', 'fin', 'home'):
    node = nodes[name]
    assert node['metadata']['labels']['infra.shanginn.io/site'] == name
    assert any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions'])
    assert all(ipaddress.ip_address(a['address']) in networks['vpn_cidr'] for a in node['status']['addresses'] if a['type'] == 'InternalIP')
    assert ipaddress.ip_network(node['spec']['podCIDR']).subnet_of(networks['pod_cidr'])
bundle = json.loads(pathlib.Path('/etc/infra-postgres/runtime.json').read_text())
assert bundle['managed_by'] == OWNER and bundle['cluster_uid'] == settings['cluster_uid']
for name in ('patroni-credentials', 'patroni-server-tls'):
    secret = kube(['get', 'secret', name, '-n', 'database', '-o', 'json'])
    assert secret['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER
    desired = ({k: base64.b64encode(v.encode()).decode() for k, v in bundle['passwords'].items()} if name == 'patroni-credentials'
               else {k: bundle['pki'][k] for k in ('tls.crt', 'tls.key', 'ca.crt')})
    assert secret['data'] == desired, 'Runtime Secret does not match the saved identity'

current = kube(['get', 'kustomization.kustomize.toolkit.fluxcd.io', 'unified-postgres', '-n', 'flux-system', '--ignore-not-found', '-o', 'json'])
if settings['stage'] == 'full':
    assert settings['bootstrap_primary_verified'] is True
    assert current is not None, 'A full cluster requires an existing verified bootstrap'
    candidates = kube(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres,role=primary', '-o', 'json'])['items']
    assert len(candidates) == 1, 'Expected exactly one current primary'
    primary = candidates[0]
    assert primary['metadata']['name'] in ('unified-pg-home-0', 'unified-pg-msk-0', 'unified-pg-fin-0')
    assert any(c['type'] == 'Ready' and c['status'] == 'True' for c in primary['status']['conditions'])
    if current['metadata'].get('annotations', {}).get('infra.shanginn.io/stage') != 'full':
        assert current['metadata']['annotations']['infra.shanginn.io/stage'] == 'bootstrap-home'
        assert primary['metadata']['name'] == 'unified-pg-home-0', 'Verify the initial home primary before adding replicas'
    checked = kube(['exec', '-n', 'database', primary['metadata']['name'], '-c', 'postgres', '--', '/opt/patroni/bin/python', '/opt/infra/verify-runtime.py'])
    assert checked['role'] == 'primary' and checked['dynamic_config_matches'] is True
    if settings['mode'] == 'watchdog':
        assert checked['watchdog_timeout_seconds'] == 30 and checked['watchdog_holder_pids']

desired_vars = {'POD_CIDR': settings['pod_cidr'], 'SERVICE_CIDR': settings['service_cidr'],
                'VPN_CIDR': settings['vpn_cidr'], 'POSTGRES_IMAGE': settings['image']}
current_vars = kube(['get', 'configmap', 'unified-postgres-settings', '-n', 'flux-system', '--ignore-not-found', '-o', 'json'])
if current_vars:
    assert current_vars['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER
    assert current_vars['data'] == desired_vars, 'Image/network changes require a separate reviewed update'
annotations = {'infra.shanginn.io/managed-by': OWNER, 'infra.shanginn.io/fencing-mode': settings['mode'], 'infra.shanginn.io/stage': settings['stage']}
if current:
    old = current['metadata'].get('annotations', {})
    assert old.get('infra.shanginn.io/managed-by') == OWNER
    assert old.get('infra.shanginn.io/fencing-mode') == settings['mode'], 'Do not change fencing of a running cluster'
    assert settings['stage'] == 'full' or old.get('infra.shanginn.io/stage') == settings['stage'], 'Refuse implicit scale-down or a different initial bootstrap'
    assert not current['spec'].get('suspend', False), 'Do not resume a deliberately suspended controller implicitly'
elif settings['stage'] == 'bootstrap-home':
    assert not kube(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres', '-o', 'json'])['items']

variables = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'unified-postgres-settings', 'namespace': 'flux-system', 'annotations': {'infra.shanginn.io/managed-by': OWNER}}, 'data': desired_vars}
patches = [{'target': {'group': 'apps', 'version': 'v1', 'kind': 'StatefulSet', 'name': 'unified-pg-' + site},
            'patch': '- op: replace\n  path: /spec/replicas\n  value: ' + str(int(site == 'home' or settings['stage'] == 'full')) + '\n'} for site in ('msk', 'fin', 'home')]
controller = {'apiVersion': 'kustomize.toolkit.fluxcd.io/v1', 'kind': 'Kustomization', 'metadata': {'name': 'unified-postgres', 'namespace': 'flux-system', 'annotations': annotations},
              'spec': {'interval': '5m', 'retryInterval': '1m', 'timeout': '10m', 'prune': False, 'wait': True,
                       'path': './clusters/unified/postgres' + ('/watchdog' if settings['mode'] == 'watchdog' else ''),
                       'sourceRef': {'kind': 'GitRepository', 'name': 'infra-flux'}, 'patches': patches,
                       'postBuild': {'substituteFrom': [{'kind': 'ConfigMap', 'name': 'unified-postgres-settings'}]}}}
kube(['apply', '-f', '-', '-o', 'json'], variables)
kube(['apply', '-f', '-', '-o', 'json'], controller)
print(json.dumps({'controller': 'unified-postgres', 'stage': settings['stage'], 'fencing_mode': settings['mode'], 'reconcile_requested': True, 'runtime_verified': False}))
