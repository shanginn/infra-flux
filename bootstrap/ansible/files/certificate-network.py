#!/usr/bin/env python3
"""Derive exact control-plane tunnel sources; never publish them to Git."""
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf']
NAME = 'unified-control-plane-tunnels'
OWNER = 'infra-flux/certificate-network'


def read(*args):
    return json.loads(subprocess.check_output(KUBE + list(args) + ['-o', 'json'], text=True))


def main():
    identity = read('get', 'namespace', 'kube-system')['metadata']['uid']
    marker = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    # The bootstrap marker identifies this managed machine; cluster UID is pinned
    # below on first creation and must remain unchanged on all later runs.
    if (marker.get('managed_by') != 'infra-flux/ansible/kubeadm' or
            marker.get('cluster_name') != 'unified' or
            marker.get('ca_sha256') != hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest()):
        raise RuntimeError('Unmanaged bootstrap identity')
    network = ipaddress.ip_network(read('get', 'configmap', 'unified-network', '-n', 'flux-system')['data']['POD_CIDR'])
    nodes = read('get', 'nodes')['items']
    if sorted(n['metadata']['name'] for n in nodes) != ['fin', 'home', 'msk']:
        raise RuntimeError('Expected exactly the three managed control planes')
    data = {}
    for node in nodes:
        meta = node['metadata']
        if 'node-role.kubernetes.io/control-plane' not in meta.get('labels', {}):
            raise RuntimeError('Node is not a control plane')
        if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions']):
            raise RuntimeError('Control plane is not Ready')
        address = ipaddress.ip_address(meta['annotations']['projectcalico.org/IPv4VXLANTunnelAddr'])
        if address.version != 4 or address not in network:
            raise RuntimeError('Tunnel source is outside the configured pod network')
        data[meta['name'].upper() + '_CONTROL_PLANE_TUNNEL_CIDR'] = str(address) + '/32'
    if len(set(data.values())) != 3:
        raise RuntimeError('Ambiguous tunnel source identity')
    raw = subprocess.check_output(KUBE + ['get', 'configmap', NAME, '-n', 'flux-system', '--ignore-not-found', '-o', 'json'], text=True)
    annotations = {'infra.shanginn.io/managed-by': OWNER, 'infra.shanginn.io/cluster-uid': identity}
    if raw.strip():
        old = json.loads(raw)
        if old.get('data') != data or any(old['metadata'].get('annotations', {}).get(k) != v for k, v in annotations.items()):
            raise RuntimeError('Existing tunnel sources changed: review and explicitly replace after node recovery')
        changed = False
    else:
        obj = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': NAME, 'namespace': 'flux-system', 'annotations': annotations, 'labels': {'reconcile.fluxcd.io/watch': 'Enabled'}}, 'data': data}
        subprocess.run(KUBE + ['create', '-f', '-'], input=json.dumps(obj), text=True, check=True, capture_output=True)
        changed = True
    current = read('get', 'configmap', NAME, '-n', 'flux-system')
    if current['data'] != data:
        raise RuntimeError('Readback mismatch')
    print(json.dumps({'changed': changed, 'exact_control_plane_sources': 3, 'prefix_length': 32}))


if __name__ == '__main__':
    main()
