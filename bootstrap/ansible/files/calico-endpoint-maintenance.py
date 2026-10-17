#!/usr/bin/env python3
"""Guarded one-Pod-at-a-time Calico endpoint adoption; inspect performs no writes."""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
import uuid

OWNER = 'infra-flux/calico-endpoint-v1'
FAULT_OWNER = 'infra-flux/ha-tests-v1'
ANNOTATION = 'infra.shanginn.io/managed-by'
NAMESPACE = 'infra-ha-test'
LOCK = 'active-fault'
NODES = {'home', 'msk', 'fin'}
BOOTSTRAP = Path('/etc/infra-flux/kubeadm-state.json')
ROOT = Path('/etc/infra-flux/calico-endpoint-maintenance')
CNI = Path('/etc/cni/net.d/calico-kubeconfig')
ENDPOINT_NAME = 'kubernetes-services-endpoint'
ENDPOINT_DATA = {'KUBERNETES_SERVICE_HOST': 'api.unified.internal', 'KUBERNETES_SERVICE_PORT': '7443'}
ENDPOINT = 'https://api.unified.internal:7443'
PROBE_IMAGE = 'docker.io/library/python:3.14.6-slim-trixie@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144'
REFRESH_HEADER = b'# Kubeconfig file for Calico CNI plugin. Installed by calico/node.'

def require(value, message):
    if not value:
        raise RuntimeError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def trusted(path, private=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022), 'Untrusted file: ' + str(path))
    return path.read_bytes()

def atomic(path, data):
    # State and sensitive preimages remain in a private root-owned directory.
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)

def save_record(record):
    atomic(ROOT / 'record.json', (json.dumps(record, sort_keys=True) + '\n').encode())

def command(argv, payload=None, timeout=25):
    result = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'Command failed: ' + argv[0])
    return result.stdout

def kube(args, payload=None):
    return command(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=5s', *args],
                   None if payload is None else json.dumps(payload).encode())

def fault_lock():
    raw = kube(['get', 'configmap', LOCK, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json'])
    if not raw.strip(): return None
    obj = json.loads(raw)
    require(obj['metadata'].get('annotations', {}).get(ANNOTATION) == FAULT_OWNER, 'Unknown cluster maintenance/fault lock')
    return obj

def lock_available(record=None):
    obj = fault_lock()
    require(obj is None or obj['data'].get('phase') == 'free' or
            (record is not None and obj['data'].get('token') == record['token'] and obj['data'].get('kind') == OWNER and
             obj['data'].get('node') == record['node']), 'Another fault or maintenance holds the cluster lock')
    return obj

def acquire(record):
    current = lock_available(record)
    if current and record.get('global_uid'):
        require(current['metadata']['uid'] == record['global_uid'], 'Cluster lock was replaced')
    payload = {'phase': 'active', 'kind': OWNER, 'token': record['token'], 'node': record['node']}
    if current:
        if current['data'].get('token') == record['token'] and current['data'].get('phase') == 'active':
            record['global_uid'] = current['metadata']['uid']; save_record(record)
            return
        current['data'] = payload
        acquired = json.loads(kube(['replace', '-f', '-', '-o', 'json'], current))
    else:
        namespace = json.loads(kube(['get', 'namespace', NAMESPACE, '-o', 'json']))
        require(namespace['metadata'].get('annotations', {}).get(ANNOTATION) == FAULT_OWNER, 'Create the owned HA-test namespace before maintenance')
        acquired = json.loads(kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': LOCK, 'namespace': NAMESPACE, 'annotations': {ANNOTATION: FAULT_OWNER}}, 'data': payload}))
    record['global_uid'] = acquired['metadata']['uid']; save_record(record)

def release(record):
    current = fault_lock()
    require(current is not None and current['metadata'].get('uid') == record.get('global_uid') and current['data'].get('token') == record['token'] and current['data'].get('kind') == OWNER and current['data'].get('node') == record['node'], 'Cluster lock identity changed')
    current['data']['phase'] = 'free'
    kube(['replace', '-f', '-'], current)

def health(node):
    nodes = json.loads(kube(['get', 'nodes', '-o', 'json']))['items']
    require({n['metadata']['name'] for n in nodes} == NODES and len(nodes) == 3, 'Expected exactly three nodes')
    addresses = []
    for entry in nodes:
        require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in entry['status'].get('conditions', [])), 'A node is not Ready')
        address = next(a['address'] for a in entry['status']['addresses'] if a['type'] == 'InternalIP')
        addresses.append('https://' + address + ':2379')
        require(kube(['--server=https://' + address + ':6443', 'get', '--raw=/readyz']).strip() == b'ok', 'A direct API is not ready')
    prefix = ['exec', '-n', 'kube-system', 'etcd-' + node, '--', 'etcdctl', '--dial-timeout=3s', '--command-timeout=5s',
        '--endpoints=' + ','.join(sorted(addresses)), '--cacert=/etc/kubernetes/pki/etcd/ca.crt',
        '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt', '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key']
    endpoints = json.loads(kube(prefix + ['endpoint', 'health', '-w', 'json']))
    require(len(endpoints) == 3 and {e['endpoint'] for e in endpoints} == set(addresses) and all(e['health'] is True for e in endpoints), 'Three healthy etcd endpoints required')
    members = json.loads(kube(prefix + ['member', 'list', '-w', 'json']))['members']
    require(len(members) == 3 and {m['name'] for m in members} == NODES and all(not m.get('isLearner', False) for m in members), 'etcd membership differs')
    return {'nodes_ready': 3, 'api_ready': 3, 'etcd_healthy': 3, 'member_ids': sorted(m['ID'] for m in members)}


def get(kind, name, namespace=None, optional=False):
    args = ['get', kind, name, '--show-managed-fields=true', '-o', 'json']
    if namespace: args += ['-n', namespace]
    if optional: args += ['--ignore-not-found']
    raw = kube(args)
    return json.loads(raw) if raw.strip() else None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def delete_exact(pod):
    """The API checks UID atomically; a reused name never deletes a replacement."""
    meta = pod['metadata']
    require(re.fullmatch('[a-z0-9.-]+', meta['name']) and meta['namespace'] in ('kube-system', NAMESPACE), 'Invalid Pod deletion target')
    kube(['delete', '--raw=/api/v1/namespaces/' + meta['namespace'] + '/pods/' + meta['name'], '-f', '-'],
         {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': meta['uid']}})


def endpoint_config(required=False):
    cm = get('configmap', ENDPOINT_NAME, 'kube-system', True)
    require(cm is not None or not required, 'Wait for Flux to reconcile the endpoint ConfigMap')
    if cm is not None:
        require(cm['metadata'].get('annotations', {}).get(ANNOTATION) == OWNER and cm.get('data') == ENDPOINT_DATA and
                not cm.get('binaryData'), 'Unexpected endpoint ConfigMap ownership or data')
    return cm


def validate_daemonset(ds):
    require(ds.get('kind') == 'DaemonSet' and ds['metadata']['name'] == 'calico-node' and
            ds['metadata']['namespace'] == 'kube-system' and not ds['metadata'].get('deletionTimestamp'), 'Unexpected Calico DaemonSet')
    require(any(m.get('manager') == 'infra-flux-bootstrap' and m.get('operation') == 'Apply' for m in ds['metadata'].get('managedFields', [])), 'Calico is not owned by this bootstrap field manager')
    spec = ds['spec']['template']['spec']
    require(spec.get('hostNetwork') is True and spec.get('serviceAccountName') == 'calico-node' and
            ds['spec']['selector'] == {'matchLabels': {'k8s-app': 'calico-node'}}, 'Unexpected Calico topology')
    containers = {c['name']: c for c in spec.get('initContainers', []) + spec['containers']}
    expected = {'upgrade-ipam': 'quay.io/calico/calico:v3.33.0', 'install-cni': 'quay.io/calico/calico:v3.33.0',
                'calico-node': 'quay.io/calico/node:v3.33.0'}
    for name, image in expected.items():
        c = containers.get(name, {})
        require(c.get('image') == image and c.get('envFrom') == [{'configMapRef': {'name': ENDPOINT_NAME, 'optional': True}}], 'Review changed Calico image or endpoint injection')
        require(not any(e['name'] in (*ENDPOINT_DATA, 'KUBECONFIG', 'SKIP_TLS_VERIFY') for e in c.get('env', [])), 'Explicit environment overrides endpoint or TLS verification')
    return sha(canonical(ds['spec']))


def validate_pod(pod, ds, node, ready=False):
    owners = pod['metadata'].get('ownerReferences', [])
    require(pod['metadata'].get('namespace') == 'kube-system' and len(owners) == 1 and
            owners[0].get('kind') == 'DaemonSet' and owners[0].get('name') == 'calico-node' and
            owners[0].get('uid') == ds['metadata']['uid'] and owners[0].get('controller') is True and
            pod['spec'].get('nodeName') == node and pod['spec'].get('hostNetwork') is True and
            pod['spec'].get('serviceAccountName') == 'calico-node', 'Pod does not belong to the reviewed Calico DaemonSet/node')
    for key in ('containers', 'initContainers'):
        actual = {c['name']: c for c in pod['spec'][key]}
        for c in ds['spec']['template']['spec'][key]:
            require(c['name'] in actual and all(actual[c['name']].get(k) == c.get(k) for k in ('image', 'env', 'envFrom')), 'Pod container differs from the reviewed template')
    if ready:
        require(not pod['metadata'].get('deletionTimestamp') and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', [])), 'Calico Pod is not Ready')


def node_pod(ds, node, ready=False):
    pods = json.loads(kube(['get', 'pods', '-n', 'kube-system', '-l', 'k8s-app=calico-node',
                            '--field-selector=spec.nodeName=' + node, '-o', 'json']))['items']
    require(len(pods) == 1, 'Expected exactly one Calico Pod on the node')
    validate_pod(pods[0], ds, node, ready)
    return pods[0]


def cni_config(raw):
    # Decoding runs locally; credential bytes never enter logs or returned proof.
    obj = json.loads(command(['/usr/bin/kubectl', 'config', 'view', '--raw', '--kubeconfig=/dev/stdin', '-o', 'json'], raw))
    require(len(obj.get('clusters', [])) == len(obj.get('users', [])) == len(obj.get('contexts', [])) == 1, 'Unexpected CNI kubeconfig topology')
    cluster = obj['clusters'][0]['cluster']; user = obj['users'][0]['user']
    require(set(cluster) == {'server', 'certificate-authority-data'} and set(user) == {'token'}, 'Unexpected CNI auth or TLS settings')
    require(sha(base64.b64decode(cluster['certificate-authority-data'], validate=True)) == sha(trusted(Path('/etc/kubernetes/pki/ca.crt'))), 'CNI CA does not match the cluster')
    token = user['token']; pieces = token.split('.')
    require(len(pieces) == 3, 'Expected a Kubernetes JWT')
    claims = json.loads(base64.urlsafe_b64decode(pieces[1] + '=' * (-len(pieces[1]) % 4)))
    require(claims.get('sub') == 'system:serviceaccount:kube-system:calico-cni-plugin', 'Unexpected CNI token identity')
    shape = copy.deepcopy(obj); shape['users'][0]['user']['token'] = '<rotating-token>'
    shape['clusters'][0]['cluster']['server'] = '<endpoint>'
    return {'shape': shape, 'server': cluster['server'], 'token_sha256': sha(token.encode()),
            'token_identity': {k: claims.get(k) for k in ('iss', 'sub', 'aud')},
            'serviceaccount': claims.get('kubernetes.io', {}).get('serviceaccount')}


def config_equivalent(before, after):
    require(before['shape'] == after['shape'] and before['token_identity'] == after['token_identity'] and
            before['serviceaccount'] == after['serviceaccount'], 'CNI settings changed outside the endpoint or normal token renewal')
    require(after['server'] == ENDPOINT, 'CNI endpoint is not the local API proxy')


def authenticated_cni_read():
    # A successful authenticated request verifies the renewed token and CA chain.
    obj = json.loads(command(['/usr/bin/kubectl', '--kubeconfig=' + str(CNI), '--server=' + ENDPOINT,
        '--request-timeout=5s', 'get', 'clusterinformation.crd.projectcalico.org', 'default', '-o', 'json']))
    require(obj.get('kind') == 'ClusterInformation' and obj['metadata']['name'] == 'default', 'CNI credential read failed')


def read_record():
    if not ROOT.exists():
        require(not ROOT.is_symlink(), 'Maintenance directory is a symlink'); return None
    info = ROOT.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'Maintenance state is not private/root-owned')
    record = json.loads(trusted(ROOT / 'record.json', True))
    require(record.get('owner') == OWNER and re.fullmatch('[0-9a-f]{32}', record.get('token', '')), 'Unknown maintenance record')
    require(sha(trusted(ROOT / 'bootstrap.before.json', True)) == record['review']['bootstrap_sha256'] and
            sha(trusted(ROOT / 'cni.before.yaml', True)) == record['cni_before_sha256'], 'Saved maintenance preimage differs')
    return record


def inspect(node, expected_ca=None):
    marker_raw = trusted(BOOTSTRAP, True); marker = json.loads(marker_raw)
    require(marker.get('managed_by') == 'infra-flux/ansible/kubeadm' and marker.get('cluster_name') == 'unified' and
            marker.get('node_name') == node and node in NODES, 'Wrong cluster or node')
    ca = sha(trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(ca == marker.get('ca_sha256') and (expected_ca is None or ca == expected_ca), 'Cluster CA differs')
    host = get('node', node)
    require(any(a['type'] == 'InternalIP' and a['address'] == marker['vpn_ipv4'] for a in host['status']['addresses']), 'Node VPN identity differs')
    require({a[4][0] for a in socket.getaddrinfo('api.unified.internal', 7443, type=socket.SOCK_STREAM)} == {'127.0.0.1'}, 'API hostname is not the node-local proxy')
    ds = get('daemonset', 'calico-node', 'kube-system'); ds_sha = validate_daemonset(ds)
    pod = node_pod(ds, node)
    hosts = trusted(Path('/var/lib/kubelet/pods') / pod['metadata']['uid'] / 'etc-hosts').decode()
    require(any(l.split('#')[0].split()[:2] == ['127.0.0.1', 'api.unified.internal'] for l in hosts.splitlines()), 'Calico Pod lacks the node-local API hosts mapping')
    cm = endpoint_config(); raw = trusted(CNI, True); config = cni_config(raw)
    service = get('service', 'kubernetes', 'default')
    require(config['server'] in (ENDPOINT, 'https://' + service['spec']['clusterIP'] + ':443'), 'Unexpected current CNI endpoint')
    review = {'node': node, 'ca_sha256': ca, 'bootstrap_sha256': sha(marker_raw), 'node_uid': host['metadata']['uid'],
              'ds_uid': ds['metadata']['uid'], 'ds_spec_sha256': ds_sha, 'pod_uid': pod['metadata']['uid'],
              'config_shape_sha256': sha(canonical(config['shape']))}
    record = read_record()
    if record:
        for key in ('node', 'ca_sha256', 'bootstrap_sha256', 'node_uid', 'ds_uid', 'ds_spec_sha256', 'config_shape_sha256'):
            require(record['review'][key] == review[key], 'Recorded identity/configuration changed: ' + key)
        config_equivalent(cni_config(trusted(ROOT / 'cni.before.yaml', True)), config) if config['server'] == ENDPOINT else None
    return {'review': record['review'] if record else review, 'current_pod_uid': pod['metadata']['uid'],
            'current_server': config['server'], 'endpoint_configured': cm is not None,
            'phase': record['phase'] if record else 'not-started'}, raw, marker_raw, ds, pod, record


def require_lock(record):
    current = fault_lock()
    require(current is not None and current['metadata']['uid'] == record.get('global_uid') and
            all(current['data'].get(k) == v for k, v in {'phase': 'active', 'kind': OWNER, 'token': record['token'], 'node': record['node']}.items()), 'Maintenance no longer holds the fault lock')


def validate_recorded_runtime(record):
    proof, raw, _, ds, pod, _ = inspect(record['node'], record['review']['ca_sha256'])
    require(pod['metadata']['uid'] != record['review']['pod_uid'] and
            pod['metadata']['uid'] == record.get('replacement_uid'), 'Replacement Calico Pod identity changed')
    validate_pod(pod, ds, record['node'], True)
    require(raw.startswith(REFRESH_HEADER), 'Waiting for calico-node token refresher to write its kubeconfig')
    before = cni_config(trusted(ROOT / 'cni.before.yaml', True)); after = cni_config(raw)
    config_equivalent(before, after)
    require(after['token_sha256'] != before['token_sha256'], 'Waiting for a genuinely renewed CNI token')
    authenticated_cni_read()
    return proof


def network_pod(record):
    code = '''import json,socket,ssl,urllib.request,urllib.error,sys
name="kubernetes.default.svc.cluster.local"
ips=sorted({a[4][0] for a in socket.getaddrinfo(name,443,type=socket.SOCK_STREAM)})
assert sys.argv[1] in ips
ctx=ssl.create_default_context(cafile="/ca/ca.crt")
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
try:
 r=opener.open("https://"+sys.argv[1]+"/version",timeout=8);status=r.status;r.close()
except urllib.error.HTTPError as e:status=e.code
assert status in (200,401,403)
print(json.dumps({"dns_resolved":True,"cluster_ip_tls":True,"http_status":status}))
'''
    service = get('service', 'kubernetes', 'default')
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'calico-check-' + record['token'], 'namespace': NAMESPACE,
        'annotations': {ANNOTATION: OWNER, 'infra.shanginn.io/maintenance-token': record['token']}}, 'spec': {
        'nodeName': record['node'], 'restartPolicy': 'Never', 'activeDeadlineSeconds': 180, 'terminationGracePeriodSeconds': 5,
        'automountServiceAccountToken': False, 'dnsPolicy': 'ClusterFirst', 'hostNetwork': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [{'name': 'check', 'image': PROBE_IMAGE, 'imagePullPolicy': 'IfNotPresent',
            'command': ['python3', '-B', '-c', code, service['spec']['clusterIP']],
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '10m', 'memory': '24Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
            'volumeMounts': [{'name': 'ca', 'mountPath': '/ca', 'readOnly': True}]}],
        'volumes': [{'name': 'ca', 'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}]}}


def validate_network_pod(pod, desired, record):
    meta = pod['metadata']
    require(meta['name'] == desired['metadata']['name'] and meta['namespace'] == NAMESPACE and
            all(meta.get('annotations', {}).get(k) == v for k, v in desired['metadata']['annotations'].items()) and
            (record.get('network_pod_uid') is None or meta['uid'] == record['network_pod_uid']), 'Probe Pod ownership/UID differs')
    # Kubernetes adds defaults; every explicitly supplied field must match recursively.
    def subset(actual, wanted):
        if isinstance(wanted, dict): return isinstance(actual, dict) and all(k in actual and subset(actual[k], v) for k, v in wanted.items())
        if isinstance(wanted, list): return isinstance(actual, list) and len(actual) == len(wanted) and all(subset(a, b) for a, b in zip(actual, wanted))
        return actual == wanted
    require(subset(pod['spec'], desired['spec']) and not pod['metadata'].get('ownerReferences'), 'Probe Pod specification differs')


def disposable_network_check(record):
    require_lock(record)
    desired = network_pod(record); name = desired['metadata']['name']
    pod = get('pod', name, NAMESPACE, True)
    if pod is None:
        require(not record.get('network_pod_uid'), 'Previously recorded probe disappeared; inspect before retrying')
        pod = json.loads(kube(['create', '-f', '-', '-o', 'json'], desired))
    validate_network_pod(pod, desired, record)
    record['network_pod_uid'] = pod['metadata']['uid']; save_record(record)
    try:
        deadline = time.monotonic() + 210
        while time.monotonic() < deadline:
            require_lock(record); pod = get('pod', name, NAMESPACE)
            validate_network_pod(pod, desired, record)
            phase = pod.get('status', {}).get('phase')
            require(phase != 'Failed', 'Disposable CNI/DNS/ClusterIP probe failed')
            if phase == 'Succeeded':
                require(pod['status'].get('podIP') and not pod['spec']['hostNetwork'], 'Probe did not obtain a CNI Pod IP')
                proof = json.loads(kube(['logs', '-n', NAMESPACE, name, '-c', 'check']))
                require(proof.get('dns_resolved') is True and proof.get('cluster_ip_tls') is True and proof.get('http_status') in (200, 401, 403), 'Unexpected network proof')
                record['network_proof'] = proof; save_record(record)
                return proof
            time.sleep(3)
        raise RuntimeError('Disposable network probe exceeded its deadline')
    finally:
        current = get('pod', name, NAMESPACE, True)
        if current is not None:
            validate_network_pod(current, desired, record); delete_exact(current)
        deadline = time.monotonic() + 30
        while get('pod', name, NAMESPACE, True) is not None:
            require(time.monotonic() < deadline, 'Owned network Pod cleanup timed out'); time.sleep(1)
        record['network_cleanup'] = True; save_record(record)


def wait_for_replacement(record):
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        require_lock(record)
        ds = get('daemonset', 'calico-node', 'kube-system')
        require(ds['metadata']['uid'] == record['review']['ds_uid'] and validate_daemonset(ds) == record['review']['ds_spec_sha256'], 'Calico DaemonSet changed during maintenance')
        try:
            pod = node_pod(ds, record['node'], True)
            if pod['metadata']['uid'] != record['review']['pod_uid']:
                require(not record.get('replacement_uid') or record['replacement_uid'] == pod['metadata']['uid'], 'Replacement Pod changed again')
                record['replacement_uid'] = pod['metadata']['uid']; save_record(record)
                validate_recorded_runtime(record)
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(3)
    raise RuntimeError('Replacement Calico/token renewal not verified; cluster lock retained')


def apply(args):
    proof, raw, marker, ds, pod, record = inspect(args.node, args.ca_sha256)
    require(json.loads(args.review_json) == proof['review'], 'Reviewed node/DaemonSet/Pod/configuration preimage differs')
    endpoint_config(True); lock_available(record)
    prior = health(args.node)
    for node in sorted(NODES): node_pod(ds, node, True)
    validate_pod(pod, ds, args.node, True); authenticated_cni_read()
    if record and record['phase'] == 'verified':
        require(record['member_ids'] == prior['member_ids'], 'etcd membership changed since verification')
        validate_recorded_runtime(record)
        require(record.get('network_cleanup') and record.get('network_proof'), 'Missing verified network check/cleanup')
        return {'node': args.node, 'changed': False, 'endpoint': ENDPOINT, 'health': prior, 'verified': True}
    if record is None:
        ROOT.mkdir(mode=0o700)
        atomic(ROOT / 'bootstrap.before.json', marker); atomic(ROOT / 'cni.before.yaml', raw)
        record = {'owner': OWNER, 'node': args.node, 'token': uuid.uuid4().hex, 'phase': 'prepared', 'review': proof['review'],
                  'cni_before_sha256': sha(raw), 'member_ids': prior['member_ids']}
        save_record(record)
    require(prior['member_ids'] == record['member_ids'], 'etcd membership changed')
    acquire(record); require_lock(record)
    require(trusted(BOOTSTRAP, True) == marker, 'Bootstrap changed before deletion')
    endpoint_config(True)
    if pod['metadata']['uid'] == record['review']['pod_uid']:
        # Record intent first, then delete with an API-enforced UID precondition.
        record['phase'] = 'replacing'; save_record(record)
        current_ds = get('daemonset', 'calico-node', 'kube-system')
        require(current_ds['metadata']['uid'] == record['review']['ds_uid'] and validate_daemonset(current_ds) == record['review']['ds_spec_sha256'], 'Calico template changed before deletion')
        current = get('pod', pod['metadata']['name'], 'kube-system')
        validate_pod(current, current_ds, args.node, True)
        require(current['metadata']['uid'] == record['review']['pod_uid'], 'Pod changed before deletion')
        delete_exact(current)
    else:
        require(record['phase'] in ('replacing', 'checking'), 'Calico Pod changed outside this maintenance')
    wait_for_replacement(record)
    record['phase'] = 'checking'; save_record(record)
    if not record.get('network_proof') or not record.get('network_cleanup'):
        disposable_network_check(record)
    deadline = time.monotonic() + 300; stable = None; last_error = None
    while time.monotonic() < deadline:
        try:
            require_lock(record); validate_recorded_runtime(record)
            after = health(args.node)
            require(after['member_ids'] == record['member_ids'], 'etcd membership changed during maintenance')
            ds = get('daemonset', 'calico-node', 'kube-system')
            for node in sorted(NODES): node_pod(ds, node, True)
            if stable is None: stable = time.monotonic()
            if time.monotonic() - stable >= 30:
                release(record); record['phase'] = 'verified'; record['verified_unix'] = time.time(); save_record(record)
                return {'node': args.node, 'changed': True, 'endpoint': ENDPOINT, 'health': after,
                        'renewed_token_authenticated': True, 'network': record['network_proof'], 'probe_removed': True, 'stable_seconds': 30}
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            last_error = str(error); stable = None
        time.sleep(5)
    raise RuntimeError('Recovery not verified; cluster lock retained: ' + str(last_error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'apply'))
    parser.add_argument('--node', choices=sorted(NODES), required=True)
    parser.add_argument('--ca-sha256')
    parser.add_argument('--review-json')
    args = parser.parse_args(); require(os.geteuid() == 0, 'Run on the owned node as root')
    if args.action == 'inspect':
        proof, *_, record = inspect(args.node, args.ca_sha256)
        lock_available(record); proof['health'] = health(args.node)
        print(json.dumps(proof, sort_keys=True)); return
    require(args.ca_sha256 and args.review_json, 'Apply requires the reviewed CA and exact per-node identity')
    trusted(BOOTSTRAP, True)
    with BOOTSTRAP.open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        print(json.dumps(apply(args), sort_keys=True))


if __name__ == '__main__': main()

