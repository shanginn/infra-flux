#!/usr/bin/env python3
"""Guarded PostgreSQL prerequisites; secrets stay on hosts and in Kubernetes."""
import argparse
import base64
import grp
import ipaddress
import json
import os
import pathlib
import pwd
import secrets
import subprocess
import tempfile

OWNER = 'infra-flux/ansible/postgres'
ROOT = pathlib.Path('/etc/infra-postgres')
DATA = pathlib.Path('/var/lib/infra-postgres/unified')
MARKER = ROOT / 'ownership.json'
BUNDLE = ROOT / 'runtime.json'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']


def kube(args, body=None):
    result = subprocess.run(KUBE + args, input=json.dumps(body) if body else None,
                            text=True, capture_output=True, check=True, timeout=30)
    return json.loads(result.stdout) if result.stdout.strip() else None


def atomic(path, data):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, sort_keys=True)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def identity(cluster_uid):
    assert kube(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid'] == cluster_uid
    nodes = {n['metadata']['name']: n for n in kube(['get', 'nodes', '-o', 'json'])['items']}
    for site in ('home', 'msk', 'fin'):
        assert nodes[site]['metadata']['labels']['infra.shanginn.io/site'] == site
        assert any(c['type'] == 'Ready' and c['status'] == 'True' for c in nodes[site]['status']['conditions'])
        addresses = [a['address'] for a in nodes[site]['status']['addresses'] if a['type'] == 'InternalIP']
        assert len(addresses) == 1 and ipaddress.ip_address(addresses[0]) in ipaddress.ip_network('100.64.0.0/10')


def owner(cluster_uid, node):
    return {'managed_by': OWNER, 'cluster_uid': cluster_uid, 'node': node, 'uid': 19999, 'gid': 19999, 'storage_bytes': 25769803776}


def prepare(args):
    identity(args.cluster_uid)
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try: lookup(19999)
        except KeyError: pass
        else: raise RuntimeError('Container UID/GID 19999 is already assigned on host')
    for path in (ROOT, MARKER, BUNDLE, DATA.parent, DATA):
        assert not path.is_symlink(), 'Refuse symlink: ' + str(path)
    owned = MARKER.exists()
    if owned:
        assert json.loads(MARKER.read_text()) == owner(args.cluster_uid, args.node)
        assert DATA.is_dir() and DATA.stat().st_uid == 19999 and DATA.stat().st_gid == 19999
    else:
        assert not ROOT.exists() or not any(ROOT.iterdir()), 'Unowned PostgreSQL configuration'
        assert not DATA.parent.exists() or not any(DATA.parent.iterdir()), 'Unowned PostgreSQL data'
    if not BUNDLE.exists() and DATA.exists():
        assert not any(DATA.iterdir()), 'Restore original runtime identity before touching PostgreSQL data'
    if BUNDLE.exists():
        saved = json.loads(BUNDLE.read_text())
        assert saved['managed_by'] == OWNER and saved['cluster_uid'] == args.cluster_uid
    # A local PV declaration reserves no filesystem blocks. Keep the unfilled
    # part of its budget free even when preparation created an empty directory.
    used_bytes = 0
    if owned:
        usage = subprocess.run(['/usr/bin/du', '-sx', '--block-size=1', str(DATA)],
                               text=True, capture_output=True, check=True, timeout=30)
        used_bytes = int(usage.stdout.split()[0])
    budget_bytes = 24 * 1024**3
    assert used_bytes <= budget_bytes, 'PostgreSQL exceeds its approved storage budget'
    fs = os.statvfs(DATA if owned else '/var/lib')
    assert args.other_reserve_gib >= 20
    assert fs.f_bavail * fs.f_frsize >= args.other_reserve_gib * 1024**3 + budget_bytes - used_bytes
    assert fs.f_favail >= 100000
    if args.command == 'check':
        return
    ROOT.mkdir(mode=0o700, exist_ok=True)
    DATA.parent.mkdir(mode=0o700, exist_ok=True)
    DATA.mkdir(mode=0o700, exist_ok=True)
    os.chown(DATA, 19999, 19999)
    if not owned:
        atomic(MARKER, owner(args.cluster_uid, args.node))


def create(args):
    identity(args.cluster_uid)
    assert json.loads(MARKER.read_text()) == owner(args.cluster_uid, 'msk')
    if BUNDLE.exists():
        existing = json.loads(BUNDLE.read_text())
        assert existing['managed_by'] == OWNER and existing['cluster_uid'] == args.cluster_uid
        return
    assert not any(DATA.iterdir()), 'Never regenerate credentials for existing data'
    for name in ('patroni-credentials', 'patroni-server-tls'):
        assert kube(['get', 'secret', name, '-n', 'database', '--ignore-not-found', '-o', 'json']) is None
    passwords = {r + '-password': secrets.token_urlsafe(48) for r in ('superuser', 'replication', 'rewind', 'restapi')}
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='.pki-') as directory:
        p = pathlib.Path(directory)
        def openssl(*argv):
            subprocess.run(['openssl', *argv], cwd=p, check=True, capture_output=True, timeout=60)
        openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '3650', '-subj', '/CN=infra-postgres-ca', '-keyout', 'ca.key', '-out', 'ca.crt')
        openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=unified-postgres.database.svc', '-keyout', 'tls.key', '-out', 'tls.csr')
        names = [name + suffix for name in ('unified-postgres', 'unified-postgres-replicas', 'unified-postgres-members') for suffix in ('', '.database', '.database.svc', '.database.svc.cluster.local')]
        (p / 'extensions').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + n for n in names) + '\n')
        openssl('x509', '-req', '-in', 'tls.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '365', '-extfile', 'extensions', '-out', 'tls.crt')
        pki = {name: base64.b64encode((p / name).read_bytes()).decode() for name in ('ca.crt', 'ca.key', 'tls.crt', 'tls.key')}
    atomic(BUNDLE, {'managed_by': OWNER, 'cluster_uid': args.cluster_uid, 'passwords': passwords, 'pki': pki})


def publish(args):
    identity(args.cluster_uid)
    bundle = json.loads(BUNDLE.read_text())
    assert bundle['managed_by'] == OWNER and bundle['cluster_uid'] == args.cluster_uid
    ns = kube(['get', 'namespace', 'database', '--ignore-not-found', '-o', 'json'])
    if ns:
        assert ns['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER
    else:
        kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'database', 'annotations': {'infra.shanginn.io/managed-by': OWNER}, 'labels': {'pod-security.kubernetes.io/enforce': 'restricted'}}})
    contents = {'patroni-credentials': {k: base64.b64encode(v.encode()).decode() for k, v in bundle['passwords'].items()},
                'patroni-server-tls': {k: bundle['pki'][k] for k in ('tls.crt', 'tls.key', 'ca.crt')}}
    for name, data in contents.items():
        current = kube(['get', 'secret', name, '-n', 'database', '--ignore-not-found', '-o', 'json'])
        if current:
            assert current['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER
            assert current['data'] == data, 'Never rotate credentials or TLS identity implicitly'
        else:
            kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': 'database', 'annotations': {'infra.shanginn.io/managed-by': OWNER}}, 'type': 'Opaque', 'data': data})


parser = argparse.ArgumentParser()
parser.add_argument('command', choices=['check', 'prepare', 'create', 'publish'])
parser.add_argument('--cluster-uid', required=True)
parser.add_argument('--node', choices=['msk', 'fin', 'home'], default='msk')
parser.add_argument('--other-reserve-gib', type=int, default=0)
args = parser.parse_args()
assert os.geteuid() == 0
os.umask(0o077)
if args.command in ('check', 'prepare'): prepare(args)
elif args.command == 'create': create(args)
else: publish(args)
print(json.dumps({'action': args.command, 'verified': True}))
