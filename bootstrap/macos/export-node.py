#!/usr/bin/env python3
"""Export bounded state only from the owned kubeadm cluster over existing SSH."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, timeout=180):
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=True)


def export(component, max_bytes, offline_restore_check=False):
    require(os.geteuid() == 0 and component in ('etcd', 'node-config'), 'Invalid export')
    require(1048576 <= max_bytes <= 536870912, 'Invalid snapshot bound')
    os.umask(0o077)
    def interrupted(*_):
        raise TimeoutError('Export interrupted')
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(420)
    marker = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    require(marker['managed_by'] == 'infra-flux/ansible/kubeadm', 'Cluster is not managed by this automation')
    node = marker['node_name']
    require(node and all(c.isalnum() or c in '-.' for c in node), 'Invalid node name')
    require(hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest() == marker['ca_sha256'],
            'Cluster CA differs from the ownership marker')
    require(command(['/usr/bin/findmnt', '-n', '-o', 'FSTYPE', '--target', '/run']).stdout.strip() == b'tmpfs',
            'Temporary configuration staging requires /run tmpfs')
    require(shutil.disk_usage('/run').free >= max_bytes * 2, 'Not enough temporary memory')
    with tempfile.TemporaryDirectory(prefix='infra-mac-node-', dir='/run') as temporary:
        staging = Path(temporary)
        snapshot_dir = None
        try:
            roots = [Path('/etc/infra-flux'), Path('/etc/infra-overlay'), Path('/etc/kubernetes')]
            if component == 'etcd':
                roots = [Path('/etc/infra-flux/kubeadm'), Path('/etc/infra-flux/kubeadm-state.json'), Path('/etc/kubernetes/pki')]
            else:
                for directory, ownership_file, expected_owner in (
                    ('/etc/infra-garage', '/etc/infra-flux/garage.json', 'infra-flux/ansible/garage'),
                    ('/etc/infra-postgres', '/etc/infra-postgres/ownership.json', 'infra-flux/ansible/postgres'),
                ):
                    path = Path(directory)
                    if path.exists():
                        owner = json.loads(Path(ownership_file).read_text())
                        require(owner.get('managed_by') == expected_owner, 'Unmanaged database/storage identity')
                        roots.append(path)
                # Restore this identity only after fencing the old node; never clone a live VPN client.
                tailscale_state = Path('/var/lib/tailscale/tailscaled.state')
                require(tailscale_state.is_file() and not tailscale_state.is_symlink(), 'Missing VPN client identity')
                roots.append(tailscale_state)
                # Exact recovery-key allowlist; do not archive snapshots or other /var/lib contents.
                recovery = Path('/var/lib/infra-headscale-recovery')
                if recovery.exists():
                    backup_owner = json.loads(Path('/etc/infra-flux/headscale-backup.json').read_text())
                    require(backup_owner.get('owner') == 'infra-flux/ansible/headscale-backup', 'Unmanaged recovery state')
                    require(not recovery.is_symlink(), 'Recovery directory is a symlink')
                    keys = [recovery / name for name in ('identity.age', 'pull_ed25519', 'pull_ed25519.pub', 'known_hosts')]
                    require(all(key.is_file() and not key.is_symlink() for key in keys), 'Incomplete recovery key set')
                    roots.extend(keys)
            names = []
            size = 0
            for root in roots:
                if not root.exists():
                    continue
                require(not root.is_symlink(), 'Refusing a symlinked configuration root')
                for source in ([root] if root.is_file() else sorted(root.rglob('*'))):
                    require(not source.is_symlink(), 'Refusing symlinks in protected configuration')
                    if source.is_dir():
                        continue
                    require(source.is_file(), 'Unexpected configuration file type')
                    size += source.stat().st_size
                    require(size + 65536 < max_bytes, 'Configuration exceeds size bound')
                    name = str(source.relative_to('/'))
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    shutil.copyfile(source, target)
                    names.append(name)
            metadata = {}
            restore_check = None
            if component == 'etcd':
                prefix = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '-n', 'kube-system',
                          'exec', f'etcd-{node}', '--']
                client = ['etcdctl', '--endpoints=https://127.0.0.1:2379',
                          '--cacert=/etc/kubernetes/pki/etcd/ca.crt',
                          '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt',
                          '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key']
                command(prefix + client + ['endpoint', 'health'])
                endpoints = json.loads(command(prefix + client + ['endpoint', 'status', '--write-out=json']).stdout)
                require(len(endpoints) == 1 and endpoints[0]['Status']['dbSize'] + size + 1048576 < max_bytes,
                        'etcd database exceeds the snapshot size bound')
                require(shutil.disk_usage('/var/lib/etcd').free >= max_bytes * (3 if offline_restore_check else 2),
                        'Not enough temporary snapshot and restore space')
                # Only this UUID directory is ever deleted. The live member directory is not touched.
                snapshot_dir = Path('/var/lib/etcd') / ('.infra-mac-backup-' + uuid.uuid4().hex)
                snapshot_dir.mkdir(mode=0o700)
                snapshot = snapshot_dir / 'snapshot.db'
                command(prefix + client + ['snapshot', 'save', str(snapshot)])
                require(snapshot.is_file() and not snapshot.is_symlink() and snapshot.stat().st_size + size + 65536 < max_bytes,
                        'etcd snapshot exceeds its bound')
                metadata = json.loads(command(prefix + ['etcdutl', 'snapshot', 'status', str(snapshot), '--write-out=json']).stdout)
                if offline_restore_check:
                    restored = snapshot_dir / 'offline-restore'
                    require(not restored.exists(), 'Restore destination must be new')
                    # etcdutl writes a new data directory only. It does not start etcd or bind a listener.
                    # The embedded snapshot hash is checked; --skip-hash-check is deliberately absent.
                    command(prefix + ['etcdutl', 'snapshot', 'restore', str(snapshot), '--data-dir', str(restored),
                                      '--name', 'offline-check', '--initial-cluster', 'offline-check=http://127.0.0.1:2380',
                                      '--initial-advertise-peer-urls', 'http://127.0.0.1:2380',
                                      '--initial-cluster-token', 'infra-offline-' + uuid.uuid4().hex,
                                      '--bump-revision', '1000000000', '--mark-compacted'])
                    restored_db = restored / 'member/snap/db'
                    require(restored_db.is_file() and (restored / 'member/wal').is_dir(), 'Offline restore did not create member data')
                    restored_status = json.loads(command(prefix + ['etcdutl', 'snapshot', 'status', str(restored_db), '--write-out=json']).stdout)
                    # etcdutl 3.6 counts the empty revision-bump marker as one extra key before etcd starts.
                    require(restored_status['totalKey'] in (metadata['totalKey'], metadata['totalKey'] + 1) and
                            restored_status['revision'] == metadata['revision'] + 1000000000,
                            'Offline restored keys or revision differ')
                    restore_check = {'completed': True, 'revision_bump': 1000000000,
                                     'source_total_keys': metadata['totalKey'],
                                     'total_keys': restored_status['totalKey'], 'revision': restored_status['revision']}
                # This file is already a consistent etcd snapshot; no full tar is written on the VPS.
                target = staging / 'etcd/snapshot.db'
                target.parent.mkdir(mode=0o700)
                shutil.copyfile(snapshot, target)
                names.append('etcd/snapshot.db')
            require(names, 'No configuration files were selected')
            manifest = {
                'format': 1, 'component': component, 'created_at': int(time.time()),
                'node_name': node, 'cluster_name': marker['cluster_name'], 'ca_sha256': marker['ca_sha256'],
                'etcd_status': metadata,
                'offline_restore': restore_check,
                'sha256': {name: hashlib.sha256((staging / name).read_bytes()).hexdigest() for name in names},
            }
            (staging / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
            with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
                for name in ['manifest.json', *names]:
                    file = staging / name
                    header = tarfile.TarInfo(name)
                    header.size = file.stat().st_size
                    header.mode = 0o600
                    with file.open('rb') as handle:
                        archive.addfile(header, handle)
        finally:
            if snapshot_dir is not None:
                shutil.rmtree(snapshot_dir)


if __name__ == '__main__':
    try:
        export(sys.argv[1], int(sys.argv[2]), len(sys.argv) > 3 and sys.argv[3] == 'offline-restore')
    except Exception as error:
        print(f'Owned node export failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
