#!/usr/bin/env python3
"""Run through an existing SSH connection; emit a consistent Headscale tar."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time


def export(hostname, max_bytes):
    if os.geteuid() != 0 or not hostname or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in hostname):
        raise RuntimeError('Root and a DNS hostname are required')
    if not 1048576 <= max_bytes <= 536870912:
        raise RuntimeError('Invalid snapshot bound')
    os.umask(0o077)
    def interrupted(*_):
        raise TimeoutError('Export interrupted')
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(300)
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
    overlay = Path('/etc/infra-overlay')
    data = Path('/var/lib/infra-headscale')
    marker = json.loads(Path('/etc/infra-flux/overlay.json').read_text())
    if marker.get('owner') != 'infra-flux/ansible/overlay' or not marker.get('coordinator'):
        raise RuntimeError('Coordinator is not managed by this automation')
    if not (overlay / 'active-coordinator').is_file():
        raise RuntimeError('Coordinator is not activated')
    subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'infra-headscale.service'], check=True)
    filesystem = subprocess.run(['/usr/bin/findmnt', '-n', '-o', 'FSTYPE', '--target', '/run'],
                                capture_output=True, check=True, text=True).stdout.strip()
    if filesystem != 'tmpfs' or shutil.disk_usage('/run').free < max_bytes * 2:
        raise RuntimeError('A sufficiently large /run tmpfs is required')
    sources = {
        'noise_private.key': data / 'noise_private.key',
        'headscale.yaml': overlay / 'headscale.yaml',
        'derp.yaml': overlay / 'derp.yaml',
        'policy.json': overlay / 'policy.json',
        f'tls/{hostname}.crt': data / 'tls' / f'{hostname}.crt',
        f'tls/{hostname}.key': data / 'tls' / f'{hostname}.key',
    }
    with tempfile.TemporaryDirectory(prefix='infra-mac-headscale-', dir='/run') as temporary:
        staging = Path(temporary)
        database = data / 'db.sqlite'
        if not database.is_file() or database.is_symlink() or database.stat().st_size > max_bytes:
            raise RuntimeError('Unexpected coordinator database')
        with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True, timeout=30)) as source:
            with closing(sqlite3.connect(staging / 'db.sqlite')) as target:
                source.backup(target, pages=256, sleep=0.1)
                target.execute('PRAGMA journal_mode=DELETE').fetchone()
                if target.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise RuntimeError('SQLite integrity check failed')
        for name, source in sources.items():
            if not source.is_file() or source.is_symlink():
                raise RuntimeError('Snapshot source is not a regular file')
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, 0o600)
        names = ['db.sqlite', *sources]
        if sum((staging / name).stat().st_size for name in names) + 65536 > max_bytes:
            raise RuntimeError('Snapshot exceeds its size bound')
        cert = subprocess.run(['/usr/bin/openssl', 'x509', '-in', str(staging / f'tls/{hostname}.crt'), '-pubkey', '-noout'],
                              capture_output=True, check=True).stdout
        key = subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(staging / f'tls/{hostname}.key'), '-pubout'],
                             capture_output=True, check=True).stdout
        host = subprocess.run(['/usr/bin/openssl', 'x509', '-in', str(staging / f'tls/{hostname}.crt'), '-noout', '-checkhost', hostname],
                              capture_output=True, check=True).stdout
        if cert != key or b'does match certificate' not in host or (staging / 'noise_private.key').stat().st_size == 0:
            raise RuntimeError('Coordinator TLS or Noise identity is invalid')
        manifest = {
            'format': 1, 'component': 'headscale', 'hostname': hostname, 'created_at': int(time.time()),
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


if __name__ == '__main__':
    try:
        export(sys.argv[1], int(sys.argv[2]))
    except Exception as error:
        print(f'Headscale export failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
