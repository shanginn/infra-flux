#!/usr/bin/env python3
"""Encrypted coordinator snapshots and explicitly fenced recovery."""
import argparse
from contextlib import closing
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import uuid

import yaml

CONFIG = Path('/etc/infra-overlay/headscale-backup.json')
RUNTIME = Path('/run/infra-headscale-backup')
DATA = Path('/var/lib/infra-headscale')
OVERLAY = Path('/etc/infra-overlay')
RECOVERY = Path('/var/lib/infra-headscale-recovery')
OWNER = 'infra-flux/ansible/headscale-backup'
METRICS = Path('/var/lib/node_exporter/textfile_collector/headscale-backup.prom')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=180, **kwargs)


def atomic_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with open(temporary, 'x', encoding='utf-8') as handle:
            os.chmod(temporary, mode)
            json.dump(value, handle, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def metrics(status, configured=True):
    last_success = status.get('last_success')
    timestamp = datetime.datetime.fromisoformat(last_success).timestamp() if last_success else 0
    payload = '\n'.join([
        f'infra_backup_configured{{component="headscale"}} {int(configured)}',
        f'infra_backup_last_success_timestamp_seconds{{component="headscale"}} {timestamp}',
        f'infra_backup_last_attempt_success{{component="headscale"}} {int(status.get("ok", False))}',
        'infra_backup_max_age_seconds{component="headscale"} 3600',
        '',
    ])
    METRICS.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = METRICS.with_name('.headscale-backup-' + uuid.uuid4().hex)
    try:
        with open(temporary, 'x') as handle:
            os.chmod(temporary, 0o644)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, METRICS)
    finally:
        temporary.unlink(missing_ok=True)


def files(config):
    hostname = config['hostname']
    return {
        'db.sqlite': DATA / 'db.sqlite',
        'noise_private.key': DATA / 'noise_private.key',
        'headscale.yaml': OVERLAY / 'headscale.yaml',
        'derp.yaml': OVERLAY / 'derp.yaml',
        'policy.json': OVERLAY / 'policy.json',
        f'tls/{hostname}.crt': DATA / 'tls' / f'{hostname}.crt',
        f'tls/{hostname}.key': DATA / 'tls' / f'{hostname}.key',
    }


def digest(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_sqlite(path):
    with closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=30)) as database:
        result = database.execute('PRAGMA integrity_check').fetchall()
        require(result == [('ok',)], 'SQLite integrity verification failed')


def check_identity(directory, config):
    settings = yaml.safe_load((directory / 'headscale.yaml').read_text())
    require(settings['server_url'].rstrip('/') == config['server_url'], 'Coordinator DNS identity differs')
    require(settings['prefixes']['v4'] == config['tailnet_prefix'], 'VPN prefix differs')
    hostname = config['hostname']
    cert = run(['/usr/bin/openssl', 'x509', '-in', str(directory / 'tls' / f'{hostname}.crt'), '-pubkey', '-noout']).stdout
    key = run(['/usr/bin/openssl', 'pkey', '-in', str(directory / 'tls' / f'{hostname}.key'), '-pubout']).stdout
    require(cert == key, 'TLS certificate and private key do not match')
    host_check = run(['/usr/bin/openssl', 'x509', '-in', str(directory / 'tls' / f'{hostname}.crt'), '-noout', '-checkhost', hostname])
    require(b'does match certificate' in host_check.stdout, 'TLS certificate DNS identity differs')
    require((directory / 'noise_private.key').stat().st_size > 0, 'Missing coordinator Noise identity')
    check_sqlite(directory / 'db.sqlite')


def snapshot(config):
    require(config['role'] == 'source', 'This host is not the snapshot source')
    require((OVERLAY / 'active-coordinator').is_file(), 'The coordinator is not activated')
    run(['/usr/bin/systemctl', 'is-active', '--quiet', 'infra-headscale.service'])
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='snapshot-', dir=RUNTIME) as temporary:
        staging = Path(temporary)
        require((DATA / 'db.sqlite').stat().st_size < config['max_bytes'], 'Coordinator database exceeds snapshot size limit')
        with closing(sqlite3.connect(f'file:{DATA / "db.sqlite"}?mode=ro', uri=True, timeout=30)) as source:
            with closing(sqlite3.connect(staging / 'db.sqlite')) as target:
                source.backup(target, pages=256, sleep=0.1)
                target.execute('PRAGMA journal_mode=DELETE').fetchone()
        os.chmod(staging / 'db.sqlite', 0o600)
        for name, path in files(config).items():
            if name == 'db.sqlite':
                continue
            require(path.is_file() and not path.is_symlink(), 'Snapshot source must be a regular file')
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, destination)
            os.chmod(destination, 0o600)
        check_identity(staging, config)
        manifest = {
            'format': 1,
            'created_at': now(),
            'source_host': config['source_host'],
            'headscale_version': config['headscale_version'],
            'server_url': config['server_url'],
            'tailnet_prefix': config['tailnet_prefix'],
            'sha256': {name: digest(staging / name) for name in files(config)},
        }
        (staging / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
        size = sum(path.stat().st_size for path in staging.rglob('*') if path.is_file())
        require(size < config['max_bytes'], 'Snapshot exceeds configured size limit')
        with subprocess.Popen(['/usr/bin/age', '-r', config['recipient']], stdin=subprocess.PIPE,
                              stdout=sys.stdout.buffer, stderr=subprocess.PIPE) as cipher:
            try:
                with tarfile.open(fileobj=cipher.stdin, mode='w|') as archive:
                    for name in ['manifest.json', *files(config)]:
                        path = staging / name
                        header = tarfile.TarInfo(name)
                        header.size = path.stat().st_size
                        header.mode = 0o600
                        with open(path, 'rb') as handle:
                            archive.addfile(header, handle)
                cipher.stdin.close()
                require(cipher.wait(timeout=30) == 0, 'Snapshot encryption failed')
            except BaseException:
                cipher.kill()
                cipher.wait()
                raise


def unpack(ciphertext, destination, config):
    require(ciphertext.is_file() and not ciphertext.is_symlink(), 'Snapshot is not a regular file')
    require(0 < ciphertext.stat().st_size <= config['max_bytes'], 'Encrypted snapshot size is invalid')
    raw = destination / 'snapshot.tar'
    run(['/usr/bin/age', '--decrypt', '-i', str(RECOVERY / 'identity.age'), '-o', str(raw), str(ciphertext)])
    require(raw.stat().st_size <= config['max_bytes'], 'Decrypted archive exceeds size limit')
    allowed = {'manifest.json', *files(config)}
    seen = set()
    total = 0
    with tarfile.open(raw, 'r:') as archive:
        for member in archive:
            require(member.name in allowed and member.name not in seen and member.isfile(), 'Unexpected archive member')
            total += member.size
            require(0 <= member.size <= config['max_bytes'] and total <= config['max_bytes'], 'Archive exceeds size limit')
            seen.add(member.name)
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.extractfile(member) as source, open(target, 'xb') as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, 0o600)
    raw.unlink()
    require(seen == allowed, 'Snapshot is incomplete')
    manifest = json.loads((destination / 'manifest.json').read_text())
    require(manifest['format'] == 1, 'Unsupported snapshot format')
    for key in ('source_host', 'headscale_version', 'server_url', 'tailnet_prefix'):
        require(manifest[key] == config[key], 'Snapshot identity differs from recovery configuration')
    require(set(manifest['sha256']) == set(files(config)), 'Snapshot hash list differs')
    for name, expected in manifest['sha256'].items():
        require(digest(destination / name) == expected, 'Snapshot content hash differs')
    check_identity(destination, config)
    return manifest


def pull(config):
    require(config['role'] == 'standby', 'Only the standby may pull snapshots')
    require(not (OVERLAY / 'active-coordinator').exists(), 'Refusing backup pull on an activated coordinator')
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    archives = RECOVERY / 'snapshots'
    archives.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = archives / ('.incoming-' + uuid.uuid4().hex)
    try:
        require(shutil.disk_usage(RECOVERY).free > 2 * config['max_bytes'], 'Insufficient free space for recovery snapshot')
        with open(pending, 'xb') as output:
            os.chmod(pending, 0o600)
            subprocess.run([
                '/usr/bin/ssh', '-F', '/dev/null', '-i', str(RECOVERY / 'pull_ed25519'),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={RECOVERY / "known_hosts"}',
                '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                '-p', str(config['ssh_port']), f'root@{config["source_address"]}', 'snapshot',
            ], stdout=output, stderr=subprocess.PIPE, timeout=240, check=True)
            output.flush()
            os.fsync(output.fileno())
        with tempfile.TemporaryDirectory(prefix='verify-', dir=RUNTIME) as temporary:
            manifest = unpack(pending, Path(temporary), config)
        name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '.age'
        os.replace(pending, archives / name)
        directory = os.open(archives, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        atomic_json(RECOVERY / 'latest.json', {'file': name, 'manifest': manifest})
        status = {'last_success': now(), 'file': name, 'ok': True}
        atomic_json(RECOVERY / 'status.json', status)
        metrics(status)
        old = sorted(archives.glob('*.age'), reverse=True)[config['keep']:]
        for path in old:
            path.unlink()
        print('Encrypted coordinator snapshot stored and verified')
    except BaseException:
        prior = {}
        status = RECOVERY / 'status.json'
        if status.exists():
            prior = json.loads(status.read_text())
        prior.update(ok=False, last_failure=now())
        atomic_json(status, prior)
        metrics(prior)
        raise
    finally:
        pending.unlink(missing_ok=True)


def fence_check(config, args):
    require(config['role'] == 'standby', 'Recovery requires the standby configuration')
    require(args.fenced_source == config['source_host'], 'Confirm the fenced source host explicitly')
    require(args.confirm_server_url == config['server_url'], 'Confirm the unchanged coordinator DNS identity')
    require(not (OVERLAY / 'active-coordinator').exists(), 'This host is already activated')
    result = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'infra-headscale.service'])
    require(result.returncode != 0, 'Stop the target coordinator before recovery')


def restore(config, args):
    fence_check(config, args)
    require(args.snapshot and Path(args.snapshot).name == args.snapshot, 'Specify a snapshot basename')
    require(DATA.is_dir() and not DATA.is_symlink(), 'Target data directory is invalid')
    require(not list(DATA.glob('db.sqlite*')) and not (DATA / 'noise_private.key').exists(),
            'Target has existing coordinator state; refusing to overwrite it')
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='restore-', dir=RUNTIME) as temporary:
        staging = Path(temporary)
        manifest = unpack(RECOVERY / 'snapshots' / args.snapshot, staging, config)
        existing = yaml.safe_load((OVERLAY / 'headscale.yaml').read_text())
        saved = yaml.safe_load((staging / 'headscale.yaml').read_text())
        require(existing['listen_addr'] == saved['listen_addr'], 'Namespace listener differs; reconcile it before restore')
        identity = pwd.getpwnam('infra-headscale')
        for name in ('headscale.yaml', 'derp.yaml', 'policy.json'):
            destination = OVERLAY / name
            previous = RECOVERY / 'before-restore' / name
            previous.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(destination, previous)
            os.chmod(previous, 0o600)
        for name, destination in files(config).items():
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            temporary_target = destination.with_name('.' + destination.name + '.restore')
            shutil.copyfile(staging / name, temporary_target)
            if name in ('db.sqlite', 'noise_private.key'):
                os.chown(temporary_target, identity.pw_uid, identity.pw_gid)
                os.chmod(temporary_target, 0o600)
            elif name.startswith('tls/'):
                os.chown(temporary_target, 0, identity.pw_gid)
                os.chmod(temporary_target, 0o640)
            else:
                os.chown(temporary_target, 0, 0)
                os.chmod(temporary_target, 0o644)
            os.replace(temporary_target, destination)
        atomic_json(RECOVERY / 'restored.json', {'snapshot': args.snapshot, 'manifest': manifest})
    print('Coordinator identity restored; service remains stopped and fenced')


def promote(config, args):
    fence_check(config, args)
    proof = json.loads((RECOVERY / 'restored.json').read_text())
    require(proof['manifest']['server_url'] == config['server_url'], 'Restored identity differs')
    for name, path in files(config).items():
        require(digest(path) == proof['manifest']['sha256'][name], 'Restored state changed before promotion')
    marker_path = Path('/etc/infra-flux/overlay.json')
    marker = json.loads(marker_path.read_text())
    require(marker['owner'] == 'infra-flux/ansible/overlay', 'Target overlay ownership differs')
    run(['/usr/bin/systemctl', 'disable', '--now', 'infra-headscale-backup.timer'])
    metrics({}, configured=False)
    marker['coordinator'] = True
    atomic_json(marker_path, marker, 0o644)
    fence = OVERLAY / 'active-coordinator'
    with open(fence, 'x') as handle:
        os.chmod(fence, 0o600)
        handle.write('Activated after explicit source fencing confirmation\n')
    run(['/usr/bin/systemctl', 'enable', '--now', 'infra-headscale.service'])
    run(['/usr/bin/systemctl', 'is-active', '--quiet', 'infra-headscale.service'])
    print('Restored coordinator started; update its unchanged DNS name and reapply the active-host configuration')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'pull', 'restore', 'promote'))
    parser.add_argument('--snapshot')
    parser.add_argument('--fenced-source')
    parser.add_argument('--confirm-server-url')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'This command requires root')
    config = json.loads(CONFIG.read_text())
    require(config['owner'] == OWNER, 'Backup configuration ownership differs')
    require(1 <= config['keep'] <= 1000, 'Invalid retention count')
    require(1048576 <= config['max_bytes'] <= 536870912, 'Invalid snapshot limit')
    os.umask(0o077)
    if args.action in ('snapshot', 'pull'):
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Snapshot deadline exceeded')))
        signal.alarm(300)
    if args.action == 'snapshot':
        snapshot(config)
    elif args.action == 'pull':
        pull(config)
    elif args.action == 'restore':
        restore(config, args)
    else:
        promote(config, args)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Commands can contain paths to secrets; do not print exception payloads.
        print(f'Coordinator backup/recovery failed ({type(error).__name__}); no promotion was requested automatically', file=sys.stderr)
        sys.exit(1)
