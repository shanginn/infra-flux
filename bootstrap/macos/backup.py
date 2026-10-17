#!/usr/bin/env python3
"""Pull bounded, verified backups into a local encrypted restic repository."""
import argparse
from contextlib import closing
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

HOME = Path.home()
STATE = HOME / 'Library/Application Support/infra-flux'
CONFIG = STATE / 'backup.json'
PASSWORD = STATE / 'restic-password'
STATUS = STATE / 'backup-status.json'
SOURCE = Path(__file__).resolve().parent
OWNER = 'infra-flux/macos-backup-v1'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic_json(path, value):
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with temporary.open('x') as handle:
            os.chmod(temporary, 0o600)
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def settings(path):
    config = json.loads(path.read_text())
    config['_path'] = str(path.resolve())
    require(config.get('owner') == OWNER, 'Run install.py to create the owned configuration')
    require(PASSWORD.is_file() and not PASSWORD.is_symlink(), 'Missing private repository password')
    require(PASSWORD.stat().st_mode & 0o077 == 0, 'Repository password must have mode 0600')
    require(STATE.stat().st_mode & 0o077 == 0, 'Backup settings directory must have mode 0700')
    config['repository'] = str(Path(config['repository']).expanduser().resolve())
    require(not Path(config['repository']).is_relative_to(STATE), 'Store the repository separately from its password')
    require(config['jobs'] and len({j['name'] for j in config['jobs']}) == len(config['jobs']), 'Invalid job list')
    for job in config['jobs']:
        require(job['name'] and all(c.isalnum() or c in '-_' for c in job['name']), 'Invalid job name')
        require(job['component'] in ('headscale', 'etcd', 'node-config', 'garage', 'postgres'), 'Unsupported exporter')
        require(job['ssh_aliases'], 'At least one SSH source is required')
        for alias in job['ssh_aliases']:
            require(alias and all(c.isalnum() or c in '-_.' for c in alias), 'Invalid SSH alias')
        maximum = 34359738368 if job['component'] in ('garage', 'postgres') else 536870912
        require(1048576 <= job['max_bytes'] <= maximum, 'Invalid stream size bound')
        if job['component'] == 'garage':
            require(0 <= job.get('max_objects', 100000) <= 100000, 'Invalid Garage object limit')
        if job['component'] == 'postgres':
            require(job.get('restore_ssh_alias') and all(c.isalnum() or c in '-_.' for c in job['restore_ssh_alias']),
                    'PostgreSQL requires an explicit isolated restore SSH alias')
    metrics = config.get('metrics_publication', {})
    if metrics.get('enabled', False):
        require(re.fullmatch(r'[0-9a-f]{64}', metrics.get('ca_sha256', '')) and metrics.get('cluster_name'), 'Metrics need an explicit cluster CA identity')
        require(metrics.get('ssh_aliases') and all(re.fullmatch(r'[A-Za-z0-9_.-]+', alias) for alias in metrics['ssh_aliases']), 'Invalid metrics SSH aliases')
    return config


def restic(config, arguments, *, timeout=1800):
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith('RESTIC_'):
            del environment[name]
    environment.update(RESTIC_REPOSITORY=config['repository'], RESTIC_PASSWORD_FILE=str(PASSWORD),
                       RESTIC_CACHE_DIR=str(STATE / 'cache'))
    return subprocess.run([config['restic'], '--json', *arguments], env=environment,
                          capture_output=True, timeout=timeout, check=True)


def export(job, alias):
    """This command is the producer supervised by restic --stdin-from-command."""
    require(alias in job['ssh_aliases'], 'Unconfigured SSH source')
    filename = {'headscale': 'export-headscale.py', 'garage': 'garage-stream.py',
                'postgres': 'export-postgres.py'}.get(job['component'], 'export-node.py')
    code = (SOURCE / filename).read_text()
    if job['component'] == 'garage':
        export_args = ['export', '--max-bytes', str(job['max_bytes']), '--max-objects', str(job.get('max_objects', 100000))]
    elif job['component'] == 'postgres':
        export_args = [str(job['max_bytes']), job['cluster_name']]
    else:
        export_args = [job['hostname'] if job['component'] == 'headscale' else job['component'], str(job['max_bytes'])]
    remote_argv = ['/usr/bin/python3', '-c', code, *export_args]
    if job['component'] == 'etcd' and job.get('offline_restore_check', False):
        remote_argv.append('offline-restore')
    remote = shlex.join(remote_argv)
    arguments = ['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                 '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                 alias, remote]
    with subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            total = 0
            while block := process.stdout.read(1024 * 1024):
                total += len(block)
                require(total <= job['max_bytes'], 'Remote stream exceeds its bound')
                sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()
            require(total > 0 and process.wait(timeout=15) == 0, 'Remote export failed')
        except BaseException:
            process.kill()
            process.wait()
            raise


def archive_name(job):
    return job['name'] + ('.pgdump' if job['component'] == 'postgres' else '.tar')


def load_exporter(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), SOURCE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_large(config, job, snapshot_id, environment):
    """Garage stays streamed; PostgreSQL requires one private SQL file for real restore."""
    filename = 'garage-stream.py' if job['component'] == 'garage' else 'verify-postgres.py'
    module = load_exporter(filename)
    with tempfile.TemporaryDirectory(prefix='verify-data-', dir=STATE) as temporary:
        with subprocess.Popen([config['restic'], 'dump', snapshot_id, '/' + archive_name(job)],
                              env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                if job['component'] == 'garage':
                    proof = module.verify_stream(process.stdout, job['max_bytes'], job.get('max_objects', 100000), job['cluster_name'])
                else:
                    sql = Path(temporary) / 'postgres.sql'
                    metadata = module.read_stream(process.stdout, sql, job['max_bytes'], job['cluster_name'])
                require(process.wait(timeout=60) == 0, 'Restic data restore failed')
            except BaseException:
                process.kill()
                process.wait()
                raise
        if job['component'] == 'postgres':
            proof = module.verify_restore(metadata, sql, job['restore_ssh_alias'])
        return proof


def verify(config, job, snapshot_id):
    """Decrypt and restore every member; keep plaintext only in a private temporary directory."""
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith('RESTIC_'):
            del environment[name]
    environment.update(RESTIC_REPOSITORY=config['repository'], RESTIC_PASSWORD_FILE=str(PASSWORD),
                       RESTIC_CACHE_DIR=str(STATE / 'cache'))
    if job['component'] in ('garage', 'postgres'):
        return verify_large(config, job, snapshot_id, environment)
    expected = {'db.sqlite', 'noise_private.key', 'headscale.yaml', 'derp.yaml', 'policy.json',
                f'tls/{job.get("hostname")}.crt', f'tls/{job.get("hostname")}.key'} if job['component'] == 'headscale' else None
    with tempfile.TemporaryDirectory(prefix='verify-', dir=STATE) as temporary:
        staging = Path(temporary)
        with subprocess.Popen([config['restic'], 'dump', snapshot_id, '/' + archive_name(job)],
                              env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                total, seen = 0, set()
                with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                    for member in archive:
                        name = Path(member.name)
                        recovery_keys = {'var/lib/infra-headscale-recovery/' + name for name in
                                         ('identity.age', 'pull_ed25519', 'pull_ed25519.pub', 'known_hosts')}
                        allowed = (member.name in expected | {'manifest.json'}) if expected else (
                            member.name in {'manifest.json', 'etcd/snapshot.db'} or
                            member.name.startswith(('etc/infra-flux/', 'etc/infra-overlay/', 'etc/kubernetes/',
                                                    'etc/infra-garage/', 'etc/infra-postgres/')) or
                            member.name == 'var/lib/tailscale/tailscaled.state' or
                            (job['component'] == 'node-config' and member.name in recovery_keys))
                        require(member.isfile() and allowed and not name.is_absolute() and '..' not in name.parts and
                                member.name not in seen,
                                'Unexpected archive member')
                        total += member.size
                        require(0 <= member.size <= job['max_bytes'] and total <= job['max_bytes'], 'Archive exceeds bound')
                        target = staging / member.name
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        with archive.extractfile(member) as source, target.open('xb') as destination:
                            shutil.copyfileobj(source, destination)
                        seen.add(member.name)
                # Drain only padding, without retaining another copy of the archive.
                tail = process.stdout.read(job['max_bytes'] - total + 1)
                require(len(tail) + total <= job['max_bytes'] and not tail.strip(b'\0'), 'Unexpected archive tail')
                require(process.wait(timeout=30) == 0, 'Restic restore failed')
            except BaseException:
                process.kill()
                process.wait()
                raise
        require('manifest.json' in seen, 'Missing manifest')
        manifest = json.loads((staging / 'manifest.json').read_text())
        require(manifest['format'] == 1 and manifest['component'] == job['component'], 'Backup identity differs')
        names = seen - {'manifest.json'}
        if expected:
            require(names == expected and manifest['hostname'] == job['hostname'], 'Incomplete coordinator archive')
        else:
            require(manifest['cluster_name'] == job['cluster_name'], 'Cluster identity differs')
            require('etc/kubernetes/pki/ca.crt' in names and
                    hashlib.sha256((staging / 'etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest() == manifest['ca_sha256'],
                    'Cluster CA identity differs')
            if job['component'] == 'etcd':
                require('etcd/snapshot.db' in names and manifest['etcd_status'].get('totalKey', 0) > 0,
                        'Missing validated etcd snapshot')
                if job.get('offline_restore_check', False):
                    proof = manifest.get('offline_restore') or {}
                    require(proof.get('completed') is True and proof.get('source_total_keys') == manifest['etcd_status']['totalKey'] and
                            proof.get('total_keys') in (manifest['etcd_status']['totalKey'], manifest['etcd_status']['totalKey'] + 1) and
                            proof.get('revision') == manifest['etcd_status']['revision'] + proof.get('revision_bump', 0),
                            'Missing successful offline etcd restore')
        require(set(manifest['sha256']) == names, 'Manifest file list differs')
        for name in names:
            require(hashlib.sha256((staging / name).read_bytes()).hexdigest() == manifest['sha256'][name],
                    'Restored content checksum differs')
        if job['component'] == 'headscale':
            with closing(sqlite3.connect(f'file:{staging / "db.sqlite"}?mode=ro', uri=True)) as database:
                require(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'Restored SQLite is invalid')


def backup_job(config, job):
    for alias in job['ssh_aliases']:
        try:
            output = restic(config, ['backup', '--host', job['name'], '--tag', 'infra-unified,pending',
                                    '--stdin-filename', archive_name(job), '--stdin-from-command', '--',
                                    sys.executable, str(SOURCE / 'backup.py'), '--config', config['_path'], 'export', job['name'],
                                    '--source', alias], timeout=7200 if job['component'] in ('garage', 'postgres') else 1800)
            summary = [json.loads(line) for line in output.stdout.splitlines() if line.strip()]
            ids = [item['snapshot_id'] for item in summary if item.get('message_type') == 'summary' and item.get('snapshot_id')]
            require(len(ids) == 1, 'Missing unambiguous restic snapshot ID')
            proof = verify(config, job, ids[0])
            output = restic(config, ['tag', '--add', 'verified', '--remove', 'pending', ids[0]])
            changes = [json.loads(line) for line in output.stdout.splitlines() if line.strip()]
            ids = [item['new_snapshot_id'] for item in changes if item.get('message_type') == 'changed']
            require(len(ids) == 1, 'Missing verified snapshot ID')
            outcome = {'last_success': int(time.time()), 'snapshot_id': ids[0], 'source': alias, 'ok': True}
            if proof is not None:
                outcome['verification'] = proof
            return outcome
        except Exception:
            if alias == job['ssh_aliases'][-1]:
                raise


def notify_failure(metrics=False):
    message = ('Не опубликован статус резервных копий в мониторинг. Проверьте backup-status.json.' if metrics else
               'Резервная копия не завершена. Проверьте infra-flux backup-status.json.')
    subprocess.run(['/usr/bin/osascript', '-e',
                    'display notification "' + message + '" with title "Резервное копирование инфраструктуры"'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)


def publish_metrics(config):
    metrics = config.get('metrics_publication', {})
    if not metrics.get('enabled', False):
        return
    current = json.loads(STATUS.read_text()) if STATUS.exists() else {'jobs': {}}
    payload = {'cluster_name': metrics['cluster_name'], 'ca_sha256': metrics['ca_sha256'], 'jobs': []}
    for job in config['jobs']:
        state = current.get('jobs', {}).get(job['name'], {})
        payload['jobs'].append({'name': job['name'], 'configured': int(job.get('enabled', False)),
            'last_success': int(state.get('last_success', 0)), 'last_attempt_success': int(state.get('ok', False))})
    code = (SOURCE / 'publish-backup-metrics.py').read_text()
    remote = shlex.join(['/usr/bin/python3', '-c', code])
    outcomes = {}
    for alias in metrics['ssh_aliases']:
        try:
            subprocess.run(['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                            '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', alias, remote],
                           input=json.dumps(payload).encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=True)
            outcomes[alias] = {'ok': True}
        except Exception as error:
            outcomes[alias] = {'ok': False, 'error_type': type(error).__name__}
    ok = all(item['ok'] for item in outcomes.values())
    current['metrics_publication'] = {'last_attempt': int(time.time()), 'ok': ok, 'targets': outcomes}
    atomic_json(STATUS, current)  # Keep actual backup result separate from monitoring delivery.
    if not ok:
        try:
            notify_failure(metrics=True)
        except Exception:
            pass


def run_backup(config, force=False):
    previous = json.loads(STATUS.read_text()) if STATUS.exists() else {'jobs': {}}
    current = datetime.datetime.now().astimezone()
    hour, minute = map(int, config.get('daily_time', '03:30').split(':'))
    latest_due = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if latest_due > current:
        latest_due -= datetime.timedelta(days=1)
    enabled = [job for job in config['jobs'] if job.get('enabled', False)]
    require(enabled, 'No enabled backup jobs')
    if not force and previous.get('ok') and all(previous['jobs'].get(job['name'], {}).get('last_success', 0) >= latest_due.timestamp() for job in enabled):
        return
    status = previous | {'last_attempt': int(time.time()), 'ok': False}
    try:
        require(shutil.disk_usage(config['repository']).free >= config['minimum_free_bytes'], 'Not enough free backup space')
        failures = []
        for job in enabled:
            prior = status['jobs'].get(job['name'], {})
            if not force and prior.get('ok') and prior.get('last_success', 0) >= latest_due.timestamp():
                continue
            try:
                extra = job['max_bytes'] if job['component'] == 'garage' else (2 * job['max_bytes'] + 2147483648 if job['component'] == 'postgres' else 0)
                require(shutil.disk_usage(config['repository']).free >= config['minimum_free_bytes'] + extra,
                        'Insufficient space for data backup/restore and the configured reserve')
                status['jobs'][job['name']] = backup_job(config, job)
            except Exception as error:
                status['jobs'][job['name']] = prior | {'ok': False, 'last_failure': int(time.time()), 'error_type': type(error).__name__}
                failures.append(job['name'])
            atomic_json(STATUS, status)
        require(not failures, 'One or more backup sources failed')
        # Verification precedes retention. Failed/pending snapshots are never selected by retention.
        restic(config, ['check'])
        maintenance_due = time.time() - status.get('last_full_check', 0) >= 7 * 86400
        if maintenance_due:
            restic(config, ['check', '--read-data'], timeout=7200)
            status['last_full_check'] = int(time.time())
        restic(config, ['forget', '--tag', 'infra-unified,verified', '--group-by', 'host,paths',
                        '--keep-daily', '7', '--keep-weekly', '4', '--keep-monthly', '6'])
        if maintenance_due:
            restic(config, ['prune', '--max-unused', '5%'], timeout=7200)
        status.update(ok=True, last_success=int(time.time()))
        status.pop('error_type', None)
        atomic_json(STATUS, status)
        print('Backup stored, restored for verification, and checked')
    except BaseException as error:
        status.update(ok=False, error_type=type(error).__name__)
        atomic_json(STATUS, status)
        try:
            notify_failure()
        except Exception:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=CONFIG)
    parser.add_argument('action', choices=('run', 'export', 'verify'))
    parser.add_argument('job', nargs='?')
    parser.add_argument('--snapshot')
    parser.add_argument('--source')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    config = settings(args.config)
    if args.action == 'export':
        def interrupted(*_):
            raise TimeoutError('Export interrupted')
        signal.signal(signal.SIGALRM, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        job = next(job for job in config['jobs'] if job['name'] == args.job)
        signal.alarm(7200 if job['component'] in ('garage', 'postgres') else 480)
        export(job, args.source)
        return
    with (STATE / 'backup.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if args.action == 'verify':
            require(args.snapshot and args.job, 'Select a job and snapshot ID')
            verify(config, next(job for job in config['jobs'] if job['name'] == args.job), args.snapshot)
            print('Restored snapshot contents verified')
        else:
            try:
                run_backup(config, args.force)
            finally:
                publish_metrics(config)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Backup failed ({type(error).__name__}); previous snapshots are retained', file=sys.stderr)
        sys.exit(1)
