#!/usr/bin/env python3
"""Run as root over SSH: bounded pg_dumpall stream, no server-side archive.

Each database has its own consistent snapshot. This is not a simultaneous
snapshot of every database, nor a physical/PITR backup. Role passwords are part
of the encrypted stream and must never be logged.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

MAGIC = b'INFRA-POSTGRES-DUMPALL/1\n'
IMAGE = 'ghcr.io/shanginn/infra-flux-patroni@sha256:5581048b8a2c28f0e3e16aa481c1b5f094c425edeaa9900bf1aef651da16863f'
KUBE = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, timeout=40):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=timeout)
    require(len(result.stdout) <= 1048576, 'Metadata exceeds bound')
    return result.stdout


def export(max_bytes, cluster_name):
    require(os.geteuid() == 0, 'Root is required for the owned kubeconfig')
    require(1048576 * 4 <= max_bytes <= 32 * 1024**3, 'Invalid stream bound')
    os.umask(0o077)
    def interrupted(*_):
        raise TimeoutError('PostgreSQL export interrupted')
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(3600)
    marker = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    owner = json.loads(Path('/etc/infra-postgres/ownership.json').read_text())
    require(marker['managed_by'] == 'infra-flux/ansible/kubeadm' and marker['cluster_name'] == cluster_name,
            'Unexpected kubeadm identity')
    require(hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest() == marker['ca_sha256'],
            'Kubernetes CA differs')
    require(owner['managed_by'] == 'infra-flux/ansible/postgres', 'PostgreSQL is not owned')
    uid = json.loads(command(KUBE + ['get', 'namespace', 'kube-system', '-o', 'json']))['metadata']['uid']
    require(uid == owner['cluster_uid'], 'Cluster UID differs')
    pods = json.loads(command(KUBE + ['get', 'pods', '-n', 'database', '-l',
                                    'cluster-name=unified-postgres,role=primary', '-o', 'json']))['items']
    require(len(pods) == 1, 'Exactly one primary is required')
    pod = pods[0]
    require(pod['metadata']['name'] in ('unified-pg-msk-0', 'unified-pg-fin-0', 'unified-pg-home-0'), 'Unexpected primary')
    require(not pod['metadata'].get('deletionTimestamp'), 'Primary is terminating')
    containers = pod['spec']['containers']
    require(len(containers) == 1 and containers[0]['name'] == 'postgres' and containers[0]['image'] == IMAGE,
            'Unreviewed PostgreSQL image')
    require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', [])),
            'Primary is not Ready')
    prefix = KUBE + ['exec', '-n', 'database', pod['metadata']['name'], '-c', 'postgres', '--']
    sql = """SELECT json_build_object(
      'version_num', current_setting('server_version_num')::int,
      'in_recovery', pg_is_in_recovery(),
      'system_identifier', (pg_control_system()).system_identifier::text,
      'timeline', (pg_control_checkpoint()).timeline_id,
      'database_bytes', (SELECT sum(pg_database_size(oid)) FROM pg_database),
      'databases', (SELECT json_agg(json_build_object('name', datname, 'oid', oid, 'allowconn', datallowconn)
         ORDER BY datname) FROM pg_database WHERE datname <> 'template0'),
      'roles', (SELECT json_agg(rolname ORDER BY rolname) FROM pg_roles WHERE rolname !~ '^pg_'),
      'custom_tablespaces', (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global'))
    );"""
    def state():
        data = json.loads(command(prefix + ['/usr/bin/env',
            'PGOPTIONS=-c statement_timeout=5000 -c default_transaction_read_only=on',
            '/usr/lib/postgresql/18/bin/psql', '-X', '-h', '/run/postgresql', '-U', 'postgres', '-d', 'postgres', '-At', '-c', sql]))
        require(data['version_num'] == 180006 and data['in_recovery'] is False, 'Expected PostgreSQL 18.6 primary')
        require(data['custom_tablespaces'] == 0, 'Custom tablespaces need a reviewed restore mapping')
        require(all(d['allowconn'] for d in data['databases']), 'A non-connectable database would be omitted')
        current = json.loads(command(KUBE + ['get', 'pod', pod['metadata']['name'], '-n', 'database', '-o', 'json']))
        require(current['metadata']['uid'] == pod['metadata']['uid'] and
                current['metadata']['labels'].get('role') == 'primary' and
                not current['metadata'].get('deletionTimestamp'), 'Primary changed during export')
        return data
    before = state()
    require(before['database_bytes'] <= 24 * 1024**3, 'Database exceeds approved working storage')
    metadata = {'format': 1, 'component': 'postgres', 'cluster_name': cluster_name,
                'cluster_uid': uid, 'ca_sha256': marker['ca_sha256'], 'created_at': int(time.time()),
                'pod_name': pod['metadata']['name'], 'pod_uid': pod['metadata']['uid'],
                'image': IMAGE, 'consistency': 'per-database', 'source': before}
    output, total = sys.stdout.buffer, 0
    def write(block):
        nonlocal total
        total += len(block)
        require(total <= max_bytes, 'PostgreSQL stream exceeds bound')
        output.write(block)
    def frame(block):
        require(len(block) <= 1048576, 'Frame exceeds bound')
        write(struct.pack('!I', len(block))); write(block)
    write(MAGIC)
    frame(json.dumps(metadata, sort_keys=True).encode())
    digest, sql_bytes = hashlib.sha256(), 0
    # The stream has its own explicit timeout; a Kubernetes request deadline
    # must not truncate a healthy multi-minute pg_dumpall exec session.
    stream_prefix = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=0',
                     'exec', '-n', 'database', pod['metadata']['name'], '-c', 'postgres', '--']
    arguments = stream_prefix + ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '3300',
        '/usr/bin/env', 'PGAPPNAME=infra-mac-backup', 'PGOPTIONS=-c default_transaction_read_only=on',
        '/usr/lib/postgresql/18/bin/pg_dumpall', '-h', '/run/postgresql', '-U', 'postgres',
        '--database=postgres', '--no-password', '--quote-all-identifiers', '--lock-wait-timeout=15s']
    with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            while block := process.stdout.read(1048576):
                sql_bytes += len(block); digest.update(block); frame(block)
            require(process.wait(timeout=30) == 0 and sql_bytes > 0, 'pg_dumpall failed or returned empty data')
        except BaseException:
            process.kill(); process.wait()
            raise
    after = state()
    for key in ('system_identifier', 'timeline', 'databases', 'roles'):
        require(before[key] == after[key], 'Primary, database or role inventory changed during export')
    write(struct.pack('!I', 0))
    frame(json.dumps({'sql_sha256': digest.hexdigest(), 'sql_bytes': sql_bytes,
                      'completed_at': int(time.time()), 'primary_unchanged': True}, sort_keys=True).encode())
    output.flush()


if __name__ == '__main__':
    try:
        export(int(sys.argv[1]), sys.argv[2])
    except Exception as error:
        print(f'PostgreSQL export failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
