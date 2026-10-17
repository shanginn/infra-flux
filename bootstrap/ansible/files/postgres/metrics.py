#!/usr/bin/env python3
"""Bounded read-only PostgreSQL checks for the node_exporter textfile collector."""
import base64
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import time

ROOT = pathlib.Path('/etc/infra-postgres')
OUT = pathlib.Path('/var/lib/node_exporter/textfile_collector')
DATA = pathlib.Path('/var/lib/infra-postgres/unified/pgdata')
STATE = OUT / 'infra_postgres.state.json'
config = json.loads((ROOT / 'metrics.json').read_text())
assert config['managed_by'] == 'infra-flux/ansible/postgres'
assert config['node'] in ('msk', 'fin', 'home')
owner = json.loads((ROOT / 'ownership.json').read_text())
assert owner['managed_by'] == config['managed_by'] and owner['node'] == config['node']
assert owner['cluster_uid'] == config['cluster_uid'] and owner['storage_bytes'] == 25769803776


def run(argv, timeout=20, input=None):
    result = subprocess.run(argv, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode: raise RuntimeError('Read-only collection command failed')
    return result.stdout


def atomic(path, content, mode):
    assert not path.is_symlink()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


now = int(time.time())
last_success = json.loads(STATE.read_text())['last_success'] if STATE.exists() else 0
metrics = {'infra_postgres_collect_timestamp_seconds': now}
success = True
try:
    used = int(run(['/usr/bin/du', '-sx', '--block-size=1', str(DATA)]).split()[0])
    metrics['infra_postgres_data_bytes'] = used
    metrics['infra_storage_used_bytes{component="postgres",destination="local"}'] = used
except Exception:
    success = False
metrics['infra_storage_configured{component="postgres",destination="local"}'] = 1
metrics['infra_storage_budget_bytes{component="postgres",destination="local"}'] = 25769803776
query = """
SELECT json_build_object(
 'primary', CASE WHEN pg_is_in_recovery() THEN 0 ELSE 1 END,
 'database_bytes', (SELECT sum(pg_database_size(oid)) FROM pg_database),
 'wal_bytes', (SELECT coalesce(sum(size),0) FROM pg_ls_waldir()),
 'streaming_replicas', (SELECT count(*) FROM pg_stat_replication WHERE state='streaming'),
 'async_replicas', (SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state='async'),
 'max_replay_lag_bytes', CASE WHEN pg_is_in_recovery() THEN 0 ELSE
    (SELECT coalesce(max(pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn)),0) FROM pg_stat_replication) END,
 'lost_slots', (SELECT count(*) FROM pg_replication_slots WHERE wal_status='lost'),
 'min_slot_safe_wal_bytes', (SELECT min(safe_wal_size) FROM pg_replication_slots),
 'max_slot_wal_keep_size_bytes', pg_size_bytes(current_setting('max_slot_wal_keep_size'))
);
"""
try:
    kube = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=10s']
    uid = run(kube + ['get', 'namespace', 'kube-system', '-o', 'jsonpath={.metadata.uid}'], 15)
    assert uid == config['cluster_uid']
    output = run(kube + ['exec', '-n', 'database', 'unified-pg-' + config['node'] + '-0', '-c', 'postgres', '--',
                       '/usr/bin/env', 'PGOPTIONS=-c statement_timeout=5000 -c lock_timeout=1000 -c default_transaction_read_only=on',
                       '/usr/lib/postgresql/18/bin/psql', '-X', '-h', '/run/postgresql', '-U', 'postgres', '-d', 'postgres', '-At', '-c', query], 20)
    for key, value in json.loads(output).items():
        if value is not None: metrics['infra_postgres_' + key] = float(value)
except Exception:
    success = False
try:
    bundle = json.loads((ROOT / 'runtime.json').read_text())
    certificate = base64.b64decode(bundle['pki']['tls.crt']).decode()
    expires = run(['/usr/bin/openssl', 'x509', '-noout', '-enddate'], 5, certificate).strip().split('=', 1)[1]
    metrics['infra_postgres_tls_expiry_timestamp_seconds'] = int(ssl.cert_time_to_seconds(expires))
except Exception:
    success = False
if success:
    last_success = now
    atomic(STATE, json.dumps({'last_success': now}), 0o600)
metrics['infra_postgres_collect_success'] = int(success)
metrics['infra_postgres_last_success_timestamp_seconds'] = last_success
atomic(OUT / 'infra_postgres.prom', ''.join(f'{name} {value}\n' for name, value in sorted(metrics.items())), 0o644)
print(json.dumps({'collection_success': success, 'attempt_timestamp': now}))
