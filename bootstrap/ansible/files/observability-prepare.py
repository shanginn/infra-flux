#!/usr/bin/env python3
"""Prepare owned application databases and runtime Secrets, never print credentials.

Run on a verified control plane with JSON on stdin. Keep the generated bundle in
the encrypted node backup; subsequent runs must retain exactly the same identity.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote

OWNER = 'infra-flux/observability'
ROOT = Path('/etc/infra-flux')
STATE = ROOT / 'observability-runtime.json'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']
BUCKET = 'glitchtip'
QUOTA = 1024**3
MAX_LAYOUT = 24 * 1024**3
TIMEOUT_RECONCILE = 'glitchtip-connect-timeout-v1'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(argv, body=None, timeout=60):
    proc = subprocess.run(argv, input=body, capture_output=True, text=True, timeout=timeout)
    require(proc.returncode == 0, 'Command failed; inspect privately before retrying')
    return proc.stdout


def kube(args, obj=None):
    out = command(KUBE + args, json.dumps(obj) if obj is not None else None)
    return json.loads(out) if out.strip() else None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read_state(path=STATE):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o077 == 0,
            'Unsafe recovery state; root-owned regular mode0600 required')
    state = json.loads(path.read_text())
    require(state.get('managed_by') == OWNER and state.get('format') == 1,
            'Unsupported recovery state identity/format')
    require(set(state.get('apps', {})) == {'grafana', 'glitchtip'}, 'Unexpected application set')
    for name, app in state['apps'].items():
        require(app.get('admin_user') == ('shanginn' if name == 'grafana' else 'admin@errors.apps.shanginn.io'),
                'Unexpected administrator identity')
        require(all(isinstance(app.get(k), str) and len(app[k]) >= 24
                    for k in ('database_password', 'secret_key', 'admin_password')), 'Invalid persisted credentials')
    require(state.get('glitchtip_connect_timeout') in (None, 5), 'Unreviewed database timeout')
    return state


def recovery_identity(state):
    """Credentials must agree before copying; progress/timeout records may differ."""
    return digest({k: state.get(k) for k in ('managed_by', 'format', 'cluster_uid',
        'ca_sha256', 'apps', 'postgres_ca', 'bucket_id', 's3_key')})


def database_url(state, timeout=None):
    app = state['apps']['glitchtip']
    url = ('postgresql://glitchtip:' + quote(app['database_password'], safe='') +
           '@unified-postgres.database.svc:5432/glitchtip?sslmode=verify-full&sslrootcert=/etc/postgresql/ca.crt')
    return url + ('&connect_timeout=5' if timeout == 5 else '')


def glitchtip_data(state, timeout=None):
    app = state['apps']['glitchtip']; key = state['s3_key']
    values = {'DATABASE_URL': database_url(state, timeout), 'SECRET_KEY': app['secret_key'],
              'AWS_ACCESS_KEY_ID': key['accessKeyId'], 'AWS_SECRET_ACCESS_KEY': key['secretAccessKey'],
              'AWS_STORAGE_BUCKET_NAME': BUCKET,
              'AWS_S3_ENDPOINT_URL': 'http://garage.garage.svc.cluster.local:3900',
              'ca.crt': state['postgres_ca']}
    return {k: base64.b64encode(v.encode()).decode() for k, v in values.items()}


def timeout_secret(state):
    require(state.get('prepared') is True, 'Complete preparation and preserve its bundle before timeout maintenance')
    obj = kube(['get', 'secret', 'glitchtip-runtime', '-n', 'error-tracking', '-o', 'json'])
    require(obj.get('type') == 'Opaque' and obj['metadata'].get('annotations', {}).get(
        'infra.shanginn.io/managed-by') == OWNER, 'Unexpected runtime Secret owner/type')
    require(obj['metadata'].get('uid') and obj['metadata'].get('resourceVersion'), 'Secret identity missing')
    return obj


def inspect_timeout(state):
    obj = timeout_secret(state)
    expected = glitchtip_data(state, state.get('glitchtip_connect_timeout'))
    intent = state.get(TIMEOUT_RECONCILE)
    if intent:
        require(obj['metadata']['uid'] == intent['secret_uid'] and
                obj['data'] in (intent['before_data'], intent['after_data']), 'Timeout maintenance resource changed')
    else:
        require(obj['data'] == expected, 'Secret differs from persisted credentials/configuration')
    return {'secret_uid': obj['metadata']['uid'], 'secret_resource_version': obj['metadata']['resourceVersion'],
            'secret_data_sha256': digest(obj['data']), 'connect_timeout': state.get('glitchtip_connect_timeout'),
            'reconcile_phase': intent.get('phase') if intent else None, 'changed': False,
            'resume_review': ({'expected_' + k: intent[k] for k in
                ('secret_uid', 'secret_resource_version', 'secret_data_sha256')} if intent else None)}


def reconcile_timeout(state, settings):
    """Exactly one JSON Patch dispatch. Unknown outcomes permit readback only."""
    obj = timeout_secret(state); desired = glitchtip_data(state, 5)
    record = state.get(TIMEOUT_RECONCILE)
    was_verified = record is not None and record.get('phase') == 'verified'
    reviewed = {k: settings.get('expected_' + k) for k in
                ('secret_uid', 'secret_resource_version', 'secret_data_sha256')}
    if record is None:
        require(reviewed == {'secret_uid': obj['metadata']['uid'],
            'secret_resource_version': obj['metadata']['resourceVersion'],
            'secret_data_sha256': digest(obj['data'])}, 'Explicit reviewed Secret UID/version/data hash required')
        if state.get('glitchtip_connect_timeout') == 5:
            require(obj['data'] == desired, 'Already-configured Secret differs')
            return {'changed': False, 'connect_timeout': 5, 'verified': True}
        require(obj['data'] == glitchtip_data(state), 'Only the exact owned legacy URL may be changed')
        record = {**reviewed, 'phase': 'dispatch-intent', 'before_data': obj['data'], 'after_data': desired}
        state[TIMEOUT_RECONCILE] = record
        save(state)
        patch = [
            {'op': 'test', 'path': '/metadata/uid', 'value': record['secret_uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': record['secret_resource_version']},
            {'op': 'test', 'path': '/data', 'value': record['before_data']},
            {'op': 'replace', 'path': '/data/DATABASE_URL', 'value': desired['DATABASE_URL']}]
        try:
            kube(['patch', 'secret', 'glitchtip-runtime', '-n', 'error-tracking', '--type=json',
                  '--patch-file=/dev/stdin', '-o', 'json'], patch)
        except (RuntimeError, subprocess.TimeoutExpired):
            pass  # Durable intent already exists; never dispatch again after uncertainty.
    else:
        require(record['phase'] in ('dispatch-intent', 'verified') and all(
            reviewed[k] == record[k] for k in reviewed), 'Resume requires the original reviewed Secret identity')
        require(record['before_data'] == glitchtip_data(state) and record['after_data'] == desired,
                'Persisted maintenance intent differs from the unchanged credentials')
    observed = timeout_secret(state)
    require(observed['metadata']['uid'] == record['secret_uid'] and observed['data'] == desired,
            'Timeout outcome unverified; retain intent, never blindly redispatch')
    record['phase'] = 'verified'
    state['glitchtip_connect_timeout'] = 5
    save(state)
    return {'changed': not was_verified, 'connect_timeout': 5, 'verified': True, 'pods_restarted': False}


def save(state):
    require(not STATE.is_symlink(), 'Refuse symlink')
    fd, path = tempfile.mkstemp(prefix='.observability-', dir=ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(state, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(path, STATE)
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(path):
            os.unlink(path)


SCRAM_VERIFY = r'''
import base64,hashlib,hmac
def matches_scram(password, verifier):
 try:
  if not password.isascii(): return False
  algorithm, saltinfo, keys = verifier.split('$')
  iterations, salt = saltinfo.split(':'); stored, server = keys.split(':')
  if algorithm != 'SCRAM-SHA-256' or not 4096 <= int(iterations) <= 1000000: return False
  salted=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.b64decode(salt,validate=True),int(iterations))
  expected=hashlib.sha256(hmac.new(salted,b'Client Key','sha256').digest()).digest()
  return hmac.compare_digest(expected,base64.b64decode(stored,validate=True)) and hmac.compare_digest(
   hmac.new(salted,b'Server Key','sha256').digest(),base64.b64decode(server,validate=True))
 except (ValueError,TypeError,AttributeError): return False
'''

SQL = SCRAM_VERIFY + r'''
import json,sys,psycopg
from psycopg import sql
p=json.load(sys.stdin)
with psycopg.connect(host='/run/postgresql',user='postgres',dbname='postgres',autocommit=True,
                     options='-c statement_timeout=15000 -c lock_timeout=3000') as conn:
 with conn.cursor() as q:
  q.execute('SELECT pg_is_in_recovery()'); assert q.fetchone()[0] is False
  for name,app in p['apps'].items():
   assert name in ('grafana','glitchtip')
   marker=p['managed_by']+':'+p['cluster_uid']+':'+name
   q.execute("SELECT shobj_description(oid,'pg_authid'),rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolcanlogin,rolbypassrls,rolconnlimit,rolpassword FROM pg_authid WHERE rolname=%s",(name,))
   role=q.fetchone()
   if role is None:
    with conn.transaction():
     q.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {} PASSWORD {}').format(sql.Identifier(name),sql.Literal(12 if name=='grafana' else 32),sql.Literal(app['database_password'])))
     q.execute(sql.SQL('COMMENT ON ROLE {} IS {}').format(sql.Identifier(name),sql.Literal(marker)))
   else:
    assert role[:-1]==(marker,False,False,False,False,True,False,12 if name=='grafana' else 32),'Existing role is not the owned application identity'
    assert matches_scram(app['database_password'],role[-1]),'Persisted password differs; never reset or replace it automatically'
   q.execute('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s)',(name,))
   assert q.fetchone()[0]==0,'Unexpected inherited database roles'
   q.execute("SELECT pg_get_userbyid(datdba),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=%s",(name,))
   db=q.fetchone()
   if db is None:
    q.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(name),sql.Identifier(name)))
    q.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(name),sql.Literal(marker)))
   else:
    assert db==(name,marker),'Existing database is unowned or requires partial-creation recovery'
   q.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(name)))
   # Grafana holds its migration advisory lock in an otherwise idle transaction
   # while executing migrations through other connections. Keep that lock alive
   # for the bounded initial startup window; GlitchTip overrides only its Job.
   q.execute(sql.SQL('ALTER DATABASE {} SET idle_in_transaction_session_timeout TO {}').format(sql.Identifier(name),sql.Literal('1800s' if name=='grafana' else '60s')))
print(json.dumps({'databases':['grafana','glitchtip'],'roles_scoped':True}))
'''


def main():
    os.umask(0o077)
    settings = json.load(sys.stdin)
    require(settings.get('enabled') is True, 'Explicit enable required')
    action = settings.get('action', 'prepare')
    require(action in ('prepare', 'inspect-glitchtip-timeout', 'reconcile-glitchtip-timeout'), 'Unsupported action')
    require(os.geteuid() == 0 and ROOT.is_dir() and not ROOT.is_symlink(), 'Owned root directory required')
    root_stat = ROOT.stat()
    require(root_stat.st_uid == 0 and not root_stat.st_mode & 0o022, 'Unsafe recovery directory ownership/mode')
    ca = hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest()
    require(ca == settings['ca_sha256'], 'Cluster CA differs')
    uid = kube(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid']
    require(uid == settings['cluster_uid'], 'Cluster UID differs')
    nodes = kube(['get', 'nodes', '-o', 'json'])['items']
    require({n['metadata']['name'] for n in nodes} == {'home', 'msk', 'fin'}, 'Unexpected topology')
    require(all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions']) for n in nodes), 'All nodes must be Ready')
    if action == 'inspect-glitchtip-timeout':
        state = read_state(STATE)
        require(state['cluster_uid'] == uid and state['ca_sha256'] == ca, 'State identity differs')
        print(json.dumps(inspect_timeout(state)))
        return
    descriptor = os.open(ROOT / 'observability-prepare.lock',
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        lock_stat = os.fstat(lock.fileno())
        require(stat.S_ISREG(lock_stat.st_mode) and lock_stat.st_uid == 0 and not lock_stat.st_mode & 0o077,
                'Unsafe preparation lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if STATE.exists():
            state = read_state(STATE)
            require(state['cluster_uid'] == uid and state['ca_sha256'] == ca, 'State identity differs')
        else:
            require(action == 'prepare' and not STATE.is_symlink(), 'Restore the original recovery bundle first')
            for ns, name in (('observability', 'grafana-runtime'), ('error-tracking', 'glitchtip-runtime'),
                             ('error-tracking', 'glitchtip-bootstrap-admin')):
                require(kube(['get', 'secret', name, '-n', ns, '--ignore-not-found', '-o', 'json']) is None,
                        'Existing application Secret requires the original recovery bundle; never regenerate credentials')
            state = {'managed_by': OWNER, 'format': 1, 'cluster_uid': uid, 'ca_sha256': ca,
                     'glitchtip_connect_timeout': 5,
                     'apps': {name: {'database_password': secrets.token_urlsafe(40),
                                     'secret_key': secrets.token_urlsafe(64),
                                     'admin_password': secrets.token_urlsafe(32)} for name in ('grafana', 'glitchtip')}}
            state['apps']['grafana']['admin_user'] = 'shanginn'
            state['apps']['glitchtip']['admin_user'] = 'admin@errors.apps.shanginn.io'
            save(state)
        if action == 'reconcile-glitchtip-timeout':
            print(json.dumps(reconcile_timeout(state, settings)))
            return
        require(not state.get(TIMEOUT_RECONCILE) or state[TIMEOUT_RECONCILE]['phase'] == 'verified',
                'Finish the pending timeout reconciliation before normal preparation')
        pods = kube(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres', '-o', 'json'])['items']
        require(len(pods) == 3 and all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', [])) for p in pods), 'Three ready PostgreSQL members required')
        primary = [p for p in pods if p['metadata']['labels'].get('role') == 'primary']
        require(len(primary) == 1 and primary[0]['spec']['nodeName'] == 'home', 'Expected one primary at home')
        dbproof = json.loads(command(KUBE + ['exec', '-i', '-n', 'database', primary[0]['metadata']['name'], '-c', 'postgres', '--', '/opt/patroni/bin/python', '-c', SQL], json.dumps(state), timeout=90))
        pgca = kube(['get', 'secret', 'patroni-server-tls', '-n', 'database', '-o', 'json'])['data']['ca.crt']
        current_pgca = base64.b64decode(pgca, validate=True).decode()
        require(state.get('postgres_ca') in (None, current_pgca), 'PostgreSQL CA changed; preserve original bundle and review rotation')
        state['postgres_ca'] = current_pgca
        save(state)

        garages = kube(['get', 'pods', '-n', 'garage', '-l', 'app.kubernetes.io/name=garage', '-o', 'json'])['items']
        require(len(garages) == 3 and all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', [])) for p in garages), 'Three ready Garage replicas required')
        pod = next(p['metadata']['name'] for p in garages if p['spec']['nodeName'] == 'msk')

        def api(name, body=None):
            return json.loads(command(KUBE + ['exec', '-n', 'garage', pod, '-c', 'garage', '--', '/garage', 'json-api', name, json.dumps(body)], timeout=40))

        buckets = api('ListBuckets')
        found = [b for b in buckets if BUCKET in b['globalAliases']]
        if 'bucket_id' not in state:
            require(not found and not state.get('bucket_create_intent'), 'Unknown bucket creation outcome; inspect by exact name')
            details = [api('GetBucketInfo', {'id': b['id']}) for b in buckets]
            require(all(b['quotas']['maxSize'] is not None for b in details), 'Unbounded existing bucket')
            require(sum(b['quotas']['maxSize'] for b in details) + QUOTA <= MAX_LAYOUT, 'Garage quotas exceed layout budget')
            state['bucket_create_intent'] = BUCKET
            save(state)
            result = api('CreateBucket', {'globalAlias': BUCKET})
            state['bucket_id'] = result['id']
            save(state)
        else:
            require(len(found) == 1 and found[0]['id'] == state['bucket_id'], 'Bucket identity differs')
        details = [api('GetBucketInfo', {'id': b['id']}) for b in api('ListBuckets')]
        others = [b for b in details if b['id'] != state['bucket_id']]
        require(all(b['quotas']['maxSize'] is not None for b in others) and sum(b['quotas']['maxSize'] for b in others) + QUOTA <= MAX_LAYOUT, 'Garage quotas exceed layout budget')
        owned = next(b for b in details if b['id'] == state['bucket_id'])
        require(owned['bytes'] <= QUOTA and owned['objects'] <= 100000, 'Refuse quota below existing data')
        api('UpdateBucket', {'id': state['bucket_id'], 'body': {'quotas': {'maxSize': QUOTA, 'maxObjects': 100000}}})
        require(api('GetBucketInfo', {'id': state['bucket_id']})['quotas'] == {'maxSize': QUOTA, 'maxObjects': 100000}, 'Quota readback differs')
        if 's3_key' not in state:
            require(not state.get('key_create_intent'), 'Unknown key creation outcome; inspect before retrying')
            state['key_create_intent'] = 'infra-flux-glitchtip'
            save(state)
            state['s3_key'] = api('CreateKey', {'name': state['key_create_intent'], 'deny': {'createBucket': True}})
            save(state)
        key = state['s3_key']
        api('AllowBucketKey', {'bucketId': state['bucket_id'], 'accessKeyId': key['accessKeyId'], 'permissions': {'read': True, 'write': True, 'owner': False}})
        info = api('GetKeyInfo', {'id': key['accessKeyId'], 'showSecretKey': True})
        require(info.get('secretAccessKey') == key['secretAccessKey'], 'S3 secret differs; never rotate persisted credentials automatically')
        require(not info['permissions']['createBucket'] and not info['expired'], 'S3 key scope differs')
        require(len(info['buckets']) == 1 and info['buckets'][0]['id'] == state['bucket_id'], 'S3 key grants exceed one bucket')
        backup_state = json.loads(Path('/etc/infra-garage/backup-key.json').read_text())
        require(backup_state['managed_by'] == 'infra-flux/garage-macbook-backup', 'Backup key owner differs')
        # The existing verified backup must include the new bucket too.
        backup_key = backup_state['accessKeyId']
        api('AllowBucketKey', {'bucketId': state['bucket_id'], 'accessKeyId': backup_key, 'permissions': {'read': True, 'write': False, 'owner': False}})
        backup_info = api('GetKeyInfo', {'id': backup_key, 'showSecretKey': False})
        require(not backup_info['permissions']['createBucket'] and not backup_info['expired'], 'Backup key invalid')
        grants = {b['id']: b['permissions'] for b in backup_info['buckets']}
        require(set(grants) == {b['id'] for b in api('ListBuckets')} and all(p['read'] and not p['write'] and not p['owner'] for p in grants.values()), 'Backup key must cover all buckets read-only')

        for ns in ('observability', 'error-tracking'):
            current = kube(['get', 'namespace', ns, '--ignore-not-found', '-o', 'json'])
            if current is None:
                kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': {'infra.shanginn.io/postgresql-client': 'true'}, 'annotations': {'infra.shanginn.io/managed-by': OWNER}}})
            else:
                require(current['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER, 'Namespace is not owned')
        g = state['apps']['grafana']
        app = state['apps']['glitchtip']
        url = database_url(state, state.get('glitchtip_connect_timeout'))
        entries = [
            ('observability', 'grafana-runtime', {'GF_SECURITY_ADMIN_USER': g['admin_user'], 'GF_SECURITY_ADMIN_PASSWORD': g['admin_password'], 'GF_SECURITY_SECRET_KEY': g['secret_key'], 'GF_DATABASE_USER': 'grafana', 'GF_DATABASE_PASSWORD': g['database_password'], 'ca.crt': state['postgres_ca']}),
            ('error-tracking', 'glitchtip-runtime', {'DATABASE_URL': url, 'SECRET_KEY': app['secret_key'], 'AWS_ACCESS_KEY_ID': key['accessKeyId'], 'AWS_SECRET_ACCESS_KEY': key['secretAccessKey'], 'AWS_STORAGE_BUCKET_NAME': BUCKET, 'AWS_S3_ENDPOINT_URL': 'http://garage.garage.svc.cluster.local:3900', 'ca.crt': state['postgres_ca']}),
            ('error-tracking', 'glitchtip-bootstrap-admin', {'email': app['admin_user'], 'password': app['admin_password']})]
        for ns, name, values in entries:
            data = {k: base64.b64encode(v.encode()).decode() for k, v in values.items()}
            current = kube(['get', 'secret', name, '-n', ns, '--ignore-not-found', '-o', 'json'])
            if current:
                require(current['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER and current['data'] == data, 'Existing Secret differs; no automatic rotation')
            else:
                kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque', 'metadata': {'name': name, 'namespace': ns, 'annotations': {'infra.shanginn.io/managed-by': OWNER}}, 'data': data})
        state['prepared'] = True
        save(state)
        print(json.dumps({'prepared': True, **dbproof, 'bucket': BUCKET, 'bucket_quota_bytes': QUOTA, 'secrets_created_or_verified': 3, 'public_ingress_enabled': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'message': 'Preparation stopped. Inspect owned state and resource identities; do not replace secrets or blindly repeat unknown creation.'}))
        sys.exit(1)
