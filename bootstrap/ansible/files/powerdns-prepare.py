#!/usr/bin/env python3
"""Bootstrap an isolated native PowerDNS database; never switch existing writers.

Run on a verified control plane with JSON stdin. The persisted bundle is the
credential authority: a rerun verifies it, and never adopts or rotates secrets.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

OWNER = 'infra-flux/powerdns'
ROOT = Path('/etc/infra-flux')
STATE = ROOT / 'powerdns-runtime.json'
NS = 'dns-powerdns'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']
SECRET_NAMES = ('powerdns-reader-runtime', 'powerdns-api-runtime')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(argv, body=None, timeout=60):
    result = subprocess.run(argv, input=body, text=True, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'Command failed; inspect privately without printing credentials')
    return result.stdout


def kube(args, obj=None):
    result = command(KUBE + args, json.dumps(obj) if obj is not None else None)
    return json.loads(result) if result.strip() else None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_state(state):
    require(state.get('managed_by') == OWNER and state.get('format') == 1, 'Recovery identity differs')
    for key in ('api_key', 'api_password', 'reader_password', 'webserver_password'):
        # Values are written into pdns.conf: prohibit newline/comment injection.
        require(isinstance(state.get(key), str) and re.fullmatch(r'[A-Za-z0-9_=-]{24,256}', state[key]),
                'Credential is not a single safe configuration value')
    require(state['webserver_password'] != state['api_key'], 'Separate webserver credential required')
    require(re.fullmatch('[0-9a-f]{64}', state.get('schema_sha256', '')), 'Schema digest missing')
    return state


def read_state(path=STATE):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077,
            'Recovery bundle must be a root-owned mode0600 regular file')
    return validate_state(json.loads(path.read_text()))


def recovery_identity(state):
    return digest({k: state[k] for k in ('managed_by', 'format', 'cluster_uid', 'ca_sha256',
        'schema_sha256', 'postgres_ca', 'api_key', 'api_password', 'reader_password', 'webserver_password')})


def save(state):
    require(not STATE.is_symlink(), 'Refuse recovery symlink')
    fd, path = tempfile.mkstemp(prefix='.powerdns-', dir=ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(state, handle, indent=2)
            handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
        os.replace(path, STATE)
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(path): os.unlink(path)


def secret_data(state, api=False):
    config = 'gpgsql-password=' + state['api_password' if api else 'reader_password'] + '\n'
    if api:
        config += 'api-key=' + state['api_key'] + '\nwebserver-password=' + state['webserver_password'] + '\n'
    return {k: base64.b64encode(v.encode()).decode() for k, v in
            {'credentials.conf': config, 'ca.crt': state['postgres_ca']}.items()}


def verify_secret(current, expected):
    require(current.get('type') == 'Opaque' and current['metadata'].get('annotations', {}).get(
        'infra.shanginn.io/managed-by') == OWNER and current.get('data') == expected,
        'Existing Secret differs; restore the original bundle instead of rotating credentials')


SQL = r'''
import base64,hashlib,hmac,json,sys,psycopg
from psycopg import sql
p=json.load(sys.stdin)
marker=p['managed_by']+':'+p['cluster_uid']
tables={'domains','records','supermasters','comments','domainmetadata','cryptokeys','tsigkeys'}
reader={'domains','records','domainmetadata'}
def scram(password, verifier):
 try:
  algorithm,saltinfo,keys=verifier.split('$'); count,salt=saltinfo.split(':'); stored,server=keys.split(':')
  if algorithm!='SCRAM-SHA-256' or not 4096<=int(count)<=1000000: return False
  salted=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.b64decode(salt,validate=True),int(count))
  return hmac.compare_digest(hashlib.sha256(hmac.new(salted,b'Client Key','sha256').digest()).digest(),base64.b64decode(stored,validate=True)) and hmac.compare_digest(hmac.new(salted,b'Server Key','sha256').digest(),base64.b64decode(server,validate=True))
 except (ValueError,TypeError,AttributeError): return False
def connect(db):
 return psycopg.connect(host='/run/postgresql',user='postgres',dbname=db,autocommit=True,
  options='-c statement_timeout=15000 -c lock_timeout=3000')
def catalog_digest(q):
 # Include executable schema properties, never contents or sequence positions.
 queries=[
  "SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1,2",
  "SELECT table_name,column_name,ordinal_position,data_type,udt_name,character_maximum_length,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY 1,3",
  "SELECT c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1,2",
  "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY 1,2",
  "SELECT sequencename,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size FROM pg_sequences WHERE schemaname='public' ORDER BY 1",
  "SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY 1,2",
  "SELECT tablename,policyname,permissive,roles,cmd,qual,with_check FROM pg_policies WHERE schemaname='public' ORDER BY 1,2"]
 result=[]
 for query in queries:
  q.execute(query); result.append(q.fetchall())
 return hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()
roles={'powerdns_owner':(False,-1,None),'powerdns_reader':(True,24,p['reader_password']),
       'powerdns_api':(True,24,p['api_password'])}
with connect('postgres') as conn:
 with conn.cursor() as q:
  q.execute('SELECT pg_is_in_recovery()'); assert q.fetchone()[0] is False
  q.execute("SELECT pg_get_userbyid(datdba),shobj_description(oid,'pg_database') FROM pg_database WHERE datname='powerdns'")
  db=q.fetchone(); assert db is None or db==('powerdns_owner',marker),'Database identity differs'
  observed={}
  for name,(login,limit,password) in roles.items():
   q.execute("SELECT shobj_description(oid,'pg_authid'),rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolcanlogin,rolbypassrls,rolinherit,rolconnlimit,rolpassword FROM pg_authid WHERE rolname=%s",(name,))
   observed[name]=r=q.fetchone()
   if r is not None:
    assert r[:-1]==(marker,False,False,False,False,login,False,False,limit),'Role identity differs'
    assert (r[-1] is None if password is None else scram(password,r[-1])),'Credential differs; no automatic reset'
   q.execute('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=%s)',(name,name))
   assert q.fetchone()[0]==0,'Unexpected membership'
  # Roles and their ownership marker are committed together.
  with conn.transaction():
   for name,(login,limit,password) in roles.items():
    if observed[name] is None:
     q.execute(sql.SQL('CREATE ROLE {} {} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {} PASSWORD {}').format(sql.Identifier(name),sql.SQL('LOGIN' if login else 'NOLOGIN'),sql.Literal(limit),sql.Literal(password)))
     q.execute(sql.SQL('COMMENT ON ROLE {} IS {}').format(sql.Identifier(name),sql.Literal(marker)))
  if db is None:
   # CREATE DATABASE is not transactional. An interrupted unmarked creation
   # deliberately stops a rerun for inspection rather than adopting a name.
   q.execute('CREATE DATABASE powerdns OWNER powerdns_owner')
   q.execute(sql.SQL('COMMENT ON DATABASE powerdns IS {}').format(sql.Literal(marker)))
  q.execute('REVOKE ALL ON DATABASE powerdns FROM PUBLIC')
  q.execute('GRANT CONNECT ON DATABASE powerdns TO powerdns_api,powerdns_reader')
  q.execute("ALTER DATABASE powerdns SET idle_in_transaction_session_timeout='60s'")
with connect('powerdns') as conn:
 with conn.cursor() as q:
  q.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
  present={r[0] for r in q.fetchall()}
  q.execute("SELECT obj_description(oid,'pg_namespace'),pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'")
  schema_marker,schema_owner=q.fetchone()
  expected=marker+':schema:'+p['schema_sha256']
  if not present:
   assert schema_marker in (None,'standard public schema'),'Unexpected empty schema identity'
   q.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'")
   assert q.fetchone()[0]==0,'Empty schema contains relations'
   q.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'")
   assert q.fetchone()[0]==0,'Empty schema contains functions'
   with conn.transaction():
    q.execute('ALTER SCHEMA public OWNER TO powerdns_owner')
    q.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC')
    q.execute('SET LOCAL ROLE powerdns_owner')
    q.execute(p['schema'],prepare=False)
    q.execute(sql.SQL('COMMENT ON SCHEMA public IS {}').format(sql.Literal(expected+':catalog:'+catalog_digest(q))))
    # PDNS treats -1 as UnknownDomainID. Reserve positive IDs instead, without
    # advancing sequences. A future importer must explicitly reject collisions
    # and preserve source sequence positions, not use MAX over these seed rows.
    q.execute("INSERT INTO domains(id,name,type) VALUES (2000000000,'health.test','NATIVE') RETURNING id")
    domain=q.fetchone()[0]
    q.executemany('INSERT INTO records(id,domain_id,name,type,content,ttl) VALUES (%s,%s,%s,%s,%s,%s)',[
     (2000000000,domain,'health.test','SOA','ns.health.test hostmaster.health.test 1 300 60 86400 60',60),
     (2000000001,domain,'health.test','NS','ns.health.test',60),
     (2000000002,domain,'ns.health.test','A','127.0.0.1',60)])
  else:
   assert schema_owner=='powerdns_owner','Schema owner differs'
   assert present==tables and schema_marker==expected+':catalog:'+catalog_digest(q),'Schema identity differs; no automatic migrations'
  q.execute("SELECT count(*) FROM domains WHERE type<>'NATIVE'"); assert q.fetchone()[0]==0
  q.execute("SELECT count(*) FROM pg_constraint WHERE conrelid='domains'::regclass AND conname='domains_native_only' AND contype='c' AND convalidated")
  assert q.fetchone()[0]==1,'NATIVE constraint absent'
  q.execute("SELECT count(*) FROM domains d JOIN records r ON r.domain_id=d.id WHERE d.name='health.test' AND d.type='NATIVE' AND r.name='health.test' AND r.type='SOA' AND NOT r.disabled")
  assert q.fetchone()[0]==1,'Health zone differs'
  q.execute('GRANT USAGE ON SCHEMA public TO powerdns_api,powerdns_reader')
  # Explicit grants, no default privileges that could expose future tables.
  for table in tables:
   q.execute('SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=%s::regclass',(table,))
   assert q.fetchone()[0]=='powerdns_owner','Table owner differs'
   q.execute(sql.SQL('REVOKE ALL ON TABLE {} FROM PUBLIC').format(sql.Identifier(table)))
   q.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE {} TO powerdns_api').format(sql.Identifier(table)))
   if table in reader:
    q.execute(sql.SQL('GRANT SELECT ON TABLE {} TO powerdns_reader').format(sql.Identifier(table)))
   for role in ('powerdns_reader','powerdns_api'):
    for privilege in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'):
     q.execute('SELECT has_table_privilege(%s,%s,%s)',(role,table,privilege))
     allowed=(role=='powerdns_api' and privilege in ('SELECT','INSERT','UPDATE','DELETE')) or (role=='powerdns_reader' and table in reader and privilege=='SELECT')
     assert q.fetchone()[0]==allowed,'Unexpected table privilege'
  q.execute("SELECT sequencename,sequenceowner FROM pg_sequences WHERE schemaname='public'")
  for sequence,owner in q.fetchall():
   assert owner=='powerdns_owner','Sequence owner differs'
   q.execute(sql.SQL('REVOKE ALL ON SEQUENCE {} FROM PUBLIC').format(sql.Identifier(sequence)))
   q.execute(sql.SQL('GRANT USAGE,SELECT ON SEQUENCE {} TO powerdns_api').format(sql.Identifier(sequence)))
   for privilege in ('SELECT','USAGE','UPDATE'):
    q.execute('SELECT has_sequence_privilege(%s,%s,%s)',('powerdns_reader',sequence,privilege)); assert q.fetchone()[0] is False
    q.execute('SELECT has_sequence_privilege(%s,%s,%s)',('powerdns_api',sequence,privilege)); assert q.fetchone()[0]==(privilege!='UPDATE')
  for role in ('powerdns_api','powerdns_reader'):
   q.execute("SELECT has_schema_privilege(%s,'public','CREATE'),has_database_privilege(%s,'powerdns','CREATE'),has_database_privilege(%s,'powerdns','TEMP')",(role,role,role))
   assert q.fetchone()==(False,False,False),'Unexpected DDL privilege'
print(json.dumps({'database':'powerdns','roles_scoped':True,'schema_verified':True}))
'''


def main():
    os.umask(0o077)
    settings = json.load(sys.stdin)
    require(settings.get('enabled') is True, 'Explicit enable required')
    require(os.geteuid() == 0 and ROOT.is_dir() and not ROOT.is_symlink(), 'Owned root directory required')
    require(ROOT.stat().st_uid == 0 and not ROOT.stat().st_mode & 0o022, 'Unsafe root directory')
    ca = hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest()
    uid = kube(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid']
    require(ca == settings['ca_sha256'] and uid == settings['cluster_uid'], 'Cluster identity differs')
    nodes = kube(['get', 'nodes', '-o', 'json'])['items']
    require({n['metadata']['name'] for n in nodes} == {'home', 'msk', 'fin'} and all(
        any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions']) for n in nodes),
        'Three Ready physical nodes required')
    pods = kube(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres', '-o', 'json'])['items']
    require(len(pods) == 3 and all(any(c['type'] == 'Ready' and c['status'] == 'True'
        for c in p['status'].get('conditions', [])) for p in pods), 'Three Ready PostgreSQL members required')
    primary = [p for p in pods if p['metadata']['labels'].get('role') == 'primary']
    require(len(primary) == 1 and primary[0]['spec']['nodeName'] == 'home', 'Expected home primary')
    schema = settings['schema']
    schema_hash = hashlib.sha256(schema.encode()).hexdigest()
    require(schema_hash == settings['schema_sha256'], 'Reviewed schema digest differs')
    pgca = base64.b64decode(kube(['get', 'secret', 'patroni-server-tls', '-n', 'database',
        '-o', 'json'])['data']['ca.crt'], validate=True).decode()
    namespace = kube(['get', 'namespace', NS, '--ignore-not-found', '-o', 'json'])
    if namespace:
        require(namespace['metadata'].get('annotations', {}).get('infra.shanginn.io/managed-by') == OWNER,
                'Namespace identity differs')
    descriptor = os.open(ROOT / 'powerdns-prepare.lock', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        st = os.fstat(lock.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Unsafe lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if STATE.exists():
            state = read_state()
            require(all(state[k] == v for k, v in {'cluster_uid': uid, 'ca_sha256': ca,
                'schema_sha256': schema_hash, 'postgres_ca': pgca}.items()), 'Recovery identity differs')
            require(settings.get('api_key', state['api_key']) == state['api_key'], 'API key differs; no rotation')
        else:
            require(not STATE.is_symlink(), 'Refuse recovery symlink')
            for name in SECRET_NAMES:
                require(kube(['get', 'secret', name, '-n', NS, '--ignore-not-found', '-o', 'json']) is None,
                        'Existing Secret requires original recovery state')
            state = validate_state({'managed_by': OWNER, 'format': 1, 'cluster_uid': uid, 'ca_sha256': ca,
                'schema_sha256': schema_hash, 'postgres_ca': pgca, 'api_key': settings['api_key'],
                **{k: secrets.token_urlsafe(40) for k in ('api_password', 'reader_password', 'webserver_password')}})
            save(state)
        # Check existing Secrets before database changes; never overwrite them.
        for name, api in zip(SECRET_NAMES, (False, True)):
            current = kube(['get', 'secret', name, '-n', NS, '--ignore-not-found', '-o', 'json'])
            if current: verify_secret(current, secret_data(state, api))
        proof = json.loads(command(KUBE + ['exec', '-i', '-n', 'database', primary[0]['metadata']['name'],
            '-c', 'postgres', '--', '/opt/patroni/bin/python', '-c', SQL], json.dumps({**state, 'schema': schema}), 90))
        if namespace is None:
            kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
                'name': NS, 'annotations': {'infra.shanginn.io/managed-by': OWNER},
                'labels': {'infra.shanginn.io/postgresql-client': 'true',
                    **{'pod-security.kubernetes.io/' + k: 'restricted' for k in ('enforce', 'audit', 'warn')}}}})
        for name, api in zip(SECRET_NAMES, (False, True)):
            current = kube(['get', 'secret', name, '-n', NS, '--ignore-not-found', '-o', 'json'])
            data = secret_data(state, api)
            if current:
                verify_secret(current, data)
            else:
                kube(['create', '-f', '-', '-o', 'json'], {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                    'metadata': {'name': name, 'namespace': NS, 'annotations': {'infra.shanginn.io/managed-by': OWNER}}, 'data': data})
        state['prepared'] = True
        save(state)
        print(json.dumps({'prepared': True, **proof, 'legacy_writers_changed': False, 'public_routes_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error_type': type(error).__name__,
            'message': 'Preparation stopped. Inspect identities privately; do not replace credentials or adopt partial database creation.'}))
        sys.exit(1)
