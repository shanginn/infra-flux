#!/usr/bin/env python3
"""Bounded application DML fence for a PowerDNS PostgreSQL database.

This controls ordinary API writes, not a database owner or administrator.
Inspect/verify are read-only. Fence is one-shot, preserves SELECT and never
unfences automatically. Use a separately reviewed writer-enable operation later.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import uuid

_module = importlib.util.spec_from_file_location('pdns_snapshot', Path(__file__).with_name('powerdns-snapshot.py'))
snapshot = importlib.util.module_from_spec(_module)
_module.loader.exec_module(snapshot)
require = snapshot.require
canonical = snapshot.canonical
TABLES = snapshot.TABLES
SEQUENCES = tuple(snapshot.SEQUENCES)
LOCK_KEY = 'infra-flux/powerdns-cutover'
DML = ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
SCHEMA_QUERIES = [
    "SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1,2",
    "SELECT table_name,column_name,ordinal_position,data_type,udt_name,character_maximum_length,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY 1,3",
    "SELECT c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1,2",
    "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY 1,2",
    "SELECT sequencename,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size FROM pg_sequences WHERE schemaname='public' ORDER BY 1",
    "SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY 1,2",
    "SELECT tablename,policyname,permissive,roles,cmd,qual,with_check FROM pg_policies WHERE schemaname='public' ORDER BY 1,2",
]

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', value), 'Invalid SQL identifier')
    return '"' + value + '"'


def schema_digest(cursor):
    rows = []
    for query in SCHEMA_QUERIES:
        cursor.execute(query)
        rows.append(cursor.fetchall())
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def one(cursor, query, args=()):
    cursor.execute(query, args)
    return cursor.fetchone()[0]


def observe(connection, expected_identity, writer_role):
    snapshot.validate_identity(expected_identity)
    require(writer_role in ('powerdns', 'powerdns_api'), 'Unexpected writer role')
    with connection.cursor() as q:
        q.execute("SELECT (pg_control_system()).system_identifier::text,d.oid::bigint,current_database(),current_user,pg_is_in_recovery() FROM pg_database d WHERE d.datname=current_database()")
        system, oid, db, user, recovery = q.fetchone()
        identity = {'label': expected_identity['label'], 'system_identifier': system,
                    'database_oid': oid, 'database': db, 'user': user}
        require(identity == expected_identity and recovery is False, 'Database identity or primary differs')
        require(one(q, 'SELECT rolsuper FROM pg_roles WHERE rolname=current_user') is True, 'Explicit administrative connection required')
        q.execute("SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s", (writer_role,))
        r = q.fetchone()
        require(r is not None, 'Writer role missing')
        role = dict(zip(('name','superuser','inherit','createrole','createdb','login','replication','bypassrls'), r))
        require(role['login'] and not any(role[k] for k in ('superuser','createrole','replication','bypassrls')), 'Writer role can bypass ordinary DML fence')
        require(one(q, 'SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=%s)', (writer_role, writer_role)) == 0, 'Role membership needs review')
        q.execute("SELECT relname,relkind,pg_get_userbyid(relowner),relacl::text FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind IN ('r','S') ORDER BY relname")
        relations = q.fetchall()
        require({r[0] for r in relations if r[1] == 'r'} == set(TABLES) and {r[0] for r in relations if r[1] == 'S'} == set(SEQUENCES), 'PowerDNS object set differs')
        require(all(r[2] == ('powerdns' if writer_role == 'powerdns' else 'powerdns_owner') for r in relations), 'Object owners differ')
        require(one(q, "SELECT count(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema')") == 0, 'Additional schema needs review')
        require(one(q, "SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace") == 0, 'Custom functions need review')
        require(one(q, "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND (relkind NOT IN ('r','S','i') OR relrowsecurity OR relforcerowsecurity)") == 0, 'Unexpected relation or RLS')
        require(one(q, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)") == 0, 'Custom triggers need review')
        require(one(q, "SELECT count(*) FROM pg_rewrite WHERE ev_class IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace)") == 0, 'Custom rewrite rules need review')
        require(one(q, "SELECT count(*) FROM pg_default_acl") == 0, 'Default grants need review')
        require(one(q, "SELECT count(*) FROM pg_attribute WHERE attrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace) AND attacl IS NOT NULL") == 0, 'Column grants need review')
        require(one(q, 'SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()') == 0, 'Prepared transaction needs review')
        effective = {'tables': {}, 'columns': {}, 'sequences': {},
                     'connect': one(q, 'SELECT has_database_privilege(%s,current_database(),%s)', (writer_role, 'CONNECT'))}
        for table in TABLES:
            relation = 'public.' + table
            effective['tables'][table] = {p: one(q, 'SELECT has_table_privilege(%s,%s,%s)', (writer_role, relation, p)) for p in ('SELECT',) + DML}
            effective['columns'][table] = {p: one(q, 'SELECT has_any_column_privilege(%s,%s,%s)', (writer_role, relation, p)) for p in ('INSERT','UPDATE')}
        for sequence in SEQUENCES:
            effective['sequences'][sequence] = {p: one(q, 'SELECT has_sequence_privilege(%s,%s,%s)', (writer_role, 'public.' + sequence, p)) for p in ('SELECT','USAGE','UPDATE')}
        # Other non-superuser LOGIN roles must not provide an ordinary write path.
        # Include NOINHERIT membership targets: SET ROLE can still expose their rights.
        q.execute("WITH RECURSIVE reachable(oid) AS (SELECT oid FROM pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname<>%s UNION SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member=r.oid) SELECT rolname,rolsuper,rolcreaterole FROM pg_roles WHERE oid IN (SELECT oid FROM reachable) ORDER BY rolname", (writer_role,))
        other = q.fetchall()
        require(len(other)<=256 and not any(r[1] or r[2] for r in other), 'Ordinary login can assume an administrative role')
        other_roles = [r[0] for r in other]
        require(not set(other_roles).intersection(r[2] for r in relations), 'Another ordinary login can assume a relation owner')
        for role_name in other_roles:
            for table in TABLES:
                require(not one(q, "SELECT has_table_privilege(%s,%s,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(%s,%s,'INSERT,UPDATE')", (role_name, 'public.'+table, role_name, 'public.'+table)), 'Another ordinary login can write')
            for sequence in SEQUENCES:
                require(not one(q, "SELECT has_sequence_privilege(%s,%s,'USAGE,UPDATE')", (role_name, 'public.'+sequence)), 'Another ordinary login can change sequences')
        q.execute("SELECT pg_get_userbyid(datdba),datacl::text FROM pg_database WHERE datname=current_database()")
        db_acl = q.fetchone()
        q.execute("SELECT pg_get_userbyid(nspowner),nspacl::text FROM pg_namespace WHERE nspname='public'")
        schema_acl = q.fetchone()
        return {'identity': identity, 'writer_role': writer_role, 'schema_sha256': schema_digest(q),
                'role': role, 'catalog_acl': {'database': list(db_acl), 'schema': list(schema_acl), 'relations': [list(x) for x in relations]}, 'effective': effective}


def validate_fenced(observation):
    e = observation['effective']
    require(set(e) == {'tables','columns','sequences','connect'} and e['connect'] is True, 'Fence lost read connection')
    require(set(e['tables']) == set(TABLES) and set(e['columns']) == set(TABLES) and set(e['sequences']) == set(SEQUENCES), 'Fence privilege inventory incomplete')
    for table in TABLES:
        require(e['tables'][table] == {'SELECT': True, **{p: False for p in DML}}, 'Ordinary table writes are not fenced')
        require(e['columns'][table] == {'INSERT': False, 'UPDATE': False}, 'Column writes are not fenced')
    for sequence in SEQUENCES:
        require(e['sequences'][sequence] == {'SELECT': True, 'USAGE': False, 'UPDATE': False}, 'Sequence changes are not fenced')
    return observation


def assert_fenced(connection, expected_identity, writer_role):
    return validate_fenced(observe(connection, expected_identity, writer_role))


def acquire_lock(connection):
    with connection.cursor() as q:
        require(one(q, 'SELECT pg_try_advisory_lock(hashtextextended(%s,0))', (LOCK_KEY,)) is True, 'Another cutover operation owns this database')


def release_lock(connection):
    with connection.cursor() as q:
        require(one(q, 'SELECT pg_advisory_unlock(hashtextextended(%s,0))', (LOCK_KEY,)) is True, 'Cutover lock ownership lost')


def validate_receipt(receipt, expected_identity, require_phase='verified-fenced'):
    require(isinstance(receipt, dict) and set(receipt) == {'format','kind','operation_id','phase','identity','writer_role','before_sha256','after_sha256','before','after','checked_at','valid_until'}, 'Fence receipt fields differ')
    require(receipt['format'] == 1 and receipt['kind'] == 'powerdns-sql-dml-fence' and receipt['phase'] == require_phase, 'Fence receipt is not verified')
    require(str(uuid.UUID(receipt['operation_id'])) == receipt['operation_id'], 'Invalid fence operation')
    require(receipt['identity'] == expected_identity, 'Fence identity differs')
    snapshot.validate_identity(expected_identity)
    require(receipt['writer_role'] in ('powerdns','powerdns_api'), 'Unexpected fence writer')
    require(receipt['before_sha256'] == digest(receipt['before']) and receipt['after_sha256'] == digest(receipt['after']), 'Fence receipt integrity differs')
    for side in ('before','after'):
        o=receipt[side]
        require(set(o) == {'identity','writer_role','schema_sha256','role','catalog_acl','effective'}, 'Fence observation fields differ')
        require(o['identity'] == expected_identity and o['writer_role'] == receipt['writer_role'], 'Fence observation identity differs')
        require(isinstance(o['schema_sha256'], str) and re.fullmatch('[0-9a-f]{64}', o['schema_sha256']), 'Invalid schema digest')
        role=o['role']
        require(set(role) == {'name','superuser','inherit','createrole','createdb','login','replication','bypassrls'} and role['name'] == receipt['writer_role'], 'Fence role inventory differs')
        require(all(type(role[k]) is bool for k in role if k != 'name') and role['login'] and not any(role[k] for k in ('superuser','createrole','replication','bypassrls')), 'Unsafe fence role')
        require(set(o['catalog_acl']) == {'database','schema','relations'}, 'Fence ACL inventory differs')
    require(receipt['before']['schema_sha256'] == receipt['after']['schema_sha256'] and receipt['before']['role'] == receipt['after']['role'], 'Schema or role changed during fence')
    validate_fenced(receipt['after'])
    start, end = snapshot.timestamp(receipt['checked_at']), snapshot.timestamp(receipt['valid_until'])
    require(0 < (end-start).total_seconds() <= 900, 'Fence observation validity must be bounded')
    return receipt


def make_receipt(operation, before, after):
    now = datetime.now(timezone.utc)
    receipt = {'format':1,'kind':'powerdns-sql-dml-fence','operation_id':operation,'phase':'verified-fenced',
               'identity':after['identity'],'writer_role':after['writer_role'],'before':before,'after':after,
               'before_sha256':digest(before),'after_sha256':digest(after),'checked_at':now.isoformat(),
               'valid_until':(now+timedelta(minutes=15)).isoformat()}
    return validate_receipt(receipt, after['identity'])


def fence_once(connection, plan, persist):
    """Caller owns durable operation journal and lock. No automatic resume/rollback."""
    acquire_lock(connection)
    committed=False
    try:
        with connection.cursor() as q:
            q.execute('BEGIN')
            try:
                q.execute("SET LOCAL lock_timeout='2s'")
                q.execute("SET LOCAL statement_timeout='15s'")
                q.execute("SET LOCAL idle_in_transaction_session_timeout='60s'")
                q.execute('LOCK TABLE '+','.join('public.'+identifier(t) for t in TABLES)+' IN SHARE ROW EXCLUSIVE MODE')
                before=observe(connection, plan['identity'], plan['writer_role'])
                require(digest(before)==plan['before_sha256'], 'Live pre-fence state differs')
                require(any(before['effective']['tables'][t][p] for t in TABLES for p in DML), 'Already fenced; do not replay')
                persist('revoke-intent', {'before':before})
                for table in TABLES:
                    q.execute('REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON TABLE public.'+identifier(table)+' FROM '+identifier(plan['writer_role']))
                for sequence in SEQUENCES:
                    q.execute('REVOKE USAGE,UPDATE ON SEQUENCE public.'+identifier(sequence)+' FROM '+identifier(plan['writer_role']))
                after=assert_fenced(connection,plan['identity'],plan['writer_role'])
                require(after['schema_sha256']==before['schema_sha256'] and after['role']==before['role'], 'Unexpected schema or role change')
                persist('commit-intent', {'before':before,'after':after})
                q.execute('COMMIT');committed=True
            except BaseException:
                if not committed:
                    try:q.execute('ROLLBACK')
                    except Exception:pass
                raise
        verified=assert_fenced(connection,plan['identity'],plan['writer_role'])
        require(verified==after,'Committed fence differs')
        receipt=make_receipt(plan['operation_id'],before,verified)
        persist('verified-fenced',{'receipt':receipt})
        return receipt
    finally:
        release_lock(connection)


def private_dir(path):
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o077 and not path.is_symlink(), 'Owned private state directory required')
    require(not any((a/'.git').exists() for a in (path,*path.parents)), 'State must remain outside Git')


def atomic(path,value):
    private_dir(path.parent);raw=canonical(value)+b'\n';tmp=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    require(not path.is_symlink(),'Receipt symlink rejected');os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('inspect','verify','fence-once'));p.add_argument('--plan',type=Path,required=True);p.add_argument('--connection-file',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--state-dir',type=Path);p.add_argument('--original-receipt',type=Path);a=p.parse_args();os.umask(0o077)
    def deadline(_signal, _frame):
        raise TimeoutError('Fence command deadline exceeded')
    signal.signal(signal.SIGALRM, deadline);signal.alarm(180)
    plan=snapshot.read_private_json(a.plan);snapshot.validate_identity(plan['identity']);require(plan['writer_role'] in ('powerdns','powerdns_api'),'Unexpected writer')
    config=snapshot.read_private_json(a.connection_file,16384);snapshot.validate_connection(config,plan['identity'])
    try:import psycopg as driver
    except ImportError:import psycopg2 as driver
    conn=driver.connect(**config,connect_timeout=5,application_name='infra-flux-pdns-fence',options='-c statement_timeout=15000 -c lock_timeout=2000 -c search_path=pg_catalog');conn.autocommit=True
    try:
        if a.command=='inspect':result=observe(conn,plan['identity'],plan['writer_role'])
        elif a.command=='verify':
            require(a.original_receipt is not None,'Original verified receipt required');old=snapshot.read_private_json(a.original_receipt);validate_receipt(old,plan['identity']);require(old['writer_role']==plan['writer_role'],'Writer mismatch');acquire_lock(conn)
            try:
                observed=assert_fenced(conn,plan['identity'],plan['writer_role']);require(observed==old['after'],'Fence state changed');result=make_receipt(old['operation_id'],old['before'],observed)
            finally:release_lock(conn)
        else:
            require(a.state_dir is not None and plan.get('kind')=='powerdns-sql-dml-fence-plan' and plan.get('format')==1,'Explicit fence plan/state required');private_dir(a.state_dir);require(str(uuid.UUID(plan['operation_id']))==plan['operation_id'],'Invalid operation ID');require(re.fullmatch('[0-9a-f]{64}',plan.get('before_sha256','')),'Preimage hash required')
            key=digest({k:plan['identity'][k] for k in ('system_identifier','database_oid','database')});journal=a.state_dir/('fence-'+key+'.json');fd=os.open(a.state_dir/('fence-'+key+'.lock'),os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600);meta=os.fstat(fd);require(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and not meta.st_mode&0o077,'Unsafe lock')
            with os.fdopen(fd,'w') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);require(not journal.exists(),'Target has a prior fence intent; read back, never replay');record={'operation_id':plan['operation_id'],'plan_sha256':digest(plan)}
                def persist(phase,details):
                    record.update(phase=phase,at=snapshot.utc_now(),**details);atomic(journal,record)
                persist('prepared',{})
                try:result=fence_once(conn,plan,persist)
                except BaseException as error:
                    persist('failed-or-unknown',{'error_type':type(error).__name__,'automatic_retry':False});raise
        snapshot.write_private_json(a.output,result)
        print(json.dumps({'output':str(a.output),'sha256':digest(result),'command':a.command,'ok':True}))
    finally:conn.close()

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'ok':False,'error_type':type(e).__name__}),file=sys.stderr);raise SystemExit(1)
