#!/usr/bin/env python3
"""Opt-in, one-step 100 -> 200 connection maintenance; inspect is read-only."""
import copy
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/etc/infra-postgres/capacity-100-to-200')
OWNER = 'infra-flux/postgres-capacity-v1'
SITES = ('home', 'msk', 'fin')
STEPS = ('patch', 'restart-msk', 'restart-fin', 'restart-home')
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=15s']


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600, 'Untrusted journal file')
    return json.loads(path.read_text())


def kube(args):
    reply = subprocess.run(KUBE + args, capture_output=True, text=True, timeout=100)
    need(reply.returncode == 0, 'Kubernetes operation failed (diagnostics sha256=' +
         hashlib.sha256(reply.stderr.encode()).hexdigest() + ')')
    return json.loads(reply.stdout)


def metadata(cluster_uid):
    need(kube(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid'] == cluster_uid,
         'Cluster identity changed')
    nodes = {n['metadata']['name']: n for n in kube(['get', 'nodes', '-o', 'json'])['items']}
    pods = kube(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres', '-o', 'json'])['items']
    need({p['metadata']['name'] for p in pods} == {'unified-pg-' + s + '-0' for s in SITES},
         'Member set changed')
    pins = {}
    for p in pods:
        site = p['spec']['nodeName']; need(site in SITES, 'Unexpected member node')
        n = nodes[site]
        for resource in (n, p):
            need(not resource['metadata'].get('deletionTimestamp') and any(
                c['type'] == 'Ready' and c['status'] == 'True' for c in resource['status']['conditions']),
                'Member or node not Ready')
        c = next(c for c in p['status']['containerStatuses'] if c['name'] == 'postgres')
        need(c['ready'] and 'running' in c['state'], 'Postgres container not running')
        pins[site] = {'node_uid': n['metadata']['uid'], 'pod': p['metadata']['name'],
                      'pod_uid': p['metadata']['uid'], 'container_id': c['containerID'],
                      'image_id': c['imageID'], 'restarts': c['restartCount'],
                      'pod_spec_sha256': digest(p['spec'])}
    return pins


# Executed in the existing container. Password is read only for the single API
# mutation and never returned. PostgreSQL observations use a read-only session.
POD = r'''
import base64,copy,hashlib,json,os,pathlib,signal,sys,urllib.request
import psycopg
p=json.load(sys.stdin)
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def api(path,data=None,method=None):
 headers={}
 if data is not None:
  password=pathlib.Path('/etc/patroni-credentials/restapi-password').read_text().strip()
  headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(('patroni:'+password).encode()).decode()}
 req=urllib.request.Request('http://127.0.0.1:8008'+path,data=None if data is None else json.dumps(data).encode(),method=method,headers=headers)
 with urllib.request.urlopen(req,timeout=75 if data is not None else 5)as response:
  raw=response.read(1024*1024+1);need(len(raw)<=1024*1024,'API response too large')
  return response.status,raw
def observe():
 status=json.loads(api('/patroni')[1]);config=json.loads(api('/config')[1])
 need(status['patroni']['scope']=='unified-postgres' and status['patroni']['name']==p['member'],'Wrong Patroni member')
 need(status['state']=='running' and not status.get('pause') and not status.get('cluster_unlocked'),'Patroni not healthy/locked')
 need(not status.get('scheduled_restart'),'Unrelated scheduled restart')
 with psycopg.connect(host='/run/postgresql',user='postgres',dbname='postgres',connect_timeout=3,options='-c default_transaction_read_only=on -c statement_timeout=5000 -c search_path=pg_catalog')as conn:
  with conn.cursor()as q:
   q.execute("SELECT system_identifier::text,pg_postmaster_start_time()::text,pg_is_in_recovery(),current_setting('transaction_read_only') FROM pg_control_system()")
   system_id,started,recovery,readonly=q.fetchone();need(readonly=='on','SQL is not read only')
   q.execute("SELECT name,setting,pending_restart FROM pg_settings WHERE context='postmaster' OR name IN ('work_mem','maintenance_work_mem','hash_mem_multiplier','synchronous_commit','synchronous_standby_names') ORDER BY name")
   settings={name:{'setting':value,'pending_restart':pending}for name,value,pending in q.fetchall()}
   q.execute('SELECT pg_last_wal_replay_lsn()::text' if recovery else 'SELECT pg_current_wal_flush_lsn()::text');lsn=q.fetchone()[0]
   q.execute('SELECT application_name,state,sync_state,replay_lsn::text FROM pg_stat_replication ORDER BY application_name')
   replication=[dict(zip(['name','state','sync_state','replay_lsn'],row))for row in q.fetchall()]
 need(str(status['database_system_identifier'])==system_id,'API/SQL system identifier differs')
 need(status['role']==('replica'if recovery else'primary'),'API/SQL role differs')
 variants=[]
 for count in [100,200]:
  v=copy.deepcopy(config);v['postgresql']['parameters']['max_connections']=count;variants.append(digest(v))
 value={'system_id':system_id,'postmaster_started':started,'recovery':recovery,'settings':settings,'lsn':lsn,'replication':replication,
        'role':status['role'],'pending_restart':status.get('pending_restart',False),'pending_reason':status.get('pending_restart_reason',{}),
        'dcs_sha256':digest(config),'dcs_100_sha256':variants[0],'dcs_200_sha256':variants[1],
        'dcs_max_connections':config['postgresql']['parameters']['max_connections'],
        'patroni_start_ticks':pathlib.Path('/proc/1/stat').read_text().rsplit(')',1)[1].split()[19]}
 return value
def stable(v):return {k:x for k,x in v.items()if k not in ['lsn','replication']}
def expired(*_):raise TimeoutError('Bounded Patroni capacity RPC')
signal.signal(signal.SIGALRM,expired);signal.alarm(90)
before=observe()
if p['action']=='inspect':print(json.dumps(before))
else:
 need(stable(before)==stable(p['expected']),'Immediate member preimage changed')
 if p['action']=='patch':
  need(int(before['dcs_max_connections'])==100 and before['settings']['max_connections']['setting']=='100','Patch precondition')
  code,raw=api('/config',{'postgresql':{'parameters':{'max_connections':200}}},'PATCH')
  need(code==200 and digest(json.loads(raw))==before['dcs_200_sha256'],'DCS response differs')
 else:
  need(p['action']=='restart' and int(before['dcs_max_connections'])==200 and before['settings']['max_connections']['setting']=='100','Restart precondition')
  need(before['pending_restart'] and set(before['pending_reason'])=={'max_connections'},'Unrelated or missing pending restart')
  code,raw=api('/restart',{'role':before['role'],'restart_pending':True,'timeout':60},'POST')
  need(code==200,'Restart acknowledgement is not synchronous success')
 print(json.dumps({'status':code,'response_sha256':hashlib.sha256(raw).hexdigest(),'action':p['action']}))
'''


def pod_rpc(pin, action='inspect', expected=None, artifact=None):
    def retain(stdout, stderr, rc, timed_out):
        if artifact is not None:
            streams = {}
            for name, raw in [('stdout', stdout or b''), ('stderr', stderr or b'')]:
                if isinstance(raw, str): raw = raw.encode()
                streams[name] = {'base64': base64.b64encode(raw[:1024 * 1024]).decode(),
                                 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                 'truncated': len(raw) > 1024 * 1024}
            save(artifact, {'action': action, 'pod_uid': pin['pod_uid'], 'container_id': pin['container_id'],
                            'returncode': rc, 'timed_out': timed_out, 'streams': streams})
    try:
        reply = subprocess.run(KUBE + ['exec', '-i', '-n', 'database', pin['pod'], '-c', 'postgres',
                                      '--', '/opt/patroni/bin/python', '-c', POD],
                               input=json.dumps({'member': pin['pod'], 'action': action, 'expected': expected}).encode(),
                               capture_output=True, timeout=100)
    except subprocess.TimeoutExpired as error:
        retain(error.stdout, error.stderr, None, True)
        raise RuntimeError('Pod RPC timed out; retained partial diagnostics, outcome unknown') from None
    retain(reply.stdout, reply.stderr, reply.returncode, False)
    need(reply.returncode == 0, 'Pod RPC failed or outcome unknown; stderr sha256=' +
         hashlib.sha256(reply.stderr).hexdigest())
    need(len(reply.stdout) <= 1024 * 1024, 'Pod RPC response exceeds bound')
    return json.loads(reply.stdout)


def observe(cluster_uid):
    pins = metadata(cluster_uid)
    members = {site: pod_rpc(pins[site]) for site in SITES}
    need(metadata(cluster_uid) == pins, 'Pod/node identities changed during observation')
    value = {'host_machine_id': Path('/etc/machine-id').read_text().strip(),
             'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'cluster_uid': cluster_uid, 'pins': pins, 'members': members}
    healthy(value)
    return value


def healthy(value):
    m = value['members']; need(set(m) == set(SITES), 'Missing member')
    need(len({m[s]['system_id'] for s in SITES}) == 1, 'System identifier differs')
    need(all(m[s]['recovery'] == (s != 'home') for s in SITES), 'HOME must remain primary')
    need(len({m[s]['dcs_sha256'] for s in SITES}) == 1, 'DCS observations disagree')
    rows = m['home']['replication']
    need({x['name'] for x in rows} == {'unified-pg-msk-0', 'unified-pg-fin-0'} and len(rows) == 2
         and all(x['state'] == 'streaming' and x['sync_state'] == 'async' for x in rows),
         'Two streaming asynchronous replicas required')


def lsn(value):
    hi, lo = value.split('/'); return int(hi, 16) * 2**32 + int(lo, 16)


def replay_barrier(value, boundary):
    need(all(value['members'][s]['lsn'] and lsn(value['members'][s]['lsn']) >= lsn(boundary)
             for s in ('msk', 'fin')), 'Replicas have not replayed the primary barrier')


def stable(value):
    v = copy.deepcopy(value)
    for member in v['members'].values():
        member.pop('lsn'); member.pop('replication')
    return v


def check_phase(value, completed):
    healthy(value)
    for site, m in value['members'].items():
        changed = 'restart-' + site in completed
        expected = '200' if changed else '100'
        need(m['settings']['max_connections']['setting'] == expected, 'Unexpected effective capacity')
        pending = set(k for k, v in m['settings'].items() if v['pending_restart'])
        reason = m['pending_reason']
        if 'patch' in completed and not changed:
            need(m['pending_restart'] and set(reason) == {'max_connections'}
                 and str(reason['max_connections']['old_value']) == '100'
                 and str(reason['max_connections']['new_value']) == '200'
                 and pending <= {'max_connections'}, 'Unrelated/missing pending setting')
        else:
            need(not m['pending_restart'] and not reason and not pending, 'Unexpected pending restart')
        need(int(m['dcs_max_connections']) == (200 if 'patch' in completed else 100), 'Wrong DCS capacity')


def transition(before, after, step):
    a, b = stable(before), stable(after)
    selected = step.removeprefix('restart-') if step != 'patch' else None
    for site in SITES:
        old, new = a['members'][site], b['members'][site]
        if step == 'patch':
            need(new['dcs_sha256'] == old['dcs_200_sha256'], 'Unrelated DCS change')
            for key in ('dcs_sha256', 'dcs_max_connections', 'pending_restart', 'pending_reason'):
                new[key] = old[key]
            new['settings']['max_connections']['pending_restart'] = old['settings']['max_connections']['pending_restart']
        elif site == selected:
            need(new['postmaster_started'] != old['postmaster_started'], 'PostgreSQL did not restart')
            new['postmaster_started'] = old['postmaster_started']
            for key in ('pending_restart', 'pending_reason'):
                new[key] = old[key]
            new['settings']['max_connections'] = old['settings']['max_connections']
    need(a == b, 'Unrelated identity/configuration/postmaster change')


def history():
    plan = read(ROOT / 'plan.json')
    result = []
    for step in STEPS:
        intent = ROOT / (step + '.intent.json'); done = ROOT / (step + '.result.json')
        if not intent.exists():
            need(not done.exists(), 'Unlinked step result')
            break
        need(done.exists(), 'Prior outcome unknown; readback only, no replay')
        i, r = read(intent), read(done)
        need(i['owner'] == r['owner'] == OWNER and i['operation'] == r['operation'] == plan['operation']
             and i['step'] == r['step'] == step and i['plan_sha256'] == digest(plan), 'Step linkage differs')
        need(r['verified'] and r['intent_sha256'] == digest(i), 'Prior step failed/unknown; readback only')
        result.append(step)
    need(all(not (ROOT / (s + '.intent.json')).exists() and not (ROOT / (s + '.result.json')).exists()
             for s in STEPS[len(result):]), 'Out-of-order step history')
    return result


def wait_after(cluster_uid, before, step, completed, deadline):
    last = None
    while time.monotonic() < deadline:
        try:
            value = observe(cluster_uid); check_phase(value, completed + [step]); transition(before, value, step)
            replay_barrier(value, before['members']['home']['lsn'])
            return value
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            last = error; time.sleep(2)
    raise RuntimeError('Read-only acceptance deadline; ' + str(last))


def execute(request):
    step = request['action']; need(step in STEPS and request.get('enabled') is True, 'Explicit opt-in required')
    need(re.fullmatch(r'[0-9a-f]{32}', request['operation']), 'One reviewed operation UUID required')
    review = request['review']; need(review['cluster_uid'] == request['cluster_uid'], 'Review cluster differs')
    if not ROOT.exists():
        need(step == 'patch', 'Patch must be first'); ROOT.mkdir(mode=0o700)
    meta = ROOT.lstat(); need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
                             and stat.S_IMODE(meta.st_mode) == 0o700, 'Unowned journal directory')
    fd = os.open(ROOT / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        meta = os.fstat(lock.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid() and meta.st_nlink == 1
             and stat.S_IMODE(meta.st_mode) == 0o600, 'Untrusted operation lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = {'owner': OWNER, 'operation': request['operation'], 'review': review}
        existing = (ROOT / 'plan.json').exists()
        if existing:
            need(read(ROOT / 'plan.json') == plan, 'Original operation/review changed')
            completed = history()
        else:
            need(step == 'patch' and set(p.name for p in ROOT.iterdir()) == {'lock'}, 'Unexpected existing journal')
            completed = []
        need(len(completed) < len(STEPS) and step == STEPS[len(completed)], 'Step already attempted or out of order')
        before = observe(request['cluster_uid']); expected = review if not completed else read(ROOT / (completed[-1] + '.result.json'))['after']
        need(stable(before) == stable(expected), 'Reviewed/current step preimage changed'); check_phase(before, completed)
        replay_barrier(before, before['members']['home']['lsn'])
        # A refused initial read-only preflight has no immutable operation yet.
        # Once this plan is durable, it and every attempted step stay immutable.
        if not existing:
            save(ROOT / 'plan.json', plan)
        intent = {'owner': OWNER, 'operation': request['operation'], 'step': step, 'plan_sha256': digest(plan), 'before': before, 'started_at': time.time()}
        save(ROOT / (step + '.intent.json'), intent)
        result = {'owner': OWNER, 'operation': request['operation'], 'step': step, 'intent_sha256': digest(intent), 'verified': False, 'outcome_unknown': True}
        try:
            site = 'home' if step == 'patch' else step.removeprefix('restart-')
            need(metadata(request['cluster_uid']) == before['pins'], 'Immediate outer identity drift')
            result['rpc'] = pod_rpc(before['pins'][site], 'patch' if step == 'patch' else 'restart', before['members'][site],
                                    artifact=ROOT / (step + '.rpc.json'))
            result['after'] = wait_after(request['cluster_uid'], before, step, completed, time.monotonic() + 120)
            result.update(verified=True, outcome_unknown=False)
        except BaseException as error:
            result.update(error_type=type(error).__name__, error=str(error))
        finally:
            if (ROOT / (step + '.rpc.json')).exists():
                result['rpc_artifact_sha256'] = digest(read(ROOT / (step + '.rpc.json')))
            result['completed_at'] = time.time(); save(ROOT / (step + '.result.json'), result)
        return result


def main(request):
    action = request.get('action', 'inspect')
    if action == 'inspect':
        return {'kind': OWNER, 'changed': False, 'review': observe(request['cluster_uid'])}
    if action == 'readback':
        plan = read(ROOT / 'plan.json')
        need(plan['owner'] == OWNER and plan['review']['cluster_uid'] == request['cluster_uid'], 'Readback journal cluster differs')
        value = observe(request['cluster_uid'])
        records = {s: read(ROOT / (s + '.result.json')) if (ROOT / (s + '.result.json')).exists() else None
                   for s in STEPS if (ROOT / (s + '.intent.json')).exists()}
        return {'kind': OWNER, 'changed': False, 'operation': plan['operation'], 'observation': value, 'recorded_steps': records,
                'adopted_unknown': False}
    return execute(request)


if __name__ == '__main__':
    os.umask(0o077)
    def expired(*_):
        raise TimeoutError('Capacity invocation deadline')
    signal.signal(signal.SIGALRM, expired); signal.alarm(480)
    answer = main(json.load(sys.stdin)); print(json.dumps(answer, sort_keys=True))
    if answer.get('verified') is False:
        raise SystemExit(1)
