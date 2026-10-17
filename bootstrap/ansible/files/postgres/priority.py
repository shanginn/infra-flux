#!/usr/bin/env python3
"""Reload reviewed per-member priorities without replacing Pods or switching roles."""
import json
import subprocess
import sys

settings = json.load(sys.stdin)
assert settings['enabled'] is True
kube = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=20s']
priorities = {'home': 100, 'msk': 50, 'fin': 10}


def run(args):
    result = subprocess.run(kube + args, capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise RuntimeError(result.stderr[-1000:])
    return json.loads(result.stdout)


assert run(['get', 'namespace', 'kube-system', '-o', 'json'])['metadata']['uid'] == settings['cluster_uid']
controller = run(['get', 'kustomization.kustomize.toolkit.fluxcd.io', 'unified-postgres', '-n', 'flux-system', '-o', 'json'])
assert controller['metadata']['annotations']['infra.shanginn.io/managed-by'] == 'infra-flux/ansible/postgres'
assert controller['metadata']['annotations']['infra.shanginn.io/stage'] == 'full'
assert not controller['spec'].get('suspend', False)
pods = run(['get', 'pods', '-n', 'database', '-l', 'cluster-name=unified-postgres', '-o', 'json'])['items']
assert {p['metadata']['name'] for p in pods} == {'unified-pg-' + site + '-0' for site in priorities}
assert all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status']['conditions']) for p in pods)
assert sum(p['metadata']['labels'].get('role') == 'primary' for p in pods) == 1
for pod in pods:
    site = pod['spec']['nodeName']
    running = next(c for c in pod['spec']['containers'] if c['name'] == 'postgres')
    assert next(e['value'] for e in running['env'] if e['name'] == 'FAILOVER_PRIORITY') == str(priorities[site]), 'Old Pod environment requires one-at-a-time replica replacement and planned switchover before reload'
    assert site in priorities and pod['metadata']['name'] == 'unified-pg-' + site + '-0'
    sts = run(['get', 'statefulset', 'unified-pg-' + site, '-n', 'database', '-o', 'json'])
    assert sts['spec']['updateStrategy']['type'] == 'OnDelete'
    container = next(c for c in sts['spec']['template']['spec']['containers'] if c['name'] == 'postgres')
    assert next(e['value'] for e in container['env'] if e['name'] == 'FAILOVER_PRIORITY') == str(priorities[site]), 'Reconcile the reviewed Git configuration first'

code = r'''
import base64,json,os,pathlib,stat,tempfile,time,urllib.request,yaml,psycopg
expected_name,priority=__INPUT__
path=pathlib.Path('/run/patroni/patroni.yaml');meta=path.lstat()
assert stat.S_ISREG(meta.st_mode) and meta.st_uid==os.getuid()==19999 and stat.S_IMODE(meta.st_mode)==0o600
config=yaml.safe_load(path.read_text())
assert config['scope']=='unified-postgres' and config['namespace']=='database' and config['name']==expected_name
assert 'nofailover' not in config['tags'], 'Conflicting nofailover tag requires separate review'
def state():
 with psycopg.connect(host='/run/postgresql',user='postgres',dbname='postgres',connect_timeout=3,options='-c default_transaction_read_only=on -c statement_timeout=3000') as conn:
  with conn.cursor() as query:
   query.execute('SELECT pg_is_in_recovery(),pg_postmaster_start_time()::text');return query.fetchone()
before=state();changed=config['tags'].get('failover_priority')!=priority
if changed:
 config['tags']['failover_priority']=priority
 fd,name=tempfile.mkstemp(prefix='.priority-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as stream:
   yaml.safe_dump(config,stream,sort_keys=False);stream.flush();os.fsync(stream.fileno())
  os.chmod(name,0o600);os.replace(name,path)
 finally:
  if os.path.exists(name):os.unlink(name)
 password=pathlib.Path('/etc/patroni-credentials/restapi-password').read_text().strip()
 request=urllib.request.Request('http://127.0.0.1:8008/reload',data=b'{}',method='POST',headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(('patroni:'+password).encode()).decode()})
 with urllib.request.urlopen(request,timeout=5) as reply:assert reply.status==202
for attempt in range(10):
 with urllib.request.urlopen('http://127.0.0.1:8008/patroni',timeout=3) as reply:status=json.load(reply)
 if status.get('tags',{}).get('failover_priority')==priority:break
 time.sleep(1)
else:raise RuntimeError('Patroni did not publish the requested priority')
assert state()==before, 'Role or PostgreSQL start time changed during priority reload'
print(json.dumps({'name':expected_name,'priority':priority,'changed':changed,'role':status['role'],'postgres_restart':False}))
'''
results = []
for pod in pods:
    site = pod['spec']['nodeName']
    script = code.replace('__INPUT__', repr((pod['metadata']['name'], priorities[site])))
    results.append(run(['exec', '-n', 'database', pod['metadata']['name'], '-c', 'postgres', '--', '/opt/patroni/bin/python', '-c', script]))
print(json.dumps({'members': results, 'changed': any(result['changed'] for result in results)}))
