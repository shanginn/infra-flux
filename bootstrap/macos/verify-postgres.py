#!/usr/bin/env python3
"""Verify a PostgreSQL framed backup, then restore only into an isolated scratch.

read_stream() checks framing/checksums into a new private Mac file. It is not a
restore test. verify_restore() explicitly uses a reviewed home SSH alias and
an isolated, temporary PG18 containerd container. It never starts Docker or
connects restored SQL to a production PostgreSQL server.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

MAGIC = b'INFRA-POSTGRES-DUMPALL/1\n'
IMAGE = 'ghcr.io/shanginn/infra-flux-patroni@sha256:5581048b8a2c28f0e3e16aa481c1b5f094c425edeaa9900bf1aef651da16863f'
HOME_RESTORE_ALIASES = ('homelab-vpn', 'homelab-overlay')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_stream(stream, destination, max_bytes, cluster_name):
    """Return metadata only after complete framing and SHA256 verification.

    destination must be a new file in an already private directory on the Mac.
    The caller must check the upstream restic producer's exit code as well.
    """
    require(4 * 1048576 <= max_bytes <= 32 * 1024**3, 'Invalid stream bound')
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink(), 'Destination must be new')
    require(destination.parent.stat().st_mode & 0o077 == 0, 'Private staging directory is required')
    require(shutil.disk_usage(destination.parent).free >= max_bytes + 2 * 1024**3,
            'Reserve the entire bounded SQL staging space before decrypting')
    total = 0
    def exact(size):
        nonlocal total
        total += size
        require(total <= max_bytes, 'Stream exceeds bound')
        chunks, remaining = [], size
        while remaining:
            block = stream.read(remaining)
            require(block, 'Truncated stream')
            chunks.append(block); remaining -= len(block)
        return b''.join(chunks)
    def frame():
        size = struct.unpack('!I', exact(4))[0]
        require(size <= 1048576, 'Invalid frame size')
        return exact(size)
    require(exact(len(MAGIC)) == MAGIC, 'Unexpected stream format')
    metadata = json.loads(frame())
    require(metadata['format'] == 1 and metadata['component'] == 'postgres' and
            metadata['cluster_name'] == cluster_name and metadata['image'] == IMAGE and
            metadata['consistency'] == 'per-database', 'Unexpected backup identity')
    source = metadata['source']
    require(source['version_num'] == 180006 and source['in_recovery'] is False and
            source['custom_tablespaces'] == 0 and 0 < source['database_bytes'] <= 24 * 1024**3,
            'Unexpected PostgreSQL source')
    require(source['databases'] and source['roles'] and all(d['allowconn'] for d in source['databases']),
            'Incomplete source inventory')
    digest, sql_bytes = hashlib.sha256(), 0
    with destination.open('xb') as output:
        os.chmod(destination, 0o600)
        while block := frame():
            digest.update(block); sql_bytes += len(block); output.write(block)
        output.flush(); os.fsync(output.fileno())
    footer = json.loads(frame())
    require(footer['sql_bytes'] == sql_bytes > 0 and footer['sql_sha256'] == digest.hexdigest() and
            footer['primary_unchanged'] is True and footer['completed_at'] >= metadata['created_at'],
            'Invalid completed export checksum')
    require(not stream.read(1), 'Unexpected trailing data')
    return metadata | {'sql_sha256': digest.hexdigest(), 'sql_bytes': sql_bytes}


# This helper runs inside a non-privileged container with no host networking,
# host socket, production volume, credentials or Kubernetes service account.
CONTAINER_RESTORE = r'''
import json,os,pathlib,subprocess,sys,uuid
expected=json.loads(sys.argv[1])
root=pathlib.Path('/restore'); data=root/'data'; socket=root/'socket'
assert not data.exists()
socket.mkdir(mode=0o700)
user='infra_verify_'+uuid.uuid4().hex
assert user not in expected['source']['roles']
env=os.environ.copy();env.update(LC_ALL='C.UTF-8')
def run(args,**kwargs):
 return subprocess.run(args,env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**kwargs)
bin='/usr/lib/postgresql/18/bin/'
run([bin+'initdb','-D',str(data),'-U',user,'--auth-local=trust','--auth-host=reject','--encoding=UTF8','--locale=C.UTF-8'],timeout=120)
options="-c listen_addresses='' -c unix_socket_directories=/restore/socket -c port=55432 -c shared_buffers=128MB -c max_connections=20 -c max_wal_size=512MB -c log_min_error_statement=panic"
started=False
try:
 run([bin+'pg_ctl','-D',str(data),'-o',options,'-l',str(root/'server.log'),'start','-w','-t','60'],timeout=90);started=True
 psql=[bin+'psql','-X','-h',str(socket),'-p','55432','-U',user,'-d','postgres','-v','ON_ERROR_STOP=1','-q']
 with (root/'input.sql.pipe').open('rb') as sql:
  run(psql,stdin=sql,timeout=3000)
 query="SELECT json_build_object('databases',(SELECT json_agg(datname ORDER BY datname) FROM pg_database WHERE datname <> 'template0'),'roles',(SELECT json_agg(rolname ORDER BY rolname) FROM pg_roles WHERE rolname !~ '^pg_'));"
 result=json.loads(subprocess.run(psql+['-At','-c',query],check=True,capture_output=True,env=env,timeout=30).stdout)
 assert result['databases']==sorted(d['name'] for d in expected['source']['databases'])
 assert set(result['roles'])==set(expected['source']['roles'])|{user}
 run([bin+'pg_amcheck','--all','--install-missing','--heapallindexed','--jobs=1','-h',str(socket),'-p','55432','-U',user],timeout=900)
 print(json.dumps({'restore_completed':True,'pg_amcheck_completed':True,'database_count':len(result['databases']),'role_count':len(expected['source']['roles']),'cross_database_snapshot':False}),flush=True)
finally:
 if started:run([bin+'pg_ctl','-D',str(data),'stop','-m','immediate','-w','-t','30'],timeout=40)
'''


# Passed by SSH as code, with SQL on stdin. No SQL archive is written remotely;
# the only large remote data is the temporary restored database itself.
REMOTE_RESTORE = r'''
import hashlib,json,os,pathlib,shutil,signal,subprocess,sys,tempfile,threading,time,uuid
expected=json.loads(sys.argv[1]);container_code=sys.argv[2];image=sys.argv[3]
assert os.geteuid()==0
marker=json.loads(pathlib.Path('/etc/infra-flux/kubeadm-state.json').read_text())
assert marker['managed_by']=='infra-flux/ansible/kubeadm' and marker['node_name']=='home'
assert marker['cluster_name']==expected['cluster_name'] and marker['ca_sha256']==expected['ca_sha256']
assert hashlib.sha256(pathlib.Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest()==expected['ca_sha256']
os.umask(0o077)
def interrupted(*_):raise TimeoutError('Scratch restore interrupted')
for sig in (signal.SIGALRM,signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,interrupted)
signal.alarm(4200)
reserve=77*1024**3;budget=32*1024**3
assert shutil.disk_usage('/var/lib').free>=reserve+budget+1024**3
assert int(pathlib.Path('/proc/meminfo').read_text().split('MemAvailable:')[1].split()[0])*1024>=4*1024**3
name='infra-pg-verify-'+uuid.uuid4().hex
root=pathlib.Path(tempfile.mkdtemp(prefix='.'+name+'-',dir='/var/lib'))
os.chown(root,19999,19999)
fifo=root/'input.sql.pipe';os.mkfifo(fifo,0o600);os.chown(fifo,19999,19999)
ctr=['/usr/bin/ctr','--namespace',name]
made_namespace=False;process=None;clean=False
def run(args,**kwargs):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,**kwargs)
try:
 run(['/usr/bin/ctr','namespaces','create',name,'infra.shanginn.io/managed-by=infra-postgres-restore'],check=True,timeout=20);made_namespace=True
 run(ctr+['images','pull','--platform','linux/amd64',image],check=True,timeout=600)
 args=ctr+['run','--rm','--read-only','--user','19999:19999','--seccomp','--cpus','1','--memory-limit',str(2*1024**3),
  '--label','infra.shanginn.io/managed-by=infra-postgres-restore',
  '--mount','type=bind,src='+str(root)+',dst=/restore,options=rbind:rw',image,name,
  '/opt/patroni/bin/python','-c',container_code,json.dumps(expected)]
 # ctr requires explicit CAP_ names; unlike docker it has no ALL shorthand.
 caps=('CHOWN','DAC_OVERRIDE','FSETID','FOWNER','MKNOD','NET_RAW','SETGID','SETUID',
       'SETFCAP','SETPCAP','NET_BIND_SERVICE','SYS_CHROOT','KILL','AUDIT_WRITE')
 at=args.index(image)
 args[at:at]=[value for cap in caps for value in ('--cap-drop','CAP_'+cap)]
 process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
 transfer={'ok':False}
 def pump():
  try:
   digest=hashlib.sha256();total=0
   with fifo.open('wb') as sql:
    while block:=sys.stdin.buffer.read(1048576):
     total+=len(block);assert total<=expected['sql_bytes'];digest.update(block)
     sql.write(block)
    assert total==expected['sql_bytes'] and digest.hexdigest()==expected['sql_sha256']
   transfer['ok']=True
  except BaseException:transfer['failed']=True
 thread=threading.Thread(target=pump,daemon=True);thread.start()
 start=time.monotonic();next_size=0
 while process.poll() is None:
  assert not transfer.get('failed') and time.monotonic()-start<3600
  assert shutil.disk_usage('/var/lib').free>=reserve
  if time.monotonic()>=next_size:
   used=int(run(['/usr/bin/du','-sx','--block-size=1',str(root)],check=True,timeout=10).stdout.split()[0])
   assert used<=budget
   next_size=time.monotonic()+2
  time.sleep(0.5)
 thread.join(timeout=5)
 assert process.returncode==0 and transfer['ok']
 proof=json.loads(process.stdout.read(65537));assert proof['restore_completed'] and proof['pg_amcheck_completed']
finally:
 if made_namespace:
  run(ctr+['tasks','kill','--signal','SIGKILL',name],check=False,timeout=20)
  run(ctr+['tasks','rm','--force',name],check=False,timeout=20)
  if process is not None and process.poll() is None:process.kill();process.wait(timeout=20)
  tasks=run(ctr+['tasks','list','--quiet'],check=True,timeout=20).stdout.strip()
  assert not tasks,'Scratch task still exists; preserve its data for explicit cleanup'
  run(ctr+['containers','rm',name],check=False,timeout=20)
  run(ctr+['snapshots','rm',name],check=False,timeout=20)
  run(ctr+['images','rm','--sync',image],check=False,timeout=120)
  run(['/usr/bin/ctr','namespaces','rm',name],check=True,timeout=20)
 assert root.name.startswith('.'+name+'-') and root.parent==pathlib.Path('/var/lib') and not root.is_symlink()
 shutil.rmtree(root);clean=True
assert clean
print(json.dumps(proof|{'scratch_removed':True,'sql_sha256':expected['sql_sha256'],'restore_backend':'isolated-home-containerd'}))
'''


def verify_restore(metadata, sql_file, ssh_alias, *, ssh_jump_chain=None):
    """Run only after explicit selection of the scratch restore host."""
    require(ssh_alias in HOME_RESTORE_ALIASES, 'Only the reviewed home scratch aliases are supported')
    chain = [] if ssh_jump_chain is None else ssh_jump_chain
    require(isinstance(chain, list) and len(chain) <= 3 and
            all(isinstance(alias, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', alias) for alias in chain),
            'SSH jump chain must contain at most three plain aliases')
    require(len(set(chain)) == len(chain) and ssh_alias not in chain, 'SSH jump chain contains a loop')
    jump = ['-J', ','.join(chain)] if chain else []
    sql_file = Path(sql_file)
    require(sql_file.is_file() and not sql_file.is_symlink() and sql_file.stat().st_mode & 0o077 == 0,
            'Private restored SQL file is required')
    require(sql_file.stat().st_size == metadata['sql_bytes'], 'SQL file size differs')
    remote = shlex.join(['/usr/bin/python3', '-c', REMOTE_RESTORE, json.dumps(metadata), CONTAINER_RESTORE, IMAGE])
    with sql_file.open('rb') as source:
        result = subprocess.run(['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                 '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                                 *jump,
                                 ssh_alias, remote], stdin=source, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=4260, check=False)
    require(result.returncode == 0, 'Isolated scratch restore failed')
    require(len(result.stdout) <= 65536, 'Restore proof exceeds bound')
    proof = json.loads(result.stdout)
    require(proof['restore_completed'] is True and proof['pg_amcheck_completed'] is True and
            proof['scratch_removed'] is True and proof['sql_sha256'] == metadata['sql_sha256'],
            'Missing complete restore proof')
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-bytes', type=int, required=True)
    parser.add_argument('--cluster-name', required=True)
    parser.add_argument('--verify-ssh', choices=HOME_RESTORE_ALIASES, required=True)
    parser.add_argument('--staging-parent', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.staging_parent.stat().st_mode & 0o077 == 0, 'Private Mac staging parent is required')
        with tempfile.TemporaryDirectory(prefix='postgres-restore-', dir=args.staging_parent) as directory:
            target = Path(directory) / 'postgres.sql'
            metadata = read_stream(sys.stdin.buffer, target, args.max_bytes, args.cluster_name)
            print(json.dumps(verify_restore(metadata, target, args.verify_ssh)))
    except Exception as error:
        print(f'PostgreSQL restore verification failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
