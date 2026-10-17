#!/usr/bin/env python3
"""Owned bounded host metrics; no new listener, package install or existing-service restart."""
import argparse
import csv
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

OWNER='infra-flux/monitoring-detail-v1'
ROOT=Path('/etc/infra-flux/monitoring-detail')
OUTPUT=Path('/var/lib/node_exporter/textfile_collector/infra-detail.prom')
UNIT=Path('/etc/systemd/system/infra-monitoring-detail.service')
TIMER=Path('/etc/systemd/system/infra-monitoring-detail.timer')
BOOTSTRAP=Path('/etc/infra-flux/kubeadm-state.json')
HEADSCALE={'headscale_mapper_changes_dropped_total','headscale_mapresponse_ended_total','headscale_mapresponse_endpoint_updates_total',
 'headscale_mapresponse_generated_total','headscale_mapresponse_sent_total','headscale_nodestore_nodes','headscale_nodestore_queue_depth',
 'headscale_nodestore_operations_total','headscale_nodestore_snapshot_builds_total','http_requests_inflight','http_requests_total',
 'http_request_duration_seconds_bucket','http_request_duration_seconds_count','http_request_duration_seconds_sum'}
DERP={'derp_accepts','derp_bytes_dropped','derp_bytes_received','derp_bytes_sent','derp_clients_local','derp_clients_remote','derp_clients_total',
 'derp_current_connections','derp_current_home_connections','derp_current_notideal_connections','derp_packets_dropped',
 'derp_packets_received','derp_packets_sent','derp_sclient_write_timeouts','derp_got_ping','derp_sent_pong','derp_average_queue_duration_ms'}
COMMON_SERVICES=['ssh.service','tailscaled.service','containerd.service','kubelet.service','infra-k8s-api-proxy.service','infra-patroni-watchdog.service']
OVERLAY_SERVICES=['infra-headscale-netns.service','infra-overlay-edge.service','infra-stun.service','infra-derper.service','infra-headscale.service']
HOME_SERVICES=['generach-inswapper.service','watchdog.service','infra-nvidia-uvm.service']
PROPERTIES='Id,LoadState,ActiveState,SubState,NRestarts'


def require(ok,msg):
    if not ok: raise RuntimeError(msg)

def sha(b):return hashlib.sha256(b).hexdigest()

def trusted(path,private=False):
    st=path.lstat();require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode & (0o077 if private else 0o022),'Untrusted owned input')
    return path.read_bytes()

def directory(path):
    st=path.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'Untrusted owned directory')

def atomic(path,data,mode=0o600):
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path);d=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:Path(tmp).unlink(missing_ok=True)

def run(args,timeout=5):
    p=subprocess.run(args,capture_output=True,timeout=timeout)
    require(p.returncode==0,'Bounded read failed: '+Path(args[0]).name)
    require(len(p.stdout)<=1048576,'Read exceeded 1 MiB')
    return p.stdout

def identity(node):
    raw=trusted(BOOTSTRAP,True);m=json.loads(raw)
    require(m.get('managed_by')=='infra-flux/ansible/kubeadm' and m.get('cluster_name')=='unified' and m.get('node_name')==node,'Bootstrap owner differs')
    ca=sha(trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(ca==m['ca_sha256'],'CA differs')
    mon=json.loads(trusted(Path('/etc/infra-flux/monitoring.json')))
    require(mon.get('managed_by')=='infra-flux/ansible/monitoring' and mon.get('node')==node,'Monitoring prerequisite differs')
    directory(OUTPUT.parent)
    return {'node':node,'machine_id':trusted(Path('/etc/machine-id')).decode().strip(),'ca_sha256':ca,'bootstrap_sha256':sha(raw)}

def make_config(node):
    proof=identity(node)
    k=json.loads(run(['/usr/bin/kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--server=https://api.unified.internal:7443','--request-timeout=5s','get','node',node,'-o','json'],8))
    require(k['metadata']['name']==node and k['metadata']['labels'].get('infra.shanginn.io/site')==node,'Registered node differs')
    proof['node_uid']=k['metadata']['uid']
    services={s:True for s in COMMON_SERVICES}
    config={'owner':OWNER,'identity':proof,'services':services,'gpu':False,'overlay':None}
    if node=='home':
        services.update({s:True for s in HOME_SERVICES})
        config['gpu']=Path('/usr/bin/nvidia-smi').is_file() and Path('/sys/module/nvidia').is_dir()
    else:
        m=json.loads(trusted(Path('/etc/infra-flux/overlay.json')))
        require(m.get('owner')=='infra-flux/ansible/overlay' and type(m.get('coordinator')) is bool,'Overlay prerequisite differs')
        ip=str(ipaddress.ip_interface(m['namespace_service']).ip)
        require(ipaddress.ip_address(ip).is_private,'Overlay service must remain private')
        ns=Path('/run/netns/infra-headscale');require(ns.exists() and not ns.is_symlink(),'Owned overlay namespace absent')
        services.update({s:True for s in OVERLAY_SERVICES});services['infra-headscale.service']=m['coordinator']
        config['overlay']={'ip':ip,'hostname':'derp-'+node+'.shanginn.io','coordinator':m['coordinator']}
    return config

def unit_guard(owned):
    for unit in (UNIT,TIMER):
        result=subprocess.run(['/usr/bin/systemctl','show',unit.name,'--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths'],capture_output=True,timeout=5)
        require(len(result.stdout)<16384,'Unit readback exceeded bound')
        props=dict(x.split('=',1) for x in result.stdout.decode().splitlines() if '=' in x)
        require(not props.get('DropInPaths'),'Unexpected collector unit drop-ins')
        if owned:
            require(result.returncode==0 and props.get('FragmentPath')==str(unit),'Loaded collector unit is not its owned file')
        else:
            require(result.returncode in (0,1) and props.get('LoadState')=='not-found' and props.get('ActiveState')=='inactive' and
                    props.get('MainPID','0')=='0' and not props.get('FragmentPath'),'Refuse a pre-existing collector unit')


def inspect(node):
    config=make_config(node);paths=[ROOT/'collector.py',ROOT/'config.json',UNIT,TIMER]
    marker=ROOT/'ownership.json'
    if ROOT.exists():directory(ROOT)
    if marker.exists():
        previous=json.loads(trusted(marker,True));require(previous.get('owner')==OWNER and previous['identity']==config['identity'],'Collector owner changed')
        require(set(previous['files'])=={str(x) for x in paths},'Unexpected owned file inventory')
        for p in paths:require(sha(trusted(p))==previous['files'][str(p)],'Owned collector file changed; review before update')
    else:
        require(not ROOT.exists() and all(not p.exists() and not p.is_symlink() for p in paths) and not OUTPUT.exists() and not OUTPUT.is_symlink() and not ROOT.is_symlink(),'Refuse to adopt existing collector files')
    unit_guard(marker.exists())
    return config

def install(args):
    config=inspect(args.node);require(json.loads(args.review_json or '{}')==config['identity'],'Reviewed node identity differs')
    require(sha(args.source.encode())==args.source_sha256,'Reviewed collector source differs')
    service=f'''[Unit]
Description=Bounded private infrastructure metrics
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {ROOT}/collector.py collect
TimeoutStartSec=45
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ReadWritePaths={ROOT} {OUTPUT.parent}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=128M
CPUQuota=20%
TasksMax=32
'''
    timer='''[Unit]
Description=Collect bounded private infrastructure metrics every minute
[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s
RandomizedDelaySec=10s
Unit=infra-monitoring-detail.service
[Install]
WantedBy=timers.target
'''
    files={ROOT/'collector.py':args.source.encode(),ROOT/'config.json':(json.dumps(config,sort_keys=True)+'\n').encode(),UNIT:service.encode(),TIMER:timer.encode()}
    unchanged=ROOT.exists() and all(path.exists() and trusted(path)==data for path,data in files.items())
    if unchanged:
        require(run(['/usr/bin/systemctl','is-enabled',TIMER.name]).strip()==b'enabled' and run(['/usr/bin/systemctl','is-active',TIMER.name]).strip()==b'active','Owned collector timer is not enabled/active')
        return {'installed':True,'changed':False,'identity':config['identity']}
    if not ROOT.exists():ROOT.mkdir(mode=0o700)
    for path,data in files.items():atomic(path,data,0o644 if path in (UNIT,TIMER) else 0o600)
    atomic(ROOT/'ownership.json',(json.dumps({'owner':OWNER,'identity':config['identity'],'files':{str(k):sha(v) for k,v in files.items()}},sort_keys=True)+'\n').encode())
    run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','enable','--now','infra-monitoring-detail.timer'])
    # Only our new read-only oneshot is started; existing services are untouched.
    run(['/usr/bin/systemctl','start','infra-monitoring-detail.service'],50)
    require(OUTPUT.exists(),'Collector did not publish metrics')
    status=re.findall(rb'^infra_detail_collect_success\{[^\n]+\} ([01])$',trusted(OUTPUT),re.M)
    require(status and all(x==b'1' for x in status),'Initial collection has a failed component; inspect private metrics status')
    return {'installed':True,'changed':True,'identity':config['identity'],'output_sha256':sha(trusted(OUTPUT))}

def parse_metrics(raw,component):
    require(len(raw)<=1048576,'Metrics response exceeded 1 MiB')
    allowed=HEADSCALE if component=='headscale' else DERP
    values={}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([-+0-9.eE]+|[+-]?Inf|NaN)(?:\s+\d+)?',line)
        require(match is not None,'Malformed Prometheus response')
        name,labels,value=match.groups()
        if name not in allowed:continue
        value=float(value);require(math.isfinite(value) and value>=0,'Invalid allowed metric')
        suffix=''
        if name.endswith('_bucket'):
            le=re.search(r'(?:\{|,)le="([0-9.eE+-]+|\+Inf)"(?:,|\})',labels or '')
            require(le is not None,'Histogram boundary absent');suffix='{le="'+le[1]+'"}'
        # All identity, route, user and other dynamic labels are removed and summed.
        key='infra_'+component+'_'+name.removeprefix(component+'_')+suffix;values[key]=values.get(key,0)+value
    require(values and len(values)<=200,'No allowed metrics or excessive families')
    return values

def endpoint_metrics(component,overlay):
    if component=='headscale':
        c=http.client.HTTPConnection('127.0.0.1',9090,timeout=4);path='/metrics'
    else:
        class LocalTLS(http.client.HTTPSConnection):
            def connect(self):
                self.sock=self._context.wrap_socket(socket.create_connection((overlay['ip'],8444),timeout=4,source_address=('127.0.0.1',0)),server_hostname=self.host)
        c=LocalTLS(overlay['hostname'],context=ssl.create_default_context(),timeout=4);path='/debug/varz'
    try:
        c.request('GET',path);r=c.getresponse();require(r.status==200,'Private metrics endpoint unavailable')
        return parse_metrics(r.read(1048577),component)
    finally:c.close()

def gpu_executable(path=Path('/usr/bin/nvidia-smi')):
    # Debian alternatives are root-owned symlinks; never execute an untrusted target.
    current=path;seen=set()
    for _ in range(8):
        require(current.is_absolute() and current not in seen,'GPU executable link cycle')
        seen.add(current);st=current.lstat();require(st.st_uid==0,'GPU executable owner differs')
        for parent in current.parent.resolve(strict=True).parents:directory(parent)
        directory(current.parent.resolve(strict=True))
        if not stat.S_ISLNK(st.st_mode):break
        target=Path(os.readlink(current));current=target if target.is_absolute() else current.parent/target
    else:raise RuntimeError('GPU executable link chain exceeded bound')
    resolved=current.resolve(strict=True)
    require(str(resolved).startswith('/usr/') and stat.S_ISREG(st.st_mode) and not st.st_mode & 0o022 and st.st_mode & 0o111,
            'GPU executable is not a trusted installed binary')
    return str(resolved)


def gpu_metrics(raw):
    values={};rows=list(csv.reader(raw.decode().splitlines()));require(0<len(rows)<=16,'Unexpected GPU inventory')
    names=['index','utilization_percent','memory_used_bytes','memory_total_bytes','temperature_celsius']
    for row in rows:
        require(len(row)==5,'Unexpected GPU query shape');index=row[0].strip();require(re.fullmatch(r'\d{1,2}',index),'Unexpected GPU index')
        for name,value in zip(names[1:],row[1:]):
            value=float(value.strip());require(math.isfinite(value) and value>=0,'Unavailable GPU numeric field')
            if name.startswith('memory_'):value*=1048576
            key='infra_gpu_'+name+'{gpu="'+index+'"}';require(key not in values,'Duplicate GPU index');values[key]=value
    return values

def collect():
    config=json.loads(trusted(ROOT/'config.json',True));require(config['owner']==OWNER,'Unknown collector config')
    proof=identity(config['identity']['node']);require(all(config['identity'][k]==v for k,v in proof.items()),'Collector host identity changed')
    state_path=ROOT/'last-success.json';state=json.loads(trusted(state_path,True)) if state_path.exists() else {}
    now=time.time();metrics={};failures=[]
    def component(name,read):
        metrics['infra_detail_configured{component="'+name+'"}']=1
        try:metrics.update(read());state[name]=now;success=1
        except Exception:failures.append(name);success=0
        metrics['infra_detail_collect_success{component="'+name+'"}']=success
        metrics['infra_detail_last_success_timestamp_seconds{component="'+name+'"}']=state.get(name,0)
        metrics['infra_detail_collect_timestamp_seconds{component="'+name+'"}']=now
    def services():
        result={}
        names=list(config['services'])
        require(all(name in COMMON_SERVICES+OVERLAY_SERVICES+HOME_SERVICES for name in names),'Unknown systemd unit')
        blocks=run(['/usr/bin/systemctl','show',*names,'--property='+PROPERTIES],5).decode().strip().split('\n\n')
        units={}
        for block in blocks:
            props=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
            require(props.get('Id') in names and props.get('Id') not in units and props.get('LoadState')=='loaded','Required service absent or duplicate')
            units[props['Id']]=props
        require(set(units)==set(names),'Incomplete systemd readback')
        for name,expected in config['services'].items():
            props=units[name]
            result['infra_service_active{service="'+name+'"}']=int(props.get('ActiveState')=='active')
            result['infra_service_expected_active{service="'+name+'"}']=int(expected)
            result['infra_service_restarts{service="'+name+'"}']=int(props.get('NRestarts','0'))
        return result
    component('systemd',services)
    if config['overlay']:
        for name in (['headscale','derp'] if config['overlay']['coordinator'] else ['derp']):
            def read(name=name):
                result=run(['/usr/bin/nsenter','--net=/run/netns/infra-headscale','/usr/bin/python3',str(ROOT/'collector.py'),'endpoint','--component',name],10)
                return json.loads(result)
            component(name,read)
    if config['gpu']:
        def gpu():
            require(Path('/sys/module/nvidia').is_dir() and Path('/dev/nvidiactl').exists(),'GPU driver not already running')
            executable=gpu_executable()
            return gpu_metrics(run([executable,'--query-gpu=index,utilization.gpu,memory.used,memory.total,temperature.gpu','--format=csv,noheader,nounits'],6))
        component('gpu',gpu)
    atomic(state_path,(json.dumps(state,sort_keys=True)+'\n').encode())
    text='# Owned bounded metrics; no raw labels or client identities\n'+''.join(k+' '+format(v,'.15g')+'\n' for k,v in sorted(metrics.items()))
    require(len(text)<65536,'Metrics publication exceeded 64 KiB')
    if OUTPUT.exists() or OUTPUT.is_symlink():trusted(OUTPUT)
    atomic(OUTPUT,text.encode(),0o644)
    return {'published':True,'failed_components':failures}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['inspect','install','collect','endpoint'])
    p.add_argument('--node',choices=['home','msk','fin']);p.add_argument('--review-json');p.add_argument('--source');p.add_argument('--source-sha256');p.add_argument('--component',choices=['headscale','derp'])
    a=p.parse_args();require(os.geteuid()==0,'Root required')
    if a.action=='inspect':print(json.dumps(inspect(a.node)));return
    if a.action=='install':print(json.dumps(install(a)));return
    if a.action=='endpoint':
        cfg=json.loads(trusted(ROOT/'config.json',True));require(cfg.get('owner')==OWNER and cfg['overlay'],'Unknown overlay collector')
        print(json.dumps(endpoint_metrics(a.component,cfg['overlay'])));return
    with (ROOT/'config.json').open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);print(json.dumps(collect()))

if __name__=='__main__':main()
