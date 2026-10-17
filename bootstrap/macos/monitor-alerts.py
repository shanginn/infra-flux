#!/usr/bin/env python3
"""Read private Prometheus alerts over SSH and issue local macOS notifications."""
import argparse
import copy
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

OWNER = 'infra-flux-monitor-v1'
STATE = Path.home() / 'Library/Application Support/infra-flux/monitor'
LIMIT = 4 * 1024 * 1024
REMOTE = r'''
import base64,hashlib,ipaddress,json,os,stat,subprocess,sys,urllib.request
uid,wanted_ca=sys.argv[1:]
k=['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=8s']
def call(args,input=None,limit=65536):
 p=subprocess.Popen(args,stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
 try:
  if input is not None:p.stdin.write(input);p.stdin.close()
  # Each command has a short kubectl timeout. The outer SSH process also has a deadline.
  out=p.stdout.read(limit+1)
  if len(out)>limit:p.kill();raise ValueError('response_limit')
  if p.wait(timeout=10):raise RuntimeError('remote_command')
  return out
 finally:
  if p.poll() is None:p.kill()
  p.wait()
def fingerprint(pem):
 return hashlib.sha256(call(['/usr/bin/openssl','x509','-outform','DER'],pem)).hexdigest()
def validate_endpoint(pods,node,pod_cidr):
 candidates=[]
 for p in pods.get('items',[]):
  meta=p.get('metadata',{});spec=p.get('spec',{});status=p.get('status',{})
  if meta.get('namespace')!='monitoring' or meta.get('labels',{}).get('app')!='prometheus' or spec.get('nodeName')!=node:continue
  if meta.get('deletionTimestamp') or status.get('phase')!='Running' or not any(c.get('type')=='Ready' and c.get('status')=='True' for c in status.get('conditions',[])):continue
  if not any(o.get('kind')=='StatefulSet' and o.get('name')=='prometheus' and o.get('controller') is True for o in meta.get('ownerReferences',[])):continue
  candidates.append(p)
 if len(candidates)!=1:raise ValueError('no_unique_local_prometheus')
 ip=ipaddress.ip_address(candidates[0]['status']['podIP']);network=ipaddress.ip_network(pod_cidr,strict=True)
 if ip.version!=4 or not network.is_private or ip not in network:raise ValueError('pod_outside_configured_cidr')
 return str(ip)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None
try:
 for path,private in [('/etc/kubernetes/pki/ca.crt',False),('/etc/kubernetes/admin.conf',True)]:
  st=os.lstat(path)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & (0o077 if private else 0o022):raise ValueError('unowned_kubernetes_identity')
 if fingerprint(open('/etc/kubernetes/pki/ca.crt','rb').read(65536))!=wanted_ca:raise ValueError('ca_mismatch')
 embedded=call(k+['config','view','--minify','--raw','-o=jsonpath={.clusters[0].cluster.certificate-authority-data}'])
 if fingerprint(base64.b64decode(embedded,validate=True))!=wanted_ca:raise ValueError('kubeconfig_ca_mismatch')
 actual=call(k+['get','namespace','kube-system','-o=jsonpath={.metadata.uid}']).decode()
 if actual!=uid:raise ValueError('cluster_uid_mismatch')
 # kubeadm nodeName can differ from the OS hostname. Bind it to this host's
 # real VPN interface instead of guessing from the SSH alias or hostname.
 interfaces=json.loads(call(['ip','-j','address','show','tailscale0']))
 local_ips={a['local'] for interface in interfaces for a in interface.get('addr_info',[]) if a.get('family')=='inet'}
 nodes=json.loads(call(k+['get','nodes','-o','json'],limit=262144))['items']
 matches=[n for n in nodes if 'node-role.kubernetes.io/control-plane' in n.get('metadata',{}).get('labels',{}) and any(a.get('type')=='InternalIP' and a.get('address') in local_ips for a in n.get('status',{}).get('addresses',[]))]
 if len(matches)!=1:raise ValueError('no_unique_local_control_plane')
 node=matches[0]['metadata']['name']
 pod_cidr=call(k+['get','configmap','unified-network','-n','flux-system','-o=jsonpath={.data.POD_CIDR}']).decode()
 pods=json.loads(call(k+['get','pods','-n','monitoring','-l','app=prometheus','--field-selector','spec.nodeName='+node,'-o','json'],limit=262144))
 ip=validate_endpoint(pods,node,pod_cidr)
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open('http://'+ip+':9090/api/v1/alerts',timeout=8) as response:
  if response.status!=200:raise ValueError('unexpected_http_status')
  payload=response.read(4194305)
 if len(payload)>4194304:raise ValueError('response_limit')
 sys.stdout.buffer.write(payload)
except Exception as e:
 print(json.dumps({'status':'error','errorType':type(e).__name__}),flush=True)
 sys.exit(1)
'''


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def validate_config(cfg):
    require(cfg.get('owner', OWNER) == OWNER, 'Unowned monitor configuration')
    aliases = cfg.get('ssh_aliases')
    require(isinstance(aliases, list) and 1 <= len(aliases) <= 2 and len(set(aliases)) == len(aliases), 'One or two distinct SSH aliases required')
    require(all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', x) for x in aliases), 'Unsafe SSH alias')
    require(bool(re.fullmatch(r'[0-9a-f-]{36}', cfg.get('cluster_uid', ''))), 'Expected kube-system UID required')
    require(bool(re.fullmatch(r'[0-9a-f]{64}', cfg.get('ca_sha256', ''))), 'Expected DER CA SHA256 required')
    return cfg


def private_file(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_mode & 0o077 == 0, 'Unowned or non-private local file')


def atomic_json(path, value):
    temporary = path.with_name('.' + path.name + '.new')
    require(not temporary.is_symlink() and not path.is_symlink(), 'Refusing symlink state')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def bounded_run(argv, timeout, max_stdout=LIMIT):
    """Bound both elapsed time and captured bytes; never print remote stderr."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Command deadline')
            for key, _ in selector.select(min(remaining, 1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > (max_stdout if key.data == 'stdout' else 65536):
                    raise ValueError('Command response limit')
        code = process.wait(timeout=max(.01, deadline - time.monotonic()))
        if code:
            raise RuntimeError('Command failed')
        return bytes(output['stdout'])
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        process.stderr.close()


def alerts_from_payload(payload):
    require(len(payload) <= LIMIT, 'Alert response limit')
    response = json.loads(payload)
    require(isinstance(response, dict) and response.get('status') == 'success', 'Invalid Prometheus response')
    alerts = response.get('data', {}).get('alerts')
    require(isinstance(alerts, list), 'Missing alerts list')
    observed = {}
    for alert in alerts:
        require(isinstance(alert, dict), 'Malformed alert')
        labels, annotations = alert.get('labels', {}), alert.get('annotations', {})
        require(isinstance(labels, dict) and isinstance(annotations, dict), 'Malformed alert labels')
        require(all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()), 'Invalid label value')
        if alert.get('state') != 'firing' or labels.get('severity') not in ('warning', 'critical'):
            continue
        labels = {k: v for k, v in labels.items() if k not in ('replica', 'prometheus_replica')}
        require(labels.get('alertname'), 'Missing alertname')
        identity = alert_identity(labels)
        summary = annotations.get('summary', labels['alertname'])
        require(isinstance(summary, str), 'Invalid alert summary')
        # Descriptions can interpolate a changing metric value. Identity and summary
        # changes matter; fluctuating values/activeAt do not cause repeated notices.
        observed[identity] = {'labels': labels, 'summary': summary[:1000]}
    return observed


def alert_identity(labels):
    return hashlib.sha256(json.dumps(labels, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def transition(old, observed):
    previous = old.get('alerts', {})
    started = [v for key, v in observed.items() if key not in previous]
    changed = [v for key, v in observed.items() if key in previous and v != previous[key]]
    resolved = [v for key, v in previous.items() if key not in observed]
    events = []
    for kind, values in [('firing', started), ('changed', changed), ('resolved', resolved)]:
        if values:
            events.append({'kind': kind, 'alerts': values})
    if old.get('unavailable_notified'):
        events.append({'kind': 'monitor_recovered', 'active_count': len(observed)})
    return events


def failure_transition(old):
    failures = old.get('consecutive_failures', 0) + 1
    events = []
    if failures >= 3 and not old.get('unavailable_notified'):
        events.append({'kind': 'monitor_unavailable'})
    return failures, events


def event_body(event):
    kind = event['kind']
    if kind == 'monitor_unavailable':
        return 'Три последовательных опроса не дали проверенных данных через VPS. Состояние кластера неизвестно; это не подтверждение его отказа.'
    if kind == 'monitor_recovered':
        return f"Связь с мониторингом восстановлена. Активных предупреждений и аварий: {event['active_count']}."
    title = {'firing': 'Новые события', 'changed': 'События изменились', 'resolved': 'События завершились'}[kind]
    alerts = sorted(event['alerts'], key=lambda x: (x['labels'].get('severity') != 'critical', x['labels']['alertname']))
    lines = [f'{title}: {len(alerts)}.']
    for alert in alerts[:4]:
        site = alert['labels'].get('node') or alert['labels'].get('instance', '')
        lines.append(f"{alert['labels']['severity']} {alert['labels']['alertname']} {site}: {alert['summary']}")
    if len(alerts) > 4:
        lines.append('Полный список в локальном status.json и Prometheus.')
    return '\n'.join(lines)[:1400]


def notify(event):
    script = 'on run argv\n display notification (item 2 of argv) with title (item 1 of argv)\nend run'
    body = ''.join(c for c in event_body(event) if c >= ' ' or c == '\n')
    bounded_run(['/usr/bin/osascript', '-e', script, 'Kubernetes · infra-flux', body], 8, 65536)


def poll(cfg):
    errors = {}
    for alias in cfg['ssh_aliases']:
        try:
            command = shlex.join(['python3', '-c', REMOTE, cfg['cluster_uid'], cfg['ca_sha256']])
            payload = bounded_run(['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', '-o', 'StrictHostKeyChecking=yes', alias, command], 23)
            return alerts_from_payload(payload), alias, errors
        except Exception as error:
            errors[alias] = type(error).__name__
    raise PollUnavailable(errors)


class PollUnavailable(Exception):
    def __init__(self, errors):
        self.errors = errors


def run_once(cfg, state_dir, dry_run=False):
    old = {'owner': OWNER, 'alerts': {}, 'consecutive_failures': 0, 'unavailable_notified': False}
    path = state_dir / 'status.json'
    if path.exists():
        private_file(path)
        old = json.loads(path.read_text())
        require(old.get('owner') == OWNER, 'Unowned monitor state')
    new = copy.deepcopy(old)
    new.update(last_attempt=utc(), notification_error=None)
    try:
        observed, source, errors = poll(cfg)
        events = transition(old, observed)
        new.update(ok=True, last_success=utc(), source=source, endpoint_errors=errors, consecutive_failures=0, observed_alert_count=len(observed))
        next_alerts = observed
    except PollUnavailable as error:
        failures, events = failure_transition(old)
        new.update(ok=False, consecutive_failures=failures, endpoint_errors=error.errors)
        next_alerts = old.get('alerts', {})
    if dry_run:
        print(json.dumps({'ok': new['ok'], 'dry_run': True, 'active_count': new.get('observed_alert_count'), 'events': [e['kind'] for e in events], 'source': new.get('source'), 'endpoint_errors': new['endpoint_errors']}))
        return 0 if new['ok'] else 1
    # Persist each accepted group so an error in a later group does not repeat it.
    # Focus/notification settings can still hide accepted notifications.
    delivered = True
    for event in events:
        try:
            notify(event)
            new['last_notification_accepted'] = utc()
            if event['kind'] in ('firing', 'changed'):
                for alert in event['alerts']:
                    new['alerts'][alert_identity(alert['labels'])] = alert
            elif event['kind'] == 'resolved':
                for alert in event['alerts']:
                    new['alerts'].pop(alert_identity(alert['labels']), None)
            elif event['kind'] == 'monitor_unavailable':
                new['unavailable_notified'] = True
            elif event['kind'] == 'monitor_recovered':
                new['unavailable_notified'] = False
            atomic_json(path, new)
        except Exception as error:
            new['notification_error'] = type(error).__name__
            delivered = False
            break
    if delivered:
        new['alerts'] = next_alerts
        if new['ok']:
            new['unavailable_notified'] = False
        elif any(e['kind'] == 'monitor_unavailable' for e in events):
            new['unavailable_notified'] = True
    atomic_json(path, new)
    print(json.dumps({'ok': new['ok'], 'active_count': new.get('observed_alert_count'), 'notification_accepted': delivered, 'source': new.get('source')}))
    return 0 if new['ok'] and delivered else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=STATE / 'config.json')
    parser.add_argument('--state-dir', type=Path, default=STATE)
    parser.add_argument('--dry-run', action='store_true', help='Read live alerts without notifications or state writes')
    args = parser.parse_args()
    require(sys.platform == 'darwin' and os.geteuid() != 0, 'Run as logged-in macOS user')
    private_file(args.config)
    cfg = validate_config(json.loads(args.config.read_text()))
    if args.dry_run:
        return run_once(cfg, args.state_dir, True)
    os.umask(0o077)
    require(not args.state_dir.is_symlink(), 'Refusing symlink state directory')
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = args.state_dir.stat()
    require(st.st_uid == os.getuid(), 'Unowned state directory')
    os.chmod(args.state_dir, 0o700)
    lockpath = args.state_dir / 'poll.lock'
    require(not lockpath.is_symlink(), 'Refusing symlink lock')
    with open(lockpath, 'a') as lock:
        os.chmod(lockpath, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        return run_once(cfg, args.state_dir)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'Monitor failed ({type(error).__name__}); no healthy-state assertion', file=sys.stderr)
        sys.exit(1)
