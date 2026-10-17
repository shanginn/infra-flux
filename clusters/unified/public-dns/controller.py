#!/usr/bin/env python3
"""Authoritative zone publisher; stdlib only, Kubernetes CAS for every write."""
import concurrent.futures
import copy
import datetime
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

CONFIG = Path(os.getenv('CONFIG', '/config/settings.json'))
ZONE = Path(os.getenv('ZONE', '/zones/apps.db'))
TOKEN_DIR = Path('/var/run/secrets/kubernetes.io/serviceaccount')
FENCE = 'infra.shanginn.io/dns-epoch'
OWNER = 'infra.shanginn.io/dns-owner'


def settings(path=CONFIG):
    cfg = json.loads(path.read_text())
    for name in (cfg['zone'], cfg['responsible']):
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name):
            raise ValueError('invalid DNS name')
    for site, addr in cfg['targets'].items():
        if not re.fullmatch(r'[a-z0-9-]+', site):
            raise ValueError('invalid target name')
        ipaddress.IPv4Address(addr)
    if len(cfg['targets']) != 2 or not 1 <= cfg['ttl'] <= 300:
        raise ValueError('expected two ingress targets and bounded TTL')
    return cfg


def config_hash(cfg):
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()


def valid_state(state, cfg):
    if not 0 < state['serial'] < 2**32:
        raise ValueError('invalid SOA serial')
    if not state['active'] or not set(state['active']) <= cfg['targets'].keys():
        raise ValueError('refuse empty/unknown address set')
    if set(state['health']) != cfg['targets'].keys():
        raise ValueError('target changes require explicit state migration')
    for health in state['health'].values():
        if type(health['up']) is not bool or not 0 <= health['streak'] <= 3:
            raise ValueError('invalid health state')
    return state


def zone_text(state, cfg):
    valid_state(state, cfg)
    zone = cfg['zone'] + '.'
    rows = [f'$ORIGIN {zone}', f'$TTL {cfg["ttl"]}',
            f'@ IN SOA ns-msk.{zone} {cfg["responsible"]}. '
            f'({state["serial"]} 30 10 86400 {cfg["ttl"]})']
    for site, addr in sorted(cfg['targets'].items()):
        rows += [f'@ IN NS ns-{site}.{zone}', f'ns-{site} IN A {addr}']
    for site in sorted(state['active']):
        rows += [f'ingress IN A {cfg["targets"][site]}', f'* IN A {cfg["targets"][site]}']
    return '\n'.join(rows) + '\n'


def next_state(state, results, cfg, now):
    state = copy.deepcopy(valid_state(state, cfg))
    for site, success in results.items():
        health = state['health'][site]
        if success == health['up']:
            health['streak'] = 0
        else:
            health['streak'] += 1
            if health['streak'] >= (2 if success else 3):
                health.update(up=success, streak=0)
    active = sorted(site for site, health in state['health'].items() if health['up'])
    state['all_down'] = not active
    if not active:
        active = state['active']  # Preserve the last nonempty RRset, never invent health.
    if active != sorted(state['active']) or state.get('settings_hash') != config_hash(cfg):
        state['serial'] = max(state['serial'] + 1, int(now))
        if state['serial'] >= 2**32:
            raise ValueError('SOA serial exhausted; operator intervention required')
    state.update(active=active, settings_hash=config_hash(cfg), last_probe=now)
    return state


def atomic_zone(text):
    ZONE.parent.mkdir(parents=True, exist_ok=True)
    if ZONE.exists() and ZONE.read_text() == text:
        return
    temporary = ZONE.with_suffix('.new')
    with temporary.open('w') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, ZONE)


class Api:
    def __init__(self):
        self.base = 'https://' + os.environ['KUBERNETES_SERVICE_HOST'] + ':' + os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')
        self.tls = ssl.create_default_context(cafile=str(TOKEN_DIR / 'ca.crt'))
        namespace = os.environ['POD_NAMESPACE']
        self.paths = {
            'zone': f'/api/v1/namespaces/{namespace}/configmaps/public-dns-zone',
            'lease': f'/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases/public-dns',
        }

    def request(self, resource, body=None):
        # Read the projected token each request so rotation needs no process restart.
        request = urllib.request.Request(self.base + self.paths[resource],
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + (TOKEN_DIR / 'token').read_text().strip(),
                     'Content-Type': 'application/json'},
            method='GET' if body is None else 'PUT')
        with urllib.request.urlopen(request, context=self.tls, timeout=3) as response:
            return json.load(response)


class Publisher:
    def __init__(self, cfg, api, identity):
        self.cfg, self.api, self.identity = cfg, api, identity
        self.observed_rv, self.observed_at = None, 0
        self.epoch, self.renewed_at = None, 0
        self.state = None
        self.metrics = {'leader': 0, 'api_errors_total': 0, 'zone_sync_timestamp_seconds': 0}
        self.loop_at = time.monotonic()

    def lease(self):
        obj = self.api.request('lease')
        spec = obj.setdefault('spec', {})
        rv, now = obj['metadata']['resourceVersion'], time.monotonic()
        if rv != self.observed_rv:
            self.observed_rv, self.observed_at = rv, now
        owner = spec.get('holderIdentity')
        # Local elapsed observation avoids reliance on synchronized wall clocks.
        expired = now - self.observed_at > max(35, spec.get('leaseDurationSeconds', 35)) + 2
        if owner and owner != self.identity and not expired:
            self.epoch = None
            self.metrics['leader'] = 0
            return False
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        if owner != self.identity:
            spec['leaseTransitions'] = spec.get('leaseTransitions', 0) + 1
            spec['acquireTime'] = stamp
        spec.update(holderIdentity=self.identity, leaseDurationSeconds=35, renewTime=stamp)
        obj = self.api.request('lease', obj)  # PUT retains resourceVersion, 409 loses election.
        self.epoch = obj['spec'].get('leaseTransitions', 0)
        self.renewed_at = time.monotonic()
        self.metrics['leader'] = 1
        return True

    def sync(self):
        obj = self.api.request('zone')
        state = valid_state(json.loads(obj['data']['state.json']), self.cfg)
        atomic_zone(zone_text(state, self.cfg))
        self.state = state
        self.metrics['zone_sync_timestamp_seconds'] = time.time()
        return obj

    def publish(self, results):
        if self.epoch is None or time.monotonic() - self.renewed_at > 15:
            raise RuntimeError('leadership renewal too old')
        lease = self.api.request('lease')['spec']
        if (lease.get('holderIdentity'), lease.get('leaseTransitions')) != (self.identity, self.epoch):
            raise RuntimeError('leadership lost')
        obj = self.api.request('zone')
        annotations = obj['metadata'].setdefault('annotations', {})
        prior_epoch = int(annotations.get(FENCE, '0'))
        if prior_epoch > self.epoch or (prior_epoch == self.epoch and annotations.get(OWNER) not in (None, self.identity)):
            raise RuntimeError('newer zone publisher fenced this process')
        state = next_state(json.loads(obj['data']['state.json']), results, self.cfg, time.time())
        annotations.update({FENCE: str(self.epoch), OWNER: self.identity})
        obj['data']['state.json'] = json.dumps(state, sort_keys=True)
        # The same CAS claims the zone epoch and updates data. An old in-flight PUT
        # cannot overwrite a newer leader's successful PUT with an older version.
        if time.monotonic() - self.renewed_at > 15:
            raise RuntimeError('leadership expired before publication')
        self.api.request('zone', obj)

    def probe(self, address):
        connection = http.client.HTTPConnection(address, 80, timeout=3)
        try:
            connection.request('GET', '/ping', headers={'Host': 'ingress.' + self.cfg['zone'], 'Connection': 'close'})
            response = connection.getresponse()
            return response.status == 200 and response.read(16).strip() == b'OK'
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()

    def metrics_text(self):
        values = dict(self.metrics)
        if self.state:
            values.update(all_targets_down=int(self.state.get('all_down', False)),
                          last_probe_timestamp_seconds=self.state.get('last_probe', 0),
                          zone_serial=self.state['serial'])
        rows = [f'infra_dns_{key} {value}' for key, value in sorted(values.items())]
        if self.state:
            for site, health in sorted(self.state['health'].items()):
                rows.append(f'infra_dns_target_healthy{{site="{site}"}} {int(health["up"])}')
        return '\n'.join(rows) + '\n'

    def run(self):
        agent = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/metrics':
                    body, status = agent.metrics_text().encode(), 200
                elif self.path == '/health':
                    status = 200 if time.monotonic() - agent.loop_at < 30 else 503
                    body = b'OK\n' if status == 200 else b'loop stalled\n'
                else:
                    body, status = b'not found\n', 404
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain; version=0.0.4')
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('0.0.0.0', 9080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        next_probe = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            while True:
                self.loop_at = time.monotonic()
                try:
                    self.sync()  # Followers continuously install the last committed zone too.
                    if self.lease() and time.monotonic() >= next_probe:
                        futures = {site: pool.submit(self.probe, addr) for site, addr in self.cfg['targets'].items()}
                        results = {site: future.result() for site, future in futures.items()}
                        self.publish(results)
                        self.sync()
                        next_probe = self.loop_at + 10
                except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as error:
                    self.metrics['api_errors_total'] += 1
                    self.metrics['leader'] = 0
                    self.epoch = None
                    print(f'zone update deferred: {type(error).__name__}', flush=True)
                time.sleep(max(0.1, 2 - (time.monotonic() - self.loop_at)))


if __name__ == '__main__':
    cfg = settings()
    if len(sys.argv) == 2 and sys.argv[1] == 'init':
        atomic_zone(zone_text(json.loads(Path('/seed/state.json').read_text()), cfg))
    else:
        Publisher(cfg, Api(), os.environ['POD_UID']).run()
