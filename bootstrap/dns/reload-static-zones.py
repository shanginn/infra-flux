#!/usr/bin/env python3
"""Guarded, single-signal reload of existing legacy BIND static zone files.

No ConfigMap, Deployment, journal or zone files are changed. Default: check only.
Guard and result JSON belong outside Git. The remote host needs only Python 3.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time

DYNAMIC = {'vibesites.ru', 'xn--80aacc0bc7ayl4g.xn--p1ai'}
CONFIG_FILES = {'named.conf', 'named.conf.acl', 'named.conf.local', 'named.conf.options'}
ZONE_CM = 'bind9-zones-ttm842m5bt'
HEX = re.compile(r'[0-9a-f]{64}')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def object_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def parse_json(data):
    require(len(data) <= 256 * 1024, 'JSON exceeds size bound')
    return json.loads(data, object_pairs_hook=unique_object)


def validate_guard(g):
    require(isinstance(g, dict) and set(g) == {
        'version', 'cluster_uid', 'deployment_uid', 'template_sha256', 'pod_name',
        'pod_uid', 'container_id', 'restarts', 'pid_start', 'configmap_uid',
        'configmap_resource_version', 'config_sha256', 'zone_sha256', 'zones'},
        'Guard keys do not match the documented schema')
    require(g['version'] == 1, 'Unsupported guard version')
    for key in ('cluster_uid', 'deployment_uid', 'pod_uid', 'configmap_uid'):
        require(isinstance(g[key], str) and re.fullmatch(r'[a-z0-9-]{1,64}', g[key]), 'Invalid object UID')
    require(isinstance(g['pod_name'], str) and LABEL.fullmatch(g['pod_name']), 'Invalid pod name')
    require(isinstance(g['container_id'], str) and re.fullmatch(r'(?:containerd|docker)://[0-9a-f]{64}', g['container_id']), 'Invalid container ID')
    require(type(g['restarts']) is int and 0 <= g['restarts'] <= 1000, 'Invalid restart count')
    for key in ('pid_start', 'configmap_resource_version'):
        require(isinstance(g[key], str) and re.fullmatch(r'[0-9]{1,32}', g[key]), 'Invalid counter')
    require(isinstance(g['template_sha256'], str) and HEX.fullmatch(g['template_sha256']), 'Invalid template hash')
    require(isinstance(g['config_sha256'], dict) and set(g['config_sha256']) == CONFIG_FILES, 'Expected four configuration hashes')
    require(isinstance(g['zone_sha256'], dict) and len(g['zone_sha256']) == 22, 'Expected all twenty-two zone file hashes')
    for hashes in (g['config_sha256'], g['zone_sha256']):
        for key, value in hashes.items():
            require(isinstance(key, str) and LABEL.fullmatch(key) and '/' not in key, 'Invalid mounted filename')
            require(isinstance(value, str) and HEX.fullmatch(value), 'Invalid file hash')
    require(isinstance(g['zones'], list) and 1 <= len(g['zones']) <= 20, 'Expected one to twenty static zones')
    names, files = set(), set()
    for z in g['zones']:
        require(isinstance(z, dict) and set(z) == {'name', 'file', 'before_serial', 'expected_serial'}, 'Invalid zone guard')
        require(isinstance(z['name'], str) and LABEL.fullmatch(z['name']) and not z['name'].endswith('.'), 'Use lower-case absolute zone without trailing dot')
        require(z['name'] not in DYNAMIC and z['file'] not in ('vibesites.ru', 'vibesites.rf'), 'Dynamic zones are unsupported')
        require(z['file'] in g['zone_sha256'], 'Target file lacks a hash')
        require(z['name'] not in names and z['file'] not in files, 'Duplicate zone or file')
        names.add(z['name']); files.add(z['file'])
        for key in ('before_serial', 'expected_serial'):
            require(type(z[key]) is int and 0 <= z[key] < 2**32, 'Invalid SOA serial')
        require(0 < (z['expected_serial'] - z['before_serial']) % 2**32 < 2**31, 'SOA serial must advance under RFC1982')
    return g


def zone_declarations(text):
    """Accept the existing explicit declarations, not arbitrary BIND syntax."""
    require('include' not in re.sub(r'//[^\n]*|/\*.*?\*/', '', text, flags=re.S), 'Nested local configuration is unsupported')
    blocks = re.findall(r'^zone "([a-z0-9.-]+)" IN \{\n(.*?)^\};', text, re.M | re.S)
    require(len(blocks) == 22 and len({name for name, _ in blocks}) == 22, 'Expected exactly twenty-two zone declarations')
    out = {}
    for name, body in blocks:
        match = re.search(r'^\s*file "([^"]+)";', body, re.M)
        require(match is not None, 'Zone lacks an explicit file')
        out[name] = {'file': match.group(1), 'static': bool(
            re.search(r'^\s*type master;', body, re.M)
            and re.search(r'allow-update\s*\{\s*none;\s*\};', body)
            and not re.search(r'update-policy|journal|inline-signing|dnssec-policy', body))}
    return out


def parse_soa(text, name):
    require('status: NOERROR,' in text, 'SOA query did not succeed')
    flags = re.findall(r'^;; flags: ([^;]+);', text, re.M)
    require(len(flags) == 1 and {'qr', 'aa'} <= set(flags[0].split()) and 'ra' not in flags[0].split(), 'SOA response is not authoritative')
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 11 and fields[0].lower() == name + '.' and fields[2:4] == ['IN', 'SOA']:
            require(all(re.fullmatch(r'[0-9]+', x) for x in fields[6:]), 'Invalid SOA numeric fields')
            rows.append(tuple(fields[4:]))
    require(len(rows) == 1, 'Expected exactly one apex SOA')
    return rows[0]


class Remote:
    def __init__(self, profile, guard):
        self.profile, self.g = profile, guard
        self.k = ['kubectl'] if profile == 'kubectl' else ['sudo', '-u', 'dev', 'minikube', 'kubectl', '--']
        self.signal_attempted = False

    def command(self, args):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('Bounded command failed; raw output suppressed') from None
        require(r.returncode == 0 and len(r.stdout) <= 4 * 1024 * 1024, 'Command failed; raw output suppressed')
        return r.stdout

    def get(self, resource, name):
        args = self.k + ['get', resource, name]
        if resource != 'namespace':
            args += ['-n', 'bind9']
        return json.loads(self.command(args + ['-o', 'json']))

    def inside(self, args):
        if self.profile == 'minikube':
            prefix = ['docker', 'exec', '-i', 'minikube', 'crictl', 'exec', '-i', self.g['container_id'].split('://')[1]]
        else:
            prefix = self.k + ['exec', '-n', 'bind9', self.g['pod_name'], '-c', 'bind9', '--']
        return self.command(prefix + args)

    def identity(self):
        g = self.g
        require(self.get('namespace', 'kube-system')['metadata']['uid'] == g['cluster_uid'], 'Cluster identity changed')
        d = self.get('deployment', 'bind9-deployment')
        require(d['metadata']['uid'] == g['deployment_uid'] and object_digest(d['spec']['template']) == g['template_sha256'], 'Deployment identity or template changed')
        require(d['spec']['replicas'] == 1 and d['status'].get('updatedReplicas') == 1 and d['status'].get('readyReplicas') == 1
                and d['status'].get('replicas') == 1 and d['status'].get('observedGeneration') == d['metadata']['generation'], 'Deployment is not stable')
        p = self.get('pod', g['pod_name'])
        require(p['metadata']['uid'] == g['pod_uid'] and not p['metadata'].get('deletionTimestamp'), 'Pod identity changed or terminating')
        cs = [c for c in p['status'].get('containerStatuses', []) if c['name'] == 'bind9']
        require(len(cs) == 1 and cs[0]['containerID'] == g['container_id'] and cs[0]['restartCount'] == g['restarts']
                and cs[0]['ready'] and 'running' in cs[0]['state'], 'Container identity or readiness changed')
        volumes = {v['name']: v for v in p['spec']['volumes']}
        require(volumes['zones-volume']['configMap']['name'] == ZONE_CM, 'Unexpected zone ConfigMap reference')
        require(self.inside(['cat', '/proc/1/comm']).strip() == 'named', 'PID1 is not named')
        # Process names containing spaces are excluded above; field22 is starttime.
        require(self.inside(['cat', '/proc/1/stat']).split()[21] == g['pid_start'], 'named process changed')
        return volumes

    def content(self, volumes):
        g = self.g
        cm = self.get('configmap', ZONE_CM)
        require(cm['metadata']['uid'] == g['configmap_uid'] and cm['metadata']['resourceVersion'] == g['configmap_resource_version'], 'Zone ConfigMap identity or revision changed')
        require({k: digest(v) for k, v in cm.get('data', {}).items()} == g['zone_sha256'] and not cm.get('binaryData'), 'Zone ConfigMap data differs')
        config = self.get('configmap', volumes['configs-volume']['configMap']['name'])
        require({k: digest(v) for k, v in config.get('data', {}).items()} == g['config_sha256'], 'Configuration ConfigMap differs')
        mounted = {}
        for filename, expected in g['config_sha256'].items():
            value = self.inside(['cat', '/etc/bind/' + filename])
            require(digest(value) == expected, 'Mounted configuration differs')
            mounted[filename] = value
        for filename, expected in g['zone_sha256'].items():
            require(digest(self.inside(['cat', '/etc/bind/zones/' + filename])) == expected, 'Projected zone data differs or is not ready')
        declarations = zone_declarations(mounted['named.conf.local'])
        require(DYNAMIC <= declarations.keys(), 'Known dynamic zones missing')
        for z in g['zones']:
            require(z['name'] in declarations and declarations[z['name']]['static']
                    and declarations[z['name']]['file'] == '/etc/bind/zones/' + z['file'], 'Target is not a matching static zone')
            check = self.inside(['named-checkzone', z['name'], '/etc/bind/zones/' + z['file']])
            require(re.search(r'loaded serial ' + str(z['expected_serial']) + r'\b', check), 'Checked file has an unexpected SOA serial')
        self.inside(['named-checkconf', '/etc/bind/named.conf'])
        return declarations

    def soas(self, names):
        return {n: parse_soa(self.inside(['dig', '@127.0.0.1', n + '.', 'SOA', '+tcp', '+norecurse',
                                        '+noall', '+comments', '+answer', '+time=2', '+tries=1']), n) for n in sorted(names)}

    def signal(self):
        require(not self.signal_attempted, 'A signal was already attempted')
        self.signal_attempted = True  # Set before dispatch, including timeout/unknown results.
        # Check process identity and all projected/config bytes in the signal's exec.
        checks = ['test "$(cat /proc/1/comm)" = named',
                  'test "$(cut -d " " -f 22 /proc/1/stat)" = ' + shlex.quote(self.g['pid_start'])]
        for folder, values in (('/etc/bind/', self.g['config_sha256']), ('/etc/bind/zones/', self.g['zone_sha256'])):
            for filename, expected in sorted(values.items()):
                checks.append('test "$(sha256sum ' + shlex.quote(folder + filename) + ' | cut -d " " -f 1)" = ' + expected)
        self.inside(['sh', '-c', ' && '.join(checks + ['kill -HUP 1'])])

    def run(self, execute):
        declarations = self.content(self.identity())
        before = self.soas(declarations)
        for z in self.g['zones']:
            require(int(before[z['name']][2]) == z['before_serial'], 'Live target serial differs from reviewed prior serial')
        self.content(self.identity())
        require(self.soas(declarations) == before, 'SOAs changed during validation; obtain a fresh guard')
        if not execute:
            return {'state': 'validated', 'signal_attempted': False, 'zone_count': len(self.g['zones'])}
        self.signal()
        deadline = time.monotonic() + 30
        while True:
            current = self.soas(z['name'] for z in self.g['zones'])
            if all(int(current[z['name']][2]) == z['expected_serial'] for z in self.g['zones']):
                break
            require(time.monotonic() < deadline, 'Post-signal serial verification timed out; do not retry signal')
            time.sleep(0.5)
        self.content(self.identity())
        after = self.soas(declarations)
        verify_after(before, after, self.g['zones'])
        return {'state': 'verified', 'signal_attempted': True, 'zone_count': len(self.g['zones']),
                'pid_start_unchanged': True, 'pod_identity_unchanged': True, 'restarts_unchanged': True,
                'non_target_soas_unchanged': True}


def verify_after(before, after, zones):
    require(before.keys() == after.keys(), 'Zone set changed')
    changed = {z['name']: z['expected_serial'] for z in zones}
    for name in before:
        if name in changed:
            require(int(after[name][2]) == changed[name], 'Target serial differs after signal')
        else:
            require(after[name] == before[name], 'Non-target SOA changed; inspect concurrent writers, do not retry signal')


def private_json(path):
    with open(path, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
                and stat.S_IMODE(st.st_mode) & 0o077 == 0 and not Path(path).is_symlink(), 'Guard must be a private owned regular file')
        return parse_json(stream.read(256 * 1024 + 1))


def remote_command(source, profile, execute):
    require(profile in ('kubectl', 'minikube'), 'Unsupported remote profile')
    # SSH invokes the account's login shell, which may be fish. POSIX shlex.quote
    # does not preserve arbitrary multiline Python across all login shells.
    # Only a fixed, single-line bootstrap and the base64 alphabet reach that shell.
    encoded = base64.b64encode(source.encode()).decode('ascii')
    command = "python3 -c 'import base64;exec(base64.b64decode(\"" + encoded + "\"))'"
    command += ' --remote --profile ' + profile
    if execute:
        command += ' --execute'
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--via', help='Existing SSH alias; no host inventory is stored here')
    parser.add_argument('--profile', choices=('kubectl', 'minikube'), required=True)
    parser.add_argument('--guard', help='Private JSON with reviewed exact identities and expected bytes')
    parser.add_argument('--output', help='New private result path outside this repository; never overwrite')
    parser.add_argument('--execute', action='store_true', help='Send one HUP after validation; default checks only')
    parser.add_argument('--remote', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.remote:
        remote = None
        try:
            guard = validate_guard(parse_json(sys.stdin.buffer.read(256 * 1024 + 1)))
            remote = Remote(args.profile, guard)
            result = remote.run(args.execute)
        except Exception as exc:
            # Only our fixed validation messages are returned; subprocess output is never printed.
            message = str(exc) if isinstance(exc, RuntimeError) else 'Unexpected validation error; details suppressed'
            result = {'state': 'failed', 'signal_attempted': bool(remote and remote.signal_attempted), 'error': message}
        print(json.dumps(result))
        return 0 if result['state'] in ('validated', 'verified') else 1
    require(args.via and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.via), 'Use an existing simple SSH alias')
    require(args.guard and args.output, '--guard and --output are required')
    guard = validate_guard(private_json(args.guard))
    output = Path(args.output).absolute()
    repo = Path(__file__).resolve().parents[2]
    require(not output.resolve().is_relative_to(repo) and not Path(args.guard).resolve().is_relative_to(repo), 'Guard and output must be outside Git')
    # Exclusive operation record prevents accidentally repeating this invocation after SSH loss.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w') as stream:
        record = {'state': 'dispatching', 'execute': args.execute, 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'guard_sha256': object_digest(guard), 'profile': args.profile, 'via': args.via}
        stream.write(json.dumps(record) + '\n'); stream.flush(); os.fsync(stream.fileno())
        command = remote_command(Path(__file__).read_text(), args.profile, args.execute)
        try:
            r = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', args.via, command],
                               input=json.dumps(guard), capture_output=True, text=True, timeout=600)
            require(r.returncode in (0, 1) and r.stdout.strip(), 'SSH outcome unknown; inspect independently, do not repeat')
            result = parse_json(r.stdout)
            require(isinstance(result, dict) and result.get('state') in ('validated', 'verified', 'failed'), 'Invalid remote result; do not repeat')
        except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
            result = {'state': 'unknown', 'signal_attempted': None, 'error': 'Remote outcome unknown; inspect independently, do not repeat'}
        record['result'] = result
        stream.seek(0); stream.truncate(); stream.write(json.dumps(record, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'state': result['state'], 'signal_attempted': result.get('signal_attempted'), 'output': str(output)}))
    return 0 if result['state'] in ('validated', 'verified') else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('Refused: ' + (str(exc) if isinstance(exc, RuntimeError) else 'invalid input or output path'), file=sys.stderr)
        sys.exit(1)
