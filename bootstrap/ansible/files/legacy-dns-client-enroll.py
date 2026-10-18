#!/usr/bin/env python3
"""One owned legacy-client enrollment, with a durable rollback deadline.

JSON stdin; stage/start/register/confirm are deliberately separate. The timer
uses the rollback subcommand. No coordinator mutations or network restoration.
"""
import datetime
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import urllib.parse

OWNER = 'infra-flux/legacy-dns-client-enroll'
PREPARE_SHA = '15b60be45505e82a0b54cf2997ac1ea3498463466f3c82ed6d2b79fdb7a5b7dc'
DIRECTORY = Path('/etc/infra-flux/legacy-dns-enroll')
HELPER = DIRECTORY / 'legacy-dns-client-enroll.py'
PREPARE = DIRECTORY / 'legacy-dns-client-prepare.py'
RECORD = DIRECTORY / 'operation.json'
CONFIG = Path('/etc/infra-flux/legacy-dns-client.json')
DROP = Path('/etc/systemd/system/tailscaled.service.d/50-infra-enrollment.conf')
UNIT = 'infra-legacy-dns-enroll-rollback'
UNIT_DIR = Path('/etc/systemd/system')
RUNTIME = Path('/run/infra-legacy-dns-enroll')
KEY = RUNTIME / 'registration-key'
HOSTS = Path('/etc/hosts')
PROC = Path('/proc')
EXEC = ('/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state '
        '--socket=/run/tailscale/tailscaled.sock --port=${PORT} $FLAGS '
        '--config=' + str(CONFIG))
DROP_TEXT = '# Managed by ' + OWNER + '.\n[Service]\nExecStart=\nExecStart=' + EXEC + '\n'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_prepare():
    s = PREPARE.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
            'Unsafe preparation helper')
    require(sha(PREPARE.read_bytes()) == PREPARE_SHA, 'Preparation helper changed')
    spec = importlib.util.spec_from_file_location('legacy_prepare', PREPARE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic(path, data, mode=0o600, gid=0):
    require(not path.is_symlink(), 'Refuse symlink destination')
    p.secure_directory(path.parent)
    fd, name = tempfile.mkstemp(prefix='.enroll-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            os.fchown(f.fileno(), 0, gid)
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        p.sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(record):
    atomic(RECORD, (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())


def read_record(operation):
    p.secure_regular(RECORD, private=True)
    record = json.loads(RECORD.read_text())
    require(record.get('managed_by') == OWNER and record.get('format') == 1 and
            record.get('operation') == operation, 'Wrong enrollment operation')
    require(record['helper_sha256'] == sha(HELPER.read_bytes()), 'Enrollment helper changed')
    require(record['prepare_receipt_sha256'] == sha(p.STATE.read_bytes()), 'Preparation receipt changed')
    require(record['guard']['machine_id_sha256'] == sha(Path('/etc/machine-id').read_bytes()),
            'Operation belongs to another machine')
    return record


def guard(baseline):
    # K3s veths, completed Jobs and generated firewall chain order are volatile.
    # Preserve the actual administration path and established service processes.
    return {**{key: baseline[key] for key in ('machine_id_sha256', 'boot_id', 'os', 'arch',
            'services', 'hosts', 'resolver', 'other_packages_sha256')},
            'admin_address': baseline['network']['admin_address'],
            'admin_route': baseline['network']['admin_route']}


def baseline_for(record):
    return p.baseline(record['guard']['admin_address'])


def assert_protected(record, baseline):
    expected = dict(record['guard'])
    expected['hosts'] = record.get('hosts_after_identity', expected['hosts'])
    require(guard(baseline) == expected, 'Protected host/service/admin-route/DNS identity changed')


def package_identity():
    require(p.tailscale_package() == 'ii \t' + p.VERSION, 'Package identity changed')
    for path, digest in p.INSTALLED_HASHES.items():
        p.secure_regular(Path(path))
        require(sha(Path(path).read_bytes()) == digest, 'Installed binary/unit/defaults changed')


def no_network_remnants(baseline):
    addresses = baseline['network']['addresses']['value']
    require(not any(item['ifname'].startswith('tailscale') for item in addresses), 'Client interface already exists')
    for family in ('-4', '-6'):
        for kind in ('rules', 'routes'):
            value = baseline['network'][family + kind]['value'] or []
            require(not any(str(item.get('table')) == '52' for item in value), 'Client routing table already used')
    no_firewall_remnants()


def no_firewall_remnants():
    for binary in ('iptables-save', 'ip6tables-save'):
        raw = p.output([binary])
        require(not re.search(r'(^:ts-|^-A ts-| -[jg] ts-)', raw, re.M), 'Client firewall remnants exist')
    if shutil.which('nft'):
        require('tailscale' not in p.output(['nft', 'list', 'tables']).lower(), 'Client nftables remnants exist')


def config_for(settings):
    url = urllib.parse.urlsplit(settings['server_url'])
    require(url.scheme == 'https' and url.hostname and url.port in (None, 443) and
            not url.username and not url.password and not url.query and not url.fragment and
            url.path in ('', '/'), 'Require a plain HTTPS coordinator origin')
    require(url.hostname != 'tailscale.com' and not url.hostname.endswith('.tailscale.com'),
            'A self-hosted coordinator is required')
    require(re.fullmatch(r'legacy-[a-z0-9][a-z0-9-]{0,47}', settings['hostname']), 'Invalid legacy hostname')
    return {'version': 'alpha0', 'locked': False, 'serverURL': settings['server_url'],
            'enabled': True, 'hostname': settings['hostname'], 'acceptDNS': False,
            'acceptRoutes': False, 'advertiseRoutes': [], 'advertiseExitNode': False,
            'exitNode': '', 'netfilterMode': 'off', 'runSSHServer': False,
            'runWebClient': False, 'remoteConfig': False, 'operatorUser': '',
            'appConnector': {'advertise': False}, 'autoUpdate': {'check': False, 'apply': False}}


def hosts_append(before, hostname, address):
    ip = ipaddress.ip_address(address)
    require(ip.is_global and ip.version == 4, 'Relay must be a public IPv4 literal')
    require(before.endswith(b'\n') and b'\x00' not in before, 'Hosts file must end in newline')
    for line in before.decode().splitlines():
        require(hostname.lower() not in [x.lower() for x in line.split('#', 1)[0].split()[1:]],
                'Coordinator already has a hosts entry')
    line = f'{ip} {hostname} # infra-flux legacy-dns coordinator relay\n'.encode()
    return before + line, line


def hosts_remove(current, line):
    require(current.splitlines(keepends=True).count(line) == 1, 'Owned relay line missing or duplicated')
    return b''.join(x for x in current.splitlines(keepends=True) if x != line)


def unit_contents(record):
    service = ('[Unit]\nDescription=Rollback unconfirmed legacy DNS enrollment\n'
               '[Service]\nType=oneshot\nUMask=0077\nExecStart=/usr/bin/python3 ' + str(HELPER) +
               ' rollback ' + record['operation'] + '\n')
    deadline = datetime.datetime.fromtimestamp(record['deadline'], datetime.timezone.utc)
    timer = ('[Unit]\nDescription=Deadline for legacy DNS enrollment\n[Timer]\nOnCalendar=' +
             deadline.strftime('%Y-%m-%d %H:%M:%S UTC') + '\nPersistent=true\nAccuracySec=1s\n'
             'RandomizedDelaySec=0\nUnit=' + UNIT + '.service\n[Install]\nWantedBy=timers.target\n')
    return {UNIT_DIR / (UNIT + '.service'): service.encode(), UNIT_DIR / (UNIT + '.timer'): timer.encode()}


def assert_files(record, allow_gate):
    package_identity()
    p.secure_regular(CONFIG, private=True)
    require(CONFIG.read_bytes() == record['config'].encode(), 'Startup configuration changed')
    p.secure_regular(DROP)
    require(DROP.read_text() == DROP_TEXT, 'Enrollment drop-in changed')
    allowed = [DROP.name]
    if allow_gate:
        p.secure_regular(p.DROP)
        require(p.DROP.read_text() == p.DROP_CONTENT, 'Preparation gate changed')
        allowed.append(p.DROP.name)
    require(sorted(x.name for x in DROP.parent.iterdir()) == sorted(allowed), 'Unexpected service drop-in')
    require(not os.path.lexists(p.APPROVAL), 'Unexpected startup approval marker')
    # Reject overrides in any search path, including type-wide drop-ins.
    for directory in map(Path, p.output(['systemd-analyze', 'unit-paths']).splitlines()):
        for name in ('service.d', 'tailscaled.service.d'):
            candidate = directory / name
            if os.path.lexists(candidate):
                require(candidate == DROP.parent, 'Foreign service override')
        candidate = directory / 'tailscaled.service'
        if os.path.lexists(candidate):
            require(candidate.resolve() == Path('/lib/systemd/system/tailscaled.service').resolve(), 'Foreign service unit')
    effective = p.output(['systemctl', 'show', 'tailscaled.service', '--property=DropInPaths', '--value']).split()
    require(sorted(effective) == sorted(str(DROP.parent / name) for name in allowed), 'Effective drop-ins differ')
    start = p.output(['systemctl', 'show', 'tailscaled.service', '--property=ExecStart', '--value'])
    require('path=/usr/sbin/tailscaled' in start and '--config=' + str(CONFIG) in start,
            'Effective startup command differs')
    for path, data in unit_contents(record).items():
        p.secure_regular(path)
        require(path.read_bytes() == data, 'Rollback unit changed')
        require(p.output(['systemctl', 'show', path.name, '--property=FragmentPath', '--value']).strip()
                == str(path), 'Rollback unit shadowed')
        require(not p.output(['systemctl', 'show', path.name, '--property=DropInPaths', '--value']).strip(),
                'Rollback unit has overrides')


def timer_armed(record, minimum=0):
    require(time.time() + minimum < record['deadline'], 'Enrollment deadline expired or too near')
    require(p.output(['systemctl', 'is-active', UNIT + '.timer']).strip() == 'active', 'Rollback timer inactive')
    require(p.output(['systemctl', 'is-enabled', UNIT + '.timer']).strip() == 'enabled', 'Rollback timer not persistent')


def _daemon_owned_once(record, allow_inactive=False):
    service = p.service('tailscaled.service')
    pid = service['MainPID']
    if pid == '0' and allow_inactive:
        require(service['ActiveState'] in ('inactive', 'failed') or
                (service['ActiveState'], service['SubState']) == ('activating', 'auto-restart'),
                'Unexpected inactive client state')
        return service
    starting_owned = allow_inactive and (service['ActiveState'], service['SubState']) == ('activating', 'start')
    require((service['ActiveState'] == 'active' or starting_owned) and pid.isdigit() and int(pid) > 1,
            'Client is not active')
    proc = PROC / pid
    require(Path(os.readlink(proc / 'exe')).resolve() == Path('/usr/sbin/tailscaled').resolve(),
            'Client process executable differs')
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    require(b'--config=' + str(CONFIG).encode() in argv and
            b'--state=/var/lib/tailscale/tailscaled.state' in argv and
            b'--socket=/run/tailscale/tailscaled.sock' in argv, 'Client process configuration differs')
    return service


def daemon_owned(record, allow_inactive=False):
    for attempt in range(3):
        try:
            return _daemon_owned_once(record, allow_inactive)
        except (FileNotFoundError, ProcessLookupError):
            # A restart may replace MainPID between systemctl and /proc reads.
            # Rollback has already restored the gate; never retry a mismatch.
            if not allow_inactive or attempt == 2:
                raise
            time.sleep(0.05)


def client_check(record, state):
    # systemd readiness precedes the local backend transition. Bound the wait;
    # do not retry authentication or tolerate a different settled identity.
    deadline = time.monotonic() + 20
    while True:
        status = json.loads(p.output(['/usr/bin/tailscale', 'status', '--json'], allowed=(0, 1), timeout=5))
        if status.get('BackendState') == state:
            break
        require(status.get('BackendState') in ('Starting', 'NoState') and time.monotonic() < deadline,
                'Unexpected client login state')
        time.sleep(0.25)
    require(status.get('BackendState') == state, 'Unexpected client login state')
    prefs = json.loads(p.output(['/usr/bin/tailscale', 'debug', 'prefs']))
    expected = {'ControlURL': record['server_url'], 'Hostname': record['hostname'],
                'CorpDNS': False, 'RouteAll': False, 'NetfilterMode': 0,
                'RunSSH': False, 'RunWebClient': False, 'RemoteConfig': False,
                'WantRunning': True}
    require(all(prefs.get(key) == value for key, value in expected.items()), 'Unsafe client preferences')
    require(not prefs.get('OperatorUser') and not prefs.get('AdvertiseRoutes') and not prefs.get('AdvertiseTags') and
            not prefs.get('ExitNodeID') and prefs.get('ExitNodeIP') in (None, '', 'invalid IP') and
            not prefs.get('AppConnector', {}).get('Advertise', False), 'Unexpected routing or tag preferences')
    no_firewall_remnants()
    if state == 'NeedsLogin':
        require(not status.get('TailscaleIPs'), 'Unregistered client has assigned addresses')
        return {'state': state}
    own = status.get('Self') or {}
    node = {key: own.get(key) for key in ('ID', 'PublicKey', 'TailscaleIPs', 'Tags')}
    require(node['ID'] and node['PublicKey'] and node['TailscaleIPs'], 'Incomplete registered identity')
    node['TailscaleIPs'] = sorted(node['TailscaleIPs'])
    node['Tags'] = sorted(node['Tags'] or [])
    return node


def inspect(settings):
    baseline = p.baseline(settings['admin_address'])
    return {'changed': False, 'guard': guard(baseline), 'baseline': baseline,
            'prepare_receipt_sha256': sha(p.STATE.read_bytes()),
            'operation_exists': RECORD.exists()}


def stage(settings):
    require(not os.path.lexists(RECORD), 'An operation already exists; inspect, never replace')
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{7,47}', settings['operation']), 'Invalid operation ID')
    require(type(settings['rollback_seconds']) is int and 300 <= settings['rollback_seconds'] <= 1800,
            'Rollback deadline must be 300..1800 seconds')
    prepare = p.read_state()
    require(prepare['phase'] == 'verified', 'Preparation is not verified')
    require(sha(p.STATE.read_bytes()) == settings['prepare_receipt_sha256'], 'Preparation receipt changed')
    p.verify_prepared()
    for path in (HELPER, PREPARE):
        with path.open('rb') as source:
            os.fsync(source.fileno())
    p.sync_directory(DIRECTORY)
    p.sync_directory(DIRECTORY.parent)
    baseline = p.baseline(settings['admin_address'])
    require(guard(baseline) == settings['expected_guard'], 'Reviewed protected baseline changed')
    require(baseline['machine_id_sha256'] == prepare['baseline']['machine_id_sha256'], 'Preparation machine mismatch')
    no_network_remnants(baseline)
    config = config_for(settings)
    p.paths_absent((CONFIG, DROP, RUNTIME, UNIT_DIR / (UNIT + '.timer'), UNIT_DIR / (UNIT + '.service')))
    for suffix in ('.timer', '.service'):
        require(p.output(['systemctl', 'show', UNIT + suffix, '--property=LoadState', '--value']).strip()
                == 'not-found', 'Rollback unit already exists')
    require(re.fullmatch(r'[0-9a-f]{64}', settings['coordinator_evidence_sha256']), 'Require reviewed coordinator proof')
    record = {'managed_by': OWNER, 'format': 1, 'operation': settings['operation'], 'phase': 'stage-intent',
              'helper_sha256': sha(HELPER.read_bytes()), 'prepare_receipt_sha256': sha(p.STATE.read_bytes()),
              'guard': guard(baseline), 'baseline': baseline, 'server_url': settings['server_url'],
              'hostname': settings['hostname'], 'deadline': int(time.time()) + settings['rollback_seconds'],
              'config': json.dumps(config, sort_keys=True, indent=2) + '\n',
              'coordinator_evidence_sha256': settings['coordinator_evidence_sha256']}
    if settings.get('relay_ipv4'):
        p.secure_regular(HOSTS)
        after, line = hosts_append(HOSTS.read_bytes(), urllib.parse.urlsplit(settings['server_url']).hostname,
                                   settings['relay_ipv4'])
        record['hosts_line'] = line.decode()
        record['hosts_after_sha256'] = sha(after)
    save(record)  # A partial stage is not automatically retried.
    atomic(CONFIG, record['config'].encode())
    atomic(DROP, DROP_TEXT.encode(), 0o644)
    for path, data in unit_contents(record).items():
        atomic(path, data, 0o644)
    p.output(['systemctl', 'daemon-reload'])
    assert_files(record, allow_gate=True)
    p.inactive_never_started()
    p.output(['systemctl', 'enable', '--now', UNIT + '.timer'])
    timer_armed(record, 120)
    if record.get('hosts_line'):
        require(p.file_identity(HOSTS) == record['guard']['hosts'], 'Hosts changed before relay append')
        atomic(HOSTS, after, record['guard']['hosts']['mode'], record['guard']['hosts']['gid'])
        record['hosts_after_identity'] = p.file_identity(HOSTS)
        save(record)
    assert_protected(record, baseline_for(record))
    record['phase'] = 'staged'; save(record)
    return {'changed': True, 'phase': record['phase'], 'operation': record['operation'], 'deadline': record['deadline']}


def start(record, settings):
    require(record['phase'] == 'staged', 'First start is single-use')
    assert_files(record, allow_gate=True)
    timer_armed(record, 120)
    p.inactive_never_started()
    require(p.service('tailscaled.service')['UnitFileState'] == 'disabled', 'Client already enabled')
    current = baseline_for(record)
    assert_protected(record, current)
    no_network_remnants(current)
    record['phase'] = 'start-intent'; save(record)
    p.DROP.unlink(); p.sync_directory(p.DROP.parent)
    p.output(['systemctl', 'daemon-reload'])
    assert_files(record, allow_gate=False)
    timer_armed(record, 100)
    p.output(['systemctl', 'start', 'tailscaled.service'], timeout=45)
    daemon_owned(record)
    client_check(record, 'NeedsLogin')
    require(p.service('tailscaled.service')['UnitFileState'] == 'disabled', 'Client enabled before confirmation')
    assert_protected(record, baseline_for(record))
    record['phase'] = 'needs-login'; save(record)
    return {'changed': True, 'phase': record['phase'], 'operation': record['operation']}


def up_arguments(record):
    return ['/usr/bin/tailscale', 'up', '--login-server=' + record['server_url'],
            '--auth-key=file:' + str(KEY), '--netfilter-mode=off', '--accept-dns=false',
            '--accept-routes=false', '--ssh=false', '--advertise-routes=',
            '--advertise-exit-node=false', '--advertise-connector=false', '--exit-node=',
            '--hostname=' + record['hostname'], '--timeout=90s']


def register(record, settings):
    require(record['phase'] == 'needs-login', 'Registration is single-use; inspect an uncertain result')
    assert_files(record, allow_gate=False)
    timer_armed(record, 120)
    daemon_owned(record)
    require(p.service('tailscaled.service')['UnitFileState'] == 'disabled', 'Client enabled before confirmation')
    client_check(record, 'NeedsLogin')
    assert_protected(record, baseline_for(record))
    key = settings.get('auth_key', '')
    require(isinstance(key, str) and 20 <= len(key) <= 512 and not any(c.isspace() for c in key), 'Invalid registration key')
    require(not os.path.lexists(RUNTIME), 'Registration runtime path already exists')
    RUNTIME.mkdir(mode=0o700)
    record['phase'] = 'register-intent'; save(record)
    try:
        atomic(KEY, key.encode())
        p.output(up_arguments(record), timeout=100)
        node = client_check(record, 'Running')
        daemon_owned(record)
        assert_protected(record, baseline_for(record))
        record['node'] = node
        record['phase'] = 'registered'; save(record)
    finally:
        if KEY.exists():
            p.secure_regular(KEY, private=True); KEY.unlink()
        RUNTIME.rmdir()
    return {'changed': True, 'phase': record['phase'], 'operation': record['operation'], 'node': record['node']}


def disarm():
    p.output(['systemctl', 'disable', '--now', UNIT + '.timer'])


def confirm(record, settings):
    require(record['phase'] == 'registered', 'Only a verified registration may be confirmed')
    assert_files(record, allow_gate=False)
    timer_armed(record, 30)
    daemon_owned(record)
    require(client_check(record, 'Running') == record['node'] == settings['expected_node'], 'Registered node identity changed')
    # Evidence comes from independent orchestration; booleans are not a substitute.
    require(re.fullmatch(r'[0-9a-f]{64}', settings['external_evidence_sha256']), 'Require independent proof digest')
    require(settings.get('key_expired') is True, 'Expire the coordinator key before confirmation')
    current = baseline_for(record)
    assert_protected(record, current)
    record['external_evidence_sha256'] = settings['external_evidence_sha256']
    record['observed_network_drift'] = {key: current[key] != record['baseline'][key] for key in ('network', 'firewall')}
    record['phase'] = 'confirm-intent'; save(record)
    p.output(['systemctl', 'enable', 'tailscaled.service'])
    require(p.service('tailscaled.service')['UnitFileState'] == 'enabled', 'Boot enable failed')
    timer_armed(record)
    record['phase'] = 'confirmed'; save(record)  # Lock makes a waiting rollback a no-op.
    disarm()
    return {'changed': True, 'phase': 'confirmed', 'operation': record['operation'],
            'observed_network_drift': record['observed_network_drift']}


def rollback(record, settings=None):
    if record['phase'] in ('confirmed', 'rolled-back'):
        return {'changed': False, 'phase': record['phase'], 'operation': record['operation']}
    # Do not require old service PIDs, boot ID, DNS or connectivity to roll back.
    # Those may be the reason rollback is needed, including a reboot.
    assert_files(record, allow_gate=p.DROP.exists())
    record['phase'] = 'rollback-intent'; save(record)
    atomic(p.DROP, p.DROP_CONTENT.encode(), 0o644)
    p.output(['systemctl', 'daemon-reload'])
    assert_files(record, allow_gate=True)
    daemon_owned(record, allow_inactive=True)
    p.output(['systemctl', 'stop', 'tailscaled.service'], timeout=45)
    p.output(['systemctl', 'disable', 'tailscaled.service'])
    service = p.service('tailscaled.service')
    require(service['MainPID'] == '0' and service['ActiveState'] in ('inactive', 'failed') and
            service['UnitFileState'] == 'disabled', 'Rollback did not stop and disable client')
    p.no_client_process()
    if KEY.exists():
        p.secure_regular(KEY, private=True); KEY.unlink()
    if RUNTIME.exists():
        p.secure_directory(RUNTIME); RUNTIME.rmdir()
    if record.get('hosts_line'):
        p.secure_regular(HOSTS)
        current = HOSTS.read_bytes()
        atomic(HOSTS, hosts_remove(current, record['hosts_line'].encode()),
               HOSTS.stat().st_mode & 0o777, HOSTS.stat().st_gid)
    current = baseline_for(record)
    no_network_remnants(current)
    record['rollback_protected_drift'] = {key: value != record['guard'][key] for key, value in guard(current).items()}
    record['phase'] = 'rolled-back'; save(record)
    disarm()
    return {'changed': True, 'phase': record['phase'], 'operation': record['operation'],
            'protected_drift': record['rollback_protected_drift'], 'state_retained': True}


def main():
    global p
    require(os.geteuid() == 0, 'Root required')
    p = load_prepare()
    p.secure_directory(DIRECTORY)
    p.secure_regular(HELPER)
    require(Path(__file__).resolve() == HELPER, 'Run the installed helper only')
    settings = ({'action': 'rollback', 'operation': sys.argv[2]} if len(sys.argv) == 3 and
                sys.argv[1] == 'rollback' else json.load(sys.stdin))
    action = settings.get('action', 'inspect')
    require(action in ('inspect', 'stage', 'start', 'register', 'confirm', 'rollback'), 'Unknown action')
    if action == 'inspect':
        return inspect(settings)
    require(action == 'rollback' or settings.get('enabled') is True, 'Explicit enable required')
    fd = os.open('/run/lock/infra-legacy-dns-enroll.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        require(os.fstat(lock.fileno()).st_uid == 0, 'Wrong lock owner')
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == 'stage':
            return stage(settings)
        record = read_record(settings['operation'])
        return globals()[action](record, settings)


if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Exception as error:
        # Never expose command stdout, authentication URLs, keys or preferences.
        print(json.dumps({'ok': False, 'error_type': type(error).__name__,
                          'message': str(error) if isinstance(error, RuntimeError) else
                          'Stopped; inspect the owned receipt and rollback timer before any retry.'}))
        sys.exit(1)
