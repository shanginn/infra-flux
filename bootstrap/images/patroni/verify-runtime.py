#!/usr/bin/env python3
"""Read-only checks, to run inside each started PostgreSQL pod."""
import json
import os
import pathlib
import stat
import urllib.request
import yaml

cfg = yaml.safe_load(pathlib.Path('/run/patroni/patroni.yaml').read_text())
def get(path):
    with urllib.request.urlopen('http://127.0.0.1:8008' + path, timeout=5) as r:
        return json.load(r)
status, dynamic = get('/patroni'), get('/config')
assert status['patroni']['version'] == '4.1.5'
assert status['patroni']['scope'] == 'unified-postgres'
assert status['server_version'] == 180006
for key, expected in {'ttl': 60, 'loop_wait': 5, 'retry_timeout': 5, 'synchronous_mode': False, 'failsafe_mode': False, 'check_timeline': True}.items():
    assert dynamic.get(key) == expected, 'Unexpected DCS setting: ' + key
assert not dynamic.get('pause', False), 'Paused Patroni disables watchdog guarantees'
assert not status.get('watchdog_failed', False)
proof = {'member': status['patroni']['name'], 'role': status['role'], 'patroni_version': status['patroni']['version'], 'postgres_version': status['server_version'], 'dynamic_config_matches': True}
if os.environ['FENCING_MODE'] == 'watchdog' and status['role'] == 'primary':
    device = os.stat('/dev/patroni-watchdog')
    number = f'{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}'
    matches = [p.parent for p in pathlib.Path('/sys/class/watchdog').glob('*/dev') if p.read_text().strip() == number]
    assert len(matches) == 1
    wd = matches[0]
    assert (wd / 'identity').read_text().strip() == 'Software Watchdog'
    assert int((wd / 'timeout').read_text()) == 30
    owners = []
    for proc in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            command = (proc / 'cmdline').read_bytes()
            if b'patroni' not in command:continue
            for fd in (proc / 'fd').iterdir():
                try:s = fd.stat()
                except FileNotFoundError:continue
                if stat.S_ISCHR(s.st_mode) and s.st_rdev == device.st_rdev:owners.append(int(proc.name))
        except (PermissionError, FileNotFoundError):
            continue
    assert owners, 'No Patroni process holds the watchdog device'
    proof.update(watchdog_identity='Software Watchdog', watchdog_timeout_seconds=30, watchdog_holder_pids=owners)
print(json.dumps(proof))
