#!/usr/bin/env python3
"""After explicit host-reset approval only. Never open any watchdog device."""
import argparse
import json
import os
import pathlib
import pwd
import grp
import stat
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--preserve-home-watchdog', action='store_true')
args = parser.parse_args()
assert os.geteuid() == 0
for lookup in (pwd.getpwuid, grp.getgrgid):
    try:lookup(19999)
    except KeyError:pass
    else:raise RuntimeError('Dedicated container UID/GID 19999 collides with an existing host account')
runtime_watchdog = subprocess.check_output(['systemctl', 'show', '--property=RuntimeWatchdogUSec', '--value'], text=True).strip()
assert runtime_watchdog in ('0', ''), 'PID 1 already has a runtime watchdog policy; review device ownership first'
if not args.preserve_home_watchdog:
    assert subprocess.run(['systemctl', 'is-active', '--quiet', 'watchdog.service']).returncode != 0
    assert subprocess.run(['systemctl', 'is-enabled', '--quiet', 'watchdog.service']).returncode != 0
boot_id = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
state = pathlib.Path('/run/infra-patroni-watchdog/prepared.json')

def devices():
    return [p for p in pathlib.Path('/sys/class/watchdog').glob('watchdog[0-9]*')]

def assert_home_preserved():
    dev = pathlib.Path('/sys/class/watchdog/watchdog0')
    assert dev.exists() and 'iTCO' in (dev / 'identity').read_text(), 'Existing home hardware watchdog0 is required'
    pid = int(subprocess.check_output(['systemctl', 'show', 'watchdog.service', '--property=MainPID', '--value']))
    assert pid > 0 and subprocess.run(['systemctl', 'is-active', '--quiet', 'watchdog.service']).returncode == 0
    hardware = os.stat('/dev/watchdog0').st_rdev
    accepted_devices = {hardware}
    # Linux watchdog_core registers the legacy misc device (10:130) for
    # watchdog0. Existing watchdog.service may hold this alias, whose rdev is
    # different from /dev/watchdog0 although both address the same driver.
    legacy = pathlib.Path('/dev/watchdog')
    if legacy.exists():
        legacy_stat = legacy.stat()
        if (stat.S_ISCHR(legacy_stat.st_mode) and
                legacy_stat.st_rdev == os.makedev(10, 130) and
                pathlib.Path('/sys/class/misc/watchdog/dev').read_text().strip() == '10:130'):
            accepted_devices.add(legacy_stat.st_rdev)
    held = False
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try:
            s = fd.stat()
            held = held or (stat.S_ISCHR(s.st_mode) and s.st_rdev in accepted_devices)
        except FileNotFoundError:
            pass
    assert held, 'Existing watchdog daemon must retain its own hardware device'

if args.preserve_home_watchdog:
    assert_home_preserved()

already_loaded = pathlib.Path('/sys/module/softdog').exists()
if already_loaded:
    # Module parameters are not exported in sysfs by Linux softdog; accept only
    # the exact module load this service recorded during this same boot.
    assert state.exists(), 'Refuse a software watchdog loaded by somebody else'
    previous = json.loads(state.read_text())
    assert previous['boot_id'] == boot_id and previous['managed_by'] == 'infra-patroni-watchdog'
else:
    assert not any((p / 'identity').read_text().strip() == 'Software Watchdog' for p in devices())
    assert not any(part.startswith('softdog.') for part in pathlib.Path('/proc/cmdline').read_text().split()), 'Kernel command-line softdog overrides require explicit review'
    modprobe_config = subprocess.check_output(['modprobe', '--showconfig'], text=True)
    for line in modprobe_config.splitlines():
        fields = line.split()
        assert not (len(fields) > 1 and fields[0] in ('options', 'install') and fields[1] == 'softdog'), 'Existing softdog options/hooks require explicit review'
    subprocess.run(['modprobe', 'softdog', 'soft_margin=30', 'soft_noboot=0', 'soft_panic=0', 'soft_active_on_boot=0', 'nowayout=0'], check=True)
    subprocess.run(['udevadm', 'settle', '--timeout=10'], check=True)
soft = [p for p in devices() if (p / 'identity').read_text().strip() == 'Software Watchdog']
assert len(soft) == 1
device = pathlib.Path('/dev') / soft[0].name
if args.preserve_home_watchdog:
    assert device.name != 'watchdog0'
    assert_home_preserved()
link = pathlib.Path('/dev/patroni-watchdog')
if link.exists() or link.is_symlink():
    assert link.is_symlink() and link.resolve() == device.resolve(), 'Refuse a foreign watchdog alias'
else:
    link.symlink_to(device)
os.chown(device, 19999, 19999)
os.chmod(device, 0o600)
state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
state.write_text(json.dumps({'managed_by': 'infra-patroni-watchdog', 'boot_id': boot_id, 'device': str(device), 'identity': 'Software Watchdog', 'timeout': 30}))
state.chmod(0o600)
print(json.dumps({'identity': 'Software Watchdog', 'device': str(device), 'opened': False, 'hardware_watchdog_preserved': args.preserve_home_watchdog}))
