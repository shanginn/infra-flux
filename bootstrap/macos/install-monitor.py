#!/usr/bin/env python3
"""Install the independent local alert poller and optional 60-second LaunchAgent."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('infra_monitor', SOURCE / 'monitor-alerts.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)
LABEL = 'io.shanginn.infra-flux.monitor'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--schedule', action='store_true')
    args = parser.parse_args()
    monitor.require(sys.platform == 'darwin' and os.geteuid() != 0, 'Run as logged-in macOS user')
    monitor.private_file(args.config)
    incoming = monitor.validate_config(json.loads(args.config.read_text()))
    os.umask(0o077)
    destination = monitor.STATE
    monitor.require(not destination.is_symlink(), 'Refusing symlink monitor directory')
    config = destination / 'config.json'
    if config.exists():
        monitor.private_file(config)
        existing = json.loads(config.read_text())
        monitor.require(existing.get('owner') == monitor.OWNER, 'Unowned monitor configuration')
        monitor.require(all(existing.get(k) == incoming.get(k) for k in ['cluster_uid', 'ca_sha256']), 'Cluster identity change needs explicit review; retain existing config')
    elif destination.exists():
        monitor.require(not any(destination.iterdir()), 'Refusing to adopt nonempty unowned directory')
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    monitor.require(destination.stat().st_uid == os.getuid(), 'Unowned monitor directory')
    os.chmod(destination, 0o700)
    incoming['owner'] = monitor.OWNER
    monitor.atomic_json(config, incoming)
    binary = destination / 'monitor-alerts.py'
    temporary = destination / '.monitor-alerts.py.new'
    monitor.require(not binary.is_symlink() and not temporary.is_symlink(), 'Refusing symlink executable')
    shutil.copyfile(SOURCE / 'monitor-alerts.py', temporary)
    os.chmod(temporary, 0o700)
    os.replace(temporary, binary)
    if args.schedule:
        agent = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')
        agent.parent.mkdir(parents=True, exist_ok=True)
        monitor.require(not agent.is_symlink(), 'Refusing symlink LaunchAgent')
        if agent.exists():
            old = plistlib.loads(agent.read_bytes())
            monitor.require(old.get('Label') == LABEL and str(binary) in old.get('ProgramArguments', []), 'Refusing unrelated LaunchAgent')
        plist = {'Label': LABEL, 'ProgramArguments': [sys.executable, str(binary), '--config', str(config)], 'StartInterval': 60, 'RunAtLoad': True, 'ProcessType': 'Background', 'LowPriorityIO': True, 'Nice': 10, 'EnvironmentVariables': {'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'}}
        temporary = agent.with_suffix('.plist.new')
        monitor.require(not temporary.is_symlink(), 'Refusing symlink temporary LaunchAgent')
        temporary.write_bytes(plistlib.dumps(plist))
        os.chmod(temporary, 0o600)
        os.replace(temporary, agent)
        target = f'gui/{os.getuid()}'
        subprocess.run(['/bin/launchctl', 'bootout', f'{target}/{LABEL}'], capture_output=True, check=False)
        subprocess.run(['/bin/launchctl', 'bootstrap', target, str(agent)], capture_output=True, check=True)
    print('Local monitor installed' + ('; 60-second user LaunchAgent loaded' if args.schedule else '; schedule not loaded'))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Monitor installation failed ({type(error).__name__}); no remote configuration changed', file=sys.stderr)
        sys.exit(1)
