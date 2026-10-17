#!/usr/bin/env python3
"""Install the reviewed local backup configuration and optional user launchd job."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
import sys

from backup import OWNER, STATE, PASSWORD, CONFIG, atomic_json, require, restic

LABEL = 'io.shanginn.infra-flux.backup'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path, help='Reviewed input configuration')
    parser.add_argument('--schedule', action='store_true', help='Load the daily and hourly catch-up LaunchAgent')
    args = parser.parse_args()
    require(sys.platform == 'darwin' and os.geteuid() != 0, 'Run as the logged-in macOS user')
    os.umask(0o077)
    binary = shutil.which('restic')
    require(binary, 'Install restic first; this installer does not install packages')
    version = subprocess.run([binary, 'version'], capture_output=True, check=True, text=True).stdout
    require(version.startswith('restic 0.19.1 '), 'Install the reviewed restic version 0.19.1')
    help_text = subprocess.run([binary, 'backup', '--help'], capture_output=True, check=True, text=True).stdout
    require('--stdin-from-command' in help_text, 'This restic version lacks reliable command streaming')
    incoming = json.loads(args.config.read_text())
    require(incoming['jobs'] and all(job['component'] in ('headscale', 'etcd', 'node-config') for job in incoming['jobs']),
            'Unsupported exporter')
    repo = Path(incoming['repository']).expanduser().resolve()
    require(repo != Path.home() and not repo.is_relative_to(STATE) and not STATE.is_relative_to(repo),
            'Use a dedicated repository separate from its credentials')
    require(repo.is_relative_to(Path.home()), 'Select a repository inside the user home directory')
    if CONFIG.exists():
        existing = json.loads(CONFIG.read_text())
        require(existing.get('owner') == OWNER and Path(existing['repository']) == repo, 'Unmanaged configuration or repository change')
        require(PASSWORD.is_file() and not PASSWORD.is_symlink(), 'Existing repository password is missing; do not regenerate it')
    else:
        require(not PASSWORD.exists(), 'Unowned password file exists')
        require(not repo.exists() or not any(repo.iterdir()), 'Refusing to adopt an existing repository')
    require(not STATE.is_symlink(), 'Credential directory must not be a symlink')
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    if not PASSWORD.exists():
        with PASSWORD.open('x') as handle:
            os.chmod(PASSWORD, 0o600)
            handle.write(secrets.token_urlsafe(48) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
    os.chmod(PASSWORD, 0o600)
    incoming.update(owner=OWNER, repository=str(repo), restic=binary)
    atomic_json(CONFIG, incoming)
    repo.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(repo, 0o700)
    if not (repo / 'config').exists():
        restic(incoming, ['init', '--repository-version', '2'])
    else:
        restic(incoming, ['cat', 'config'])
    destination = STATE / 'bin'
    destination.mkdir(mode=0o700, exist_ok=True)
    for name in ('backup.py', 'export-headscale.py', 'export-node.py'):
        source = Path(__file__).resolve().parent / name
        target = destination / name
        temporary = destination / ('.' + name + '.new')
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o700)
        os.replace(temporary, target)
    if args.schedule:
        agent = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')
        agent.parent.mkdir(parents=True, exist_ok=True)
        if agent.exists():
            existing_agent = plistlib.loads(agent.read_bytes())
            require(existing_agent.get('Label') == LABEL and str(destination / 'backup.py') in existing_agent.get('ProgramArguments', []),
                    'Refusing to replace an unrelated LaunchAgent')
        hour, minute = map(int, incoming.get('daily_time', '03:30').split(':'))
        plist = {
            'Label': LABEL,
            'ProgramArguments': [sys.executable, str(destination / 'backup.py'), 'run'],
            'StartCalendarInterval': {'Hour': hour, 'Minute': minute},
            'StartInterval': 3600,
            'RunAtLoad': True,
            'ProcessType': 'Background',
            'LowPriorityIO': True,
            'Nice': 10,
            'EnvironmentVariables': {'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'},
        }
        temporary = agent.with_suffix('.plist.new')
        temporary.write_bytes(plistlib.dumps(plist))
        os.chmod(temporary, 0o600)
        os.replace(temporary, agent)
        target = f'gui/{os.getuid()}'
        subprocess.run(['/bin/launchctl', 'bootout', f'{target}/{LABEL}'], capture_output=True, check=False)
        subprocess.run(['/bin/launchctl', 'bootstrap', target, str(agent)], capture_output=True, check=True)
    print('Encrypted repository configured' + ('; user backup schedule loaded' if args.schedule else '; schedule not loaded'))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Backup installation failed ({type(error).__name__}); retained existing credentials and repository', file=sys.stderr)
        sys.exit(1)
