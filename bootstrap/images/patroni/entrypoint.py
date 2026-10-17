#!/usr/bin/env python3
"""Render runtime-only identity and credentials without printing them."""
import json
import os
import pathlib
import stat
import yaml

src = pathlib.Path('/etc/patroni/patroni.yaml')
config = yaml.safe_load(src.read_text())
mode = os.environ['FENCING_MODE']
if mode not in ('watchdog', 'manual-verified-off'):
    raise SystemExit('Unrecognized fencing mode')
assert config['bootstrap']['dcs']['ttl'] == 60
assert config['bootstrap']['dcs']['loop_wait'] == 5
assert config['bootstrap']['dcs']['retry_timeout'] == 5
assert config['bootstrap']['dcs']['synchronous_mode'] is False
assert config['bootstrap']['dcs']['failsafe_mode'] is False
config['name'] = os.environ['POD_NAME']
config['kubernetes']['namespace'] = os.environ['POD_NAMESPACE']
config['kubernetes']['pod_ip'] = os.environ['POD_IP']
config['restapi']['connect_address'] = os.environ['POD_IP'] + ':8008'
config['postgresql']['connect_address'] = os.environ['POD_IP'] + ':5432'
config['tags']['failover_priority'] = int(os.environ['FAILOVER_PRIORITY'])
if mode == 'watchdog':
    assert config['watchdog'] == {'mode': 'required', 'device': '/dev/patroni-watchdog', 'safety_margin': -1}
    device = os.stat(config['watchdog']['device'])
    assert stat.S_ISCHR(device.st_mode), 'Watchdog must be a character device'
    number = f'{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}'
    found = [p.parent for p in pathlib.Path('/sys/class/watchdog').glob('*/dev') if p.read_text().strip() == number]
    assert len(found) == 1 and (found[0] / 'identity').read_text().strip() == 'Software Watchdog'
    assert os.access(config['watchdog']['device'], os.R_OK | os.W_OK)
else:
    assert config['watchdog']['mode'] == 'off'
    assert config['postgresql']['pre_promote'] == '/opt/patroni/bin/python /opt/infra/manual-promotion-gate.py'
secret = pathlib.Path('/etc/patroni-credentials')
for role, user in [('superuser', 'postgres'), ('replication', 'replicator'), ('rewind', 'rewind_user')]:
    password = (secret / (role + '-password')).read_text().rstrip('\n')
    assert len(password) >= 24
    config['postgresql']['authentication'][role].update(username=user, password=password)
api_password = (secret / 'restapi-password').read_text().rstrip('\n')
assert len(api_password) >= 24
config['restapi']['authentication'] = {'username': 'patroni', 'password': api_password}
target = pathlib.Path('/run/patroni/patroni.yaml')
target.write_text(yaml.safe_dump(config, sort_keys=False))
target.chmod(0o600)
os.execv('/opt/patroni/bin/patroni', ['patroni', str(target)])
