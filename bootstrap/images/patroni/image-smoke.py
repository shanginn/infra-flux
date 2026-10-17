#!/usr/bin/env python3
"""Exercise this exact image in a disposable, unprivileged container.

Only /tmp is written. No Kubernetes access, watchdog device or host mounts are
needed. This proves image/runtime basics, not HA fencing or WAN fault handling.
"""
import copy
import importlib.metadata
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time

import psycopg
from psycopg import sql
import yaml


def run(argv, **kwargs):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}:\n{result.stdout[-8000:]}\n{result.stderr[-8000:]}')
    return result


def main():
    assert os.getuid() == 19999 and os.getgid() == 19999
    assert importlib.metadata.version('patroni') == '4.1.5'
    assert psycopg.__version__ == '3.3.2'
    template = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text().replace('__POD_CIDR__', '127.0.0.1/32'))
    pg = pathlib.Path('/usr/lib/postgresql/18/bin')
    assert run([str(pg / 'postgres'), '--version']).stdout.startswith('postgres (PostgreSQL) 18.6')
    with tempfile.TemporaryDirectory(prefix='patroni-image-smoke-') as temp:
        root = pathlib.Path(temp)
        data = root / 'primary'
        replica = root / 'replica'
        sock1 = root / 'socket-primary'
        sock2 = root / 'socket-replica'
        sock1.mkdir(); sock2.mkdir()
        cert, key = root / 'tls.crt', root / 'tls.key'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(key), '-out', str(cert)])
        key.chmod(0o600)
        password = secrets.token_urlsafe(32)
        pwfile = root / 'password'
        pwfile.write_text(password); pwfile.chmod(0o600)
        run([str(pg / 'initdb'), '-D', str(data), '-U', 'postgres', '--encoding=UTF8', '--data-checksums',
             '--auth-local=peer', '--auth-host=scram-sha-256', '--pwfile=' + str(pwfile)])
        config = copy.deepcopy(template)
        config.update(name='image-smoke', scope='image-smoke')
        config['watchdog'] = {'mode': 'off'}
        # Advertised addresses must be non-loopback for Patroni validation.
        # TEST-NET is used only in this unstarted config; actual SQL tests below
        # stay on loopback inside the network-less container.
        config['kubernetes'].update(namespace='image-smoke', pod_ip='192.0.2.10')
        config['restapi'].update(listen='127.0.0.1:58008', connect_address='192.0.2.10:58008')
        config['postgresql'].update(listen='127.0.0.1:55432', connect_address='192.0.2.10:55432', data_dir=str(data), pgpass=str(root / 'pgpass'))
        config['postgresql']['parameters']['unix_socket_directories'] = str(sock1)
        for role, user in [('superuser', 'postgres'), ('replication', 'replicator'), ('rewind', 'rewind_user')]:
            config['postgresql']['authentication'][role].update(username=user, password=password)
            if role != 'superuser':
                config['postgresql']['authentication'][role]['sslrootcert'] = str(cert)
        params = config['bootstrap']['dcs']['postgresql']['parameters']
        params.update(ssl_cert_file=str(cert), ssl_key_file=str(key), ssl_ca_file=str(cert))
        config_path = root / 'patroni.yaml'
        config_path.write_text(yaml.safe_dump(config)); config_path.chmod(0o600)
        run(['/opt/patroni/bin/patroni', '--validate-config', '--ignore-listen-port', str(config_path)])
        # Exercise the actual PostgreSQL settings, retaining local durability,
        # SSL/SCRAM, WAL slot bounds, and the production buffer sizes.
        actual = dict(params, listen_addresses='127.0.0.1', port=55432, unix_socket_directories=str(sock1))
        with (data / 'postgresql.conf').open('a') as output:
            for name, value in actual.items():
                output.write('\n' + name + " = '" + str(value).replace("'", "''") + "'\n")
        (data / 'pg_hba.conf').write_text('local all postgres peer\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostssl replication replicator 127.0.0.1/32 scram-sha-256\n')
        started = []
        try:
            run([str(pg / 'pg_ctl'), '-D', str(data), '-w', '-t', '30', '-l', str(root / 'primary.log'), 'start'])
            started.append(data)
            with psycopg.connect(host=str(sock1), port=55432, user='postgres', dbname='postgres', autocommit=True) as conn:
                assert conn.execute('SHOW server_version_num').fetchone()[0] == '180006'
                assert conn.execute('SHOW synchronous_commit').fetchone()[0] == 'on'
                assert conn.execute('SHOW synchronous_standby_names').fetchone()[0] == ''
                assert conn.execute('SHOW max_slot_wal_keep_size').fetchone()[0] == '8GB'
                conn.execute(sql.SQL('CREATE ROLE replicator REPLICATION LOGIN PASSWORD {}').format(sql.Literal(password)))
                conn.execute('CREATE TABLE image_smoke (id integer PRIMARY KEY, value text NOT NULL)')
                conn.execute("INSERT INTO image_smoke VALUES (1, 'before basebackup')")
            with psycopg.connect(host='127.0.0.1', port=55432, user='postgres', password=password, dbname='postgres',
                                 sslmode='verify-full', sslrootcert=str(cert)) as conn:
                assert conn.execute('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()').fetchone()[0] is True
            pgpass = root / 'basebackup.pgpass'
            pgpass.write_text('127.0.0.1:55432:*:replicator:' + password + '\n'); pgpass.chmod(0o600)
            env = os.environ | {'PGPASSFILE': str(pgpass), 'PGSSLMODE': 'verify-full', 'PGSSLROOTCERT': str(cert), 'PGCONNECT_TIMEOUT': '5'}
            run([str(pg / 'pg_basebackup'), '-h', '127.0.0.1', '-p', '55432', '-U', 'replicator', '-D', str(replica),
                 '-X', 'stream', '-R', '-C', '-S', 'smoke_replica', '--checkpoint=fast', '--max-rate=25M'], env=env)
            run([str(pg / 'pg_ctl'), '-D', str(replica), '-w', '-t', '30', '-l', str(root / 'replica.log'),
                 '-o', '-p 55433 -c unix_socket_directories=' + str(sock2), 'start'])
            started.append(replica)
            with psycopg.connect(host=str(sock1), port=55432, user='postgres', dbname='postgres', autocommit=True) as conn:
                conn.execute("INSERT INTO image_smoke VALUES (2, 'streaming async')")
            for attempt in range(60):
                with psycopg.connect(host=str(sock2), port=55433, user='postgres', dbname='postgres') as conn:
                    assert conn.execute('SELECT pg_is_in_recovery()').fetchone()[0] is True
                    if conn.execute('SELECT count(*) FROM image_smoke').fetchone()[0] == 2:
                        break
                time.sleep(0.5)
            else:
                raise AssertionError('Replica did not receive committed rows')
            with psycopg.connect(host=str(sock1), port=55432, user='postgres', dbname='postgres') as conn:
                assert conn.execute('SELECT state,sync_state FROM pg_stat_replication').fetchall() == [('streaming', 'async')]
                assert conn.execute("SELECT wal_status FROM pg_replication_slots WHERE slot_name='smoke_replica'").fetchone()[0] in ('reserved', 'extended')
            refused = subprocess.run(['/opt/patroni/bin/python', '/opt/infra/manual-promotion-gate.py'], capture_output=True, timeout=10)
            assert refused.returncode == 1
        except Exception:
            for logfile in root.glob('*.log'):
                print(logfile.name + ':\n' + logfile.read_text()[-12000:], file=sys.stderr)
            raise
        finally:
            for directory in reversed(started):
                subprocess.run([str(pg / 'pg_ctl'), '-D', str(directory), '-w', '-t', '30', '-m', 'fast', 'stop'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40)
    print(json.dumps({'patroni': '4.1.5', 'postgresql': '18.6', 'uid': 19999, 'config_validator': 'passed',
                      'tls_scram': 'passed', 'basebackup_streaming_async': 'passed', 'manual_gate_without_approval': 'refused',
                      'watchdog_opened': False, 'kubernetes_dcs_tested': False, 'fencing_tested': False}))


if __name__ == '__main__':
    main()
