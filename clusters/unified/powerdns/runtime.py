#!/usr/bin/env python3
"""Start PDNS, probe real DNS/DB reads, and expose only fixed-path metrics.

The official PDNS image supplies Python and pdnsutil. No schema changes or
secret values are written to logs, command arguments or the generated config.
"""
import base64
import http.server
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import threading
import urllib.request

CONFIG = Path('/opt/powerdns')
RUNTIME = Path('/run/pdns')
SECRET = Path('/etc/powerdns/runtime')
TLS_HOST = 'unified-postgres.database.svc'
HEALTH_ZONE = 'health.test.'


def credentials(role, directory=SECRET):
    wanted = {'gpgsql-password'}
    if role == 'api':
        wanted |= {'api-key', 'webserver-password'}
    values = {}
    for line in (directory / 'credentials.conf').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in wanted or key in values:
            raise ValueError('Unexpected credential setting')
        # Raw PDNS config values: forbid comments, continuations and control data.
        if not value or value != value.strip() or any(c.isspace() or c in '#\\' for c in value):
            raise ValueError('Unsupported credential encoding')
        values[key] = value
    if set(values) != wanted:
        raise ValueError('Missing credential setting')
    if role == 'api' and values['api-key'] == values['webserver-password']:
        raise ValueError('API and web passwords must be distinct')
    if not (directory / 'ca.crt').is_file():
        raise ValueError('Missing database CA')
    return values


def database_service(role, node):
    if role == 'api':
        return TLS_HOST
    if node not in {'msk', 'fin'}:
        raise ValueError('Reader must run on a declared VPS')
    return f'powerdns-postgres-{node}.database.svc'


def render(role, node, hostaddr):
    ipaddress.IPv4Address(hostaddr)
    session = 'read-write' if role == 'api' else 'any'
    # host keeps the certified identity; hostaddr selects the stable Service IP.
    extra = (f'hostaddr={hostaddr} sslmode=verify-full '
             f'sslrootcert={SECRET}/ca.crt connect_timeout=3 '
             f'target_session_attrs={session} application_name=powerdns_{role} '
             "options='-c statement_timeout=3000"
             + (' -c default_transaction_read_only=on' if role == 'reader' else '') + "'")
    return ((CONFIG / 'pdns.conf').read_text() + '\n'
            + (CONFIG / f'{role}.conf').read_text() + '\n'
            + 'gpgsql-extra-connection-parameters=' + extra + '\n')


def start(role):
    credentials(role)
    host = database_service(role, os.environ.get('POD_NODE', ''))
    answers = {a[4][0] for a in socket.getaddrinfo(host, 5432, socket.AF_INET, socket.SOCK_STREAM)}
    if len(answers) != 1:
        raise ValueError('Expected one stable database Service address')
    contents = render(role, os.environ.get('POD_NODE', ''), answers.pop())
    os.umask(0o077)
    target = RUNTIME / 'pdns.conf'
    temporary = RUNTIME / 'pdns.conf.new'
    temporary.write_text(contents)
    temporary.replace(target)
    os.execv('/usr/local/sbin/pdns_server', ['pdns_server', '--config-dir=' + str(RUNTIME)])


def name_at(data, offset):
    labels, seen, end = [], set(), None
    while True:
        if offset in seen or len(seen) > 128 or offset >= len(data):
            raise ValueError('Invalid DNS name')
        seen.add(offset)
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                raise ValueError('Truncated DNS pointer')
            if end is None:
                end = offset + 2
            offset = ((size & 0x3f) << 8) | data[offset + 1]
            continue
        if size & 0xc0 or size > 63 or offset + 1 + size > len(data):
            raise ValueError('Invalid DNS label')
        offset += 1
        if not size:
            return b'.'.join(labels).lower() + b'.', end or offset
        labels.append(data[offset:offset + size])
        offset += size


def valid_soa(data, ident):
    if len(data) < 12:
        return False
    response_id, flags, questions, answers, _, _ = struct.unpack('!6H', data[:12])
    if response_id != ident or flags & 0xfe8f != 0x8400 or questions != 1 or not answers:
        return False
    qname, offset = name_at(data, 12)
    if qname != HEALTH_ZONE.encode() or data[offset:offset + 4] != struct.pack('!HH', 6, 1):
        return False
    offset += 4
    for _ in range(answers):
        owner, offset = name_at(data, offset)
        if offset + 10 > len(data):
            return False
        kind, rclass, _, size = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        if offset + size > len(data):
            return False
        if kind == 6 and rclass == 1 and owner == HEALTH_ZONE.encode():
            _, end = name_at(data, offset)
            _, end = name_at(data, end)
            return end + 20 == offset + size
        offset += size
    return False


def exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ValueError('Truncated DNS stream')
        data += chunk
    return data


def dns_probe(tcp):
    ident = secrets.randbits(16)
    name = b''.join(bytes([len(x)]) + x.encode() for x in HEALTH_ZONE.rstrip('.').split('.')) + b'\0'
    query = struct.pack('!6H', ident, 0, 1, 0, 0, 0) + name + struct.pack('!HH', 6, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect(('127.0.0.1', 5353))
        if tcp:
            sock.sendall(struct.pack('!H', len(query)) + query)
            length = struct.unpack('!H', exact(sock, 2))[0]
            data = exact(sock, length)
        else:
            sock.send(query)
            data = sock.recv(65535)
    if not valid_soa(data, ident):
        raise ValueError('Local authoritative SOA unavailable')


def ready(role):
    dns_probe(False)
    dns_probe(True)
    if role == 'api':
        # A new connection enforces libpq target_session_attrs=read-write.
        # This lists only the synthetic health zone; it never changes DB state.
        result = subprocess.run(
            ['/usr/local/bin/pdnsutil', '--config-dir=' + str(RUNTIME), 'zone', 'list', 'health.test'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        if result.returncode:
            raise ValueError('Writable database unavailable')


def metrics(role):
    headers = {}
    if role == 'api':
        password = credentials(role)['webserver-password']
        headers['Authorization'] = 'Basic ' + base64.b64encode(('metrics:' + password).encode()).decode()
    request = urllib.request.Request('http://127.0.0.1:8081/metrics', headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024 or b'pdns_auth_' not in body:
        raise ValueError('Invalid metrics response')
    return body


def bridge(role):
    # This listener exposes no proxy URL, API route, credentials or zone data.
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            try:
                if self.path == '/health':
                    body = b'ok\n'
                elif self.path == '/metrics':
                    body = metrics(role)
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; version=0.0.4')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError):
                self.send_error(503, 'Metrics unavailable')

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 4
        slots = threading.BoundedSemaphore(4)

        def get_request(self):
            conn, address = super().get_request()
            conn.settimeout(4)
            return conn, address

        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                request.close()
                return
            try:
                super().process_request(request, address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()

    Server(('0.0.0.0', 9081), Handler).serve_forever()


def main():
    mode, role = sys.argv[1:]
    if role not in {'reader', 'api'} or mode not in {'start', 'ready', 'metrics'}:
        raise ValueError('Invalid operation')
    {'start': start, 'ready': ready, 'metrics': bridge}[mode](role)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Connection errors may contain credentials; emit no exception text.
        print('PowerDNS operation failed; check configuration, DNS and database health', file=sys.stderr)
        sys.exit(1)
