#!/usr/bin/env python3
"""Temporary, private ACL diagnostic; not a DNS authority or HTTP proxy.

Run with an external systemd RuntimeMaxSec as well as --lifetime. DNS clients
must use TXT _infra-vpn-probe.invalid, port 5354, and +noedns. HTTP GET /nonce
on port 18081 returns the nonce and observed peer address. No files are written.
"""
import argparse
import ipaddress
import json
import re
import selectors
import socket
import struct
import time

NETWORKS = tuple(ipaddress.ip_network(n) for n in
                 ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
NAME = b''.join(bytes([len(p)]) + p for p in b'_infra-vpn-probe.invalid'.split(b'.')) + b'\0'
QUESTION = NAME + struct.pack('!HH', 16, 1)

def private_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in network for network in NETWORKS):
        raise ValueError('Require a specific RFC1918 or CGNAT IPv4 address')
    return str(address)

def validate(bind, nonce, sources, lifetime):
    bind = private_ipv4(bind)
    if not re.fullmatch(r'[0-9a-fA-F]{32}', nonce):
        raise ValueError('Nonce must contain exactly 32 hexadecimal characters')
    sources = [private_ipv4(x) for x in sources]
    if not 1 <= len(sources) <= 16 or len(set(sources)) != len(sources):
        raise ValueError('Require 1–16 distinct private source addresses')
    if type(lifetime) is not int or not 1 <= lifetime <= 600:
        raise ValueError('Lifetime must be an integer between 1 and 600 seconds')
    return bind, nonce, frozenset(sources), lifetime

def dns_reply(data, nonce):
    if len(data) != 12 + len(QUESTION):
        return None
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if flags & ~0x0120 or (qd, an, ns, ar) != (1, 0, 0, 0):
        return None
    if data[12:].lower() != QUESTION:
        return None
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 0, 33) + b'\x20' + nonce.encode('ascii')
    return struct.pack('!6H', ident, 0x8400 | (flags & 0x0100), 1, 1, 0, 0) + data[12:] + answer

def http_reply(data, nonce, peer):
    if len(data) > 1024 or not data.endswith(b'\r\n\r\n'):
        return None
    lines = data[:-4].split(b'\r\n')
    if not lines or lines[0] not in (b'GET /nonce HTTP/1.0', b'GET /nonce HTTP/1.1'):
        return None
    if len(lines) > 17:
        return None
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        if not separator or not re.fullmatch(rb'[A-Za-z0-9-]+', name):
            return None
        if any(c < 32 or c > 126 for c in value) or name.lower() == b'transfer-encoding':
            return None
        if name.lower() == b'content-length' and value.strip() != b'0':
            return None
    body = (nonce + '\nsource=' + peer + '\n').encode('ascii')
    return (b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n'
            b'Cache-Control: no-store\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)

def emit(event):
    print(json.dumps(event, separators=(',', ':')), flush=True)


def serve(bind, nonce, sources, lifetime):
    bind, nonce, sources, lifetime = validate(bind, nonce, sources, lifetime)
    selector, sockets, clients = selectors.DefaultSelector(), set(), {}
    end, events, responses = time.monotonic() + lifetime, 0, 0
    window, count = -1, 0

    def log(event):
        nonlocal events
        if events < 96:
            emit(event)
            events += 1

    def close(sock):
        try:
            selector.unregister(sock)
        except KeyError:
            pass
        clients.pop(sock, None)
        sockets.discard(sock)
        sock.close()

    def permitted_response():
        nonlocal window, count, responses
        second = int(time.monotonic())
        if second != window:
            window, count = second, 0
        if count >= 20:
            return False
        count += 1
        responses += 1
        return True

    try:
        for kind, port, socktype in (('udp', 5354, socket.SOCK_DGRAM),
                                     ('dns', 5354, socket.SOCK_STREAM),
                                     ('http', 18081, socket.SOCK_STREAM)):
            sock = socket.socket(socket.AF_INET, socktype)
            sockets.add(sock)
            sock.setblocking(False)
            sock.bind((bind, port))
            if socktype == socket.SOCK_STREAM:
                sock.listen(8)
            selector.register(sock, selectors.EVENT_READ, kind)
        emit({'event': 'ready', 'bind': bind, 'lifetime_seconds': lifetime,
              'ports': [5354, 18081], 'allowed_sources': len(sources)})
        while time.monotonic() < end:
            for sock, state in list(clients.items()):
                if time.monotonic() >= state['deadline']:
                    close(sock)
            for key, mask in selector.select(min(0.2, max(0, end - time.monotonic()))):
                if time.monotonic() >= end:
                    break
                sock, kind = key.fileobj, key.data
                try:
                    if kind == 'udp':
                        data, peer = sock.recvfrom(513)
                        reply = dns_reply(data, nonce) if peer[0] in sources else None
                        if reply and permitted_response():
                            sock.sendto(reply, peer)
                            log({'event': 'source', 'protocol': 'dns-udp', 'source': peer[0]})
                    elif kind in ('dns', 'http'):
                        conn, peer = sock.accept()
                        if peer[0] not in sources or len(clients) >= 16:
                            conn.close()
                            continue
                        conn.setblocking(False)
                        clients[conn] = {'kind': kind, 'peer': peer[0], 'buf': b'',
                                         'deadline': min(end, time.monotonic() + 2), 'out': b''}
                        sockets.add(conn)
                        selector.register(conn, selectors.EVENT_READ, 'client')
                    elif sock in clients:
                        state = clients[sock]
                        if mask & selectors.EVENT_WRITE:
                            sent = sock.send(state['out'])
                            state['out'] = state['out'][sent:]
                            if not state['out']:
                                log({'event': 'source', 'protocol': state['kind'] + '-tcp', 'source': state['peer']})
                                close(sock)
                            continue
                        chunk = sock.recv(1025)
                        state['buf'] += chunk
                        data, reply = state['buf'], None
                        limit = 514 if state['kind'] == 'dns' else 1024
                        if not chunk or len(data) > limit:
                            close(sock)
                            continue
                        if state['kind'] == 'dns' and len(data) >= 2:
                            size = struct.unpack('!H', data[:2])[0]
                            if size > 512 or len(data) > size + 2:
                                close(sock)
                                continue
                            if len(data) < size + 2:
                                continue
                            if len(data) == size + 2:
                                reply = dns_reply(data[2:], nonce)
                                reply = struct.pack('!H', len(reply)) + reply if reply else None
                        elif state['kind'] == 'http' and b'\r\n\r\n' in data:
                            reply = http_reply(data, nonce, state['peer'])
                        else:
                            continue
                        if reply and permitted_response():
                            state['out'] = reply
                            selector.modify(sock, selectors.EVENT_WRITE, 'client')
                        else:
                            close(sock)
                except (OSError, ValueError):
                    if sock in clients:
                        close(sock)
    finally:
        for sock in list(sockets):
            close(sock)
        selector.close()
        emit({'event': 'stopped', 'responses_queued': responses, 'source_events': events})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--allow-source', action='append', required=True)
    parser.add_argument('--lifetime', type=int, default=120)
    args = parser.parse_args()
    try:
        serve(args.bind, args.nonce, args.allow_source, args.lifetime)
    except (ValueError, OSError) as error:
        parser.exit(1, type(error).__name__ + ': probe could not start or configuration is invalid\n')
