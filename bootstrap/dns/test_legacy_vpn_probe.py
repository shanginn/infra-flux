"""Offline protocol and lifecycle checks; no real sockets or listeners."""
import importlib.util
from pathlib import Path
import selectors
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('legacy-vpn-probe.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
NONCE = '0123456789abcdef0123456789abcdef'
QUERY = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + M.QUESTION


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now


class Sock:
    def __init__(self, label, receives=(), accepts=(), datagrams=(), short_send=False):
        self.label, self.receives, self.accepts = label, list(receives), list(accepts)
        self.datagrams, self.sent, self.sent_datagrams = list(datagrams), b'', []
        self.closed, self.bound, self.short_send = False, None, short_send
    def setblocking(self, value): self.blocking = value
    def bind(self, address): self.bound = address
    def listen(self, size): self.backlog = size
    def accept(self): return self.accepts.pop(0)
    def recv(self, size): return self.receives.pop(0)[:size]
    def recvfrom(self, size):
        data, peer = self.datagrams.pop(0)
        return data[:size], peer
    def send(self, data):
        size = min(len(data), 2) if self.short_send else len(data)
        self.short_send = False
        self.sent += data[:size]
        return size
    def sendto(self, data, peer): self.sent_datagrams.append((data, peer))
    def close(self): self.closed = True


class Selector:
    def __init__(self, clock, schedule):
        self.clock, self.schedule, self.keys, self.closed = clock, list(schedule), {}, False
        self.peak_clients = 0
    def register(self, sock, mask, data):
        self.keys[sock.label] = SimpleNamespace(fileobj=sock, data=data)
        self.peak_clients = max(self.peak_clients, sum(k.startswith('client') for k in self.keys))
    def modify(self, sock, mask, data): self.register(sock, mask, data)
    def unregister(self, sock):
        if sock.label not in self.keys: raise KeyError(sock.label)
        del self.keys[sock.label]
    def select(self, timeout):
        if self.schedule:
            action = self.schedule.pop(0)
            if isinstance(action, (int, float)):
                self.clock.now += action
                return []
            self.clock.now += 0.01
            name, mask = action
            return [(self.keys[name], mask)]
        self.clock.now += timeout
        return []
    def close(self): self.closed = True


class ProtocolTests(unittest.TestCase):
    def test_private_bind_and_exact_sources_only(self):
        self.assertEqual(M.validate('100.65.0.1', NONCE, ['100.65.0.4'], 600)[0], '100.65.0.1')
        for address in ('0.0.0.0', '203.0.113.9', '127.0.0.1', '169.254.1.1', '::1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                M.validate(address, NONCE, ['100.65.0.4'], 1)
        for sources in ([], ['100.65.0.4'] * 2, ['8.8.8.8'], ['100.65.0.' + str(i) for i in range(17)]):
            with self.assertRaises(ValueError): M.validate('100.65.0.1', NONCE, sources, 1)

    def test_nonce_and_deadline_cannot_be_unbounded(self):
        for nonce in ('', 'a' * 31, 'g' * 32, 'a' * 33):
            with self.assertRaises(ValueError): M.validate('100.65.0.1', nonce, ['100.65.0.4'], 1)
        for lifetime in (0, -1, 601, 1.5, True):
            with self.assertRaises(ValueError): M.validate('100.65.0.1', NONCE, ['100.65.0.4'], lifetime)

    def test_dns_exact_single_txt_no_recursion_or_cache(self):
        reply = M.dns_reply(QUERY, NONCE)
        self.assertEqual(struct.unpack('!6H', reply[:12]), (123, 0x8500, 1, 1, 0, 0))
        self.assertEqual(reply[12:12 + len(M.QUESTION)], M.QUESTION)
        answer = reply[12 + len(M.QUESTION):]
        self.assertEqual(struct.unpack('!HHIH', answer[2:12]), (16, 1, 0, 33))
        self.assertEqual(answer[12:], b'\x20' + NONCE.encode())
        self.assertLess(len(reply), 128)

    def test_default_dig_ad_flag_is_accepted_but_never_claimed_authenticated(self):
        query = struct.pack('!6H', 123, 0x0120, 1, 0, 0, 0) + M.QUESTION
        self.assertEqual(struct.unpack('!H', M.dns_reply(query, NONCE)[2:4])[0], 0x8500)

    def test_dns_rejects_malformed_edns_compression_and_other_records(self):
        packets = [b'', QUERY[:-1], QUERY + b'\0', QUERY.replace(b'invalid', b'example'),
                   QUERY[:-4] + struct.pack('!HH', 1, 1), QUERY[:-2] + b'\0\3',
                   struct.pack('!6H', 123, 0, 1, 0, 0, 0) + b'\xc0\x0c\0\x10\0\1']
        for flags in (0x8000, 0x0800, 0x0200, 0x0040):
            packets.append(struct.pack('!6H', 123, flags, 1, 0, 0, 0) + M.QUESTION)
        for counts in ((2, 0, 0, 0), (1, 0, 0, 1), (1, 1, 0, 0)):
            packets.append(struct.pack('!6H', 123, 0, *counts) + M.QUESTION)
        for packet in packets:
            with self.subTest(packet=packet): self.assertIsNone(M.dns_reply(packet, NONCE))

    def test_http_is_exact_endpoint_and_reports_peer(self):
        reply = M.http_reply(b'GET /nonce HTTP/1.1\r\nHost: test\r\n\r\n', NONCE, '100.65.0.4')
        header, body = reply.split(b'\r\n\r\n')
        self.assertEqual(body, (NONCE + '\nsource=100.65.0.4\n').encode())
        self.assertIn(b'Content-Length: ' + str(len(body)).encode(), header)
        for request in (b'POST /nonce HTTP/1.1\r\n\r\n', b'GET / HTTP/1.1\r\n\r\n',
                        b'GET /nonce HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n',
                        b'GET /nonce HTTP/1.1\r\nContent-Length: 1\r\n\r\nx',
                        b'GET /nonce HTTP/1.1\r\nBadHeader\r\n\r\n', b'x' * 1025):
            self.assertIsNone(M.http_reply(request, NONCE, '100.65.0.4'))


class LifecycleTests(unittest.TestCase):
    def run_server(self, listeners, schedule, lifetime=1):
        clock, events = Clock(), []
        selector = Selector(clock, schedule)
        self.last_selector = selector
        with patch.object(M.socket, 'socket', side_effect=listeners), \
             patch.object(M.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(M.time, 'monotonic', side_effect=clock), \
             patch.object(M, 'emit', side_effect=events.append):
            M.serve('100.65.0.1', NONCE, ['100.65.0.4'], lifetime)
        self.assertTrue(all(sock.closed for sock in listeners))
        self.assertTrue(selector.closed)
        self.assertGreaterEqual(clock.now, lifetime)
        return events

    def test_udp_source_allowlist_and_fixed_rate_cap(self):
        udp = Sock('udp', datagrams=[(QUERY, ('100.65.0.4', 9000))] * 21 + [(QUERY, ('100.65.0.5', 9000))])
        listeners = [udp, Sock('dns'), Sock('http')]
        events = self.run_server(listeners, [('udp', selectors.EVENT_READ)] * 22)
        self.assertEqual(len(udp.sent_datagrams), 20)
        self.assertTrue(all(peer[0] == '100.65.0.4' for _, peer in udp.sent_datagrams))
        self.assertEqual([s.bound for s in listeners], [('100.65.0.1', 5354), ('100.65.0.1', 5354), ('100.65.0.1', 18081)])
        self.assertEqual(events[0]['event'], 'ready')
        self.assertEqual(events[-1]['event'], 'stopped')
        self.assertTrue(all(NONCE not in str(event) for event in events))

    def test_tcp_fragmentation_framing_and_partial_write(self):
        frame = struct.pack('!H', len(QUERY)) + QUERY
        client = Sock('client', receives=[frame[:1], frame[1:8], frame[8:]], short_send=True)
        listeners = [Sock('udp'), Sock('dns', accepts=[(client, ('100.65.0.4', 9000))]), Sock('http')]
        events = self.run_server(listeners, [('dns', selectors.EVENT_READ)] +
                                 [('client', selectors.EVENT_READ)] * 3 + [('client', selectors.EVENT_WRITE)] * 2)
        self.assertTrue(client.closed)
        self.assertEqual(struct.unpack('!H', client.sent[:2])[0], len(client.sent) - 2)
        self.assertEqual(client.sent[2:], M.dns_reply(QUERY, NONCE))
        self.assertEqual(len([e for e in events if e['event'] == 'source']), 1)

    def test_unauthorized_tcp_peer_gets_no_response(self):
        client = Sock('client')
        listeners = [Sock('udp'), Sock('dns'), Sock('http', accepts=[(client, ('100.65.0.5', 9000))])]
        self.run_server(listeners, [('http', selectors.EVENT_READ)])
        self.assertTrue(client.closed)
        self.assertEqual(client.sent, b'')

    def test_http_fragmented_request_returns_observed_source(self):
        client = Sock('client', receives=[b'GET /nonce HTTP/1.1\r\nHost: test', b'\r\n\r\n'])
        listeners = [Sock('udp'), Sock('dns'), Sock('http', accepts=[(client, ('100.65.0.4', 9000))])]
        self.run_server(listeners, [('http', selectors.EVENT_READ), ('client', selectors.EVENT_READ),
                                    ('client', selectors.EVENT_READ), ('client', selectors.EVENT_WRITE)])
        self.assertTrue(client.closed)
        self.assertTrue(client.sent.endswith((NONCE + '\nsource=100.65.0.4\n').encode()))

    def test_open_client_count_is_bounded(self):
        peers = [Sock('client' + str(n)) for n in range(17)]
        listeners = [Sock('udp'), Sock('dns'), Sock('http', accepts=[(p, ('100.65.0.4', 9000)) for p in peers])]
        self.run_server(listeners, [('http', selectors.EVENT_READ)] * 17)
        self.assertTrue(all(p.closed for p in peers))
        self.assertEqual(self.last_selector.peak_clients, 16)
        self.assertFalse(any(p.sent for p in peers))

    def test_log_count_stays_bounded_with_many_permitted_sources(self):
        udp = Sock('udp', datagrams=[(QUERY, ('100.65.0.4', 9000))] * 120)
        schedule = []
        for _ in range(6):
            schedule.extend([('udp', selectors.EVENT_READ)] * 20)
            schedule.append(1)
        events = self.run_server([udp, Sock('dns'), Sock('http')], schedule, lifetime=8)
        self.assertEqual(len(udp.sent_datagrams), 120)
        self.assertEqual(sum(e['event'] == 'source' for e in events), 96)
        self.assertEqual(len(events), 98)

    def test_incomplete_client_cannot_extend_server_deadline(self):
        client = Sock('client', receives=[b'GET /'])
        listeners = [Sock('udp'), Sock('dns'), Sock('http', accepts=[(client, ('100.65.0.4', 9000))])]
        self.run_server(listeners, [('http', selectors.EVENT_READ), ('client', selectors.EVENT_READ)])
        self.assertTrue(client.closed)
        self.assertEqual(client.sent, b'')

    def test_oversized_tcp_frame_closes_without_reply(self):
        client = Sock('client', receives=[struct.pack('!H', 65535)])
        listeners = [Sock('udp'), Sock('dns', accepts=[(client, ('100.65.0.4', 9000))]), Sock('http')]
        self.run_server(listeners, [('dns', selectors.EVENT_READ), ('client', selectors.EVENT_READ)])
        self.assertTrue(client.closed)
        self.assertEqual(client.sent, b'')

    def test_bind_failure_closes_previously_created_sockets(self):
        listeners = [Sock('udp'), Sock('dns'), Sock('http')]
        listeners[2].bind = lambda address: (_ for _ in ()).throw(OSError('in use'))
        events, selector = [], Selector(Clock(), [])
        with patch.object(M.socket, 'socket', side_effect=listeners), \
             patch.object(M.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(M, 'emit', side_effect=events.append), self.assertRaises(OSError):
            M.serve('100.65.0.1', NONCE, ['100.65.0.4'], 1)
        self.assertTrue(all(sock.closed for sock in listeners))
        self.assertTrue(selector.closed)
        self.assertFalse(any(e['event'] == 'ready' for e in events))


if __name__ == '__main__':
    unittest.main()
