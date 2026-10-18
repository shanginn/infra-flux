import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('powerdns_runtime', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.CONFIG = Path(__file__).parent


def response(flags=0x8400, ident=123, kind=6):
    name = b'\x06health\x04test\x00'
    question = name + struct.pack('!HH', 6, 1)
    soa = b'\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c' + struct.pack('!5I', 1, 30, 10, 3600, 30)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(soa)) + soa
    return struct.pack('!6H', ident, flags, 1, 1, 0, 0) + question + answer


class RuntimeTests(unittest.TestCase):
    def test_authoritative_soa_required(self):
        self.assertTrue(runtime.valid_soa(response(), 123))
        for flags in (0x8000, 0x8402, 0x8480, 0x8600, 0x0400):
            with self.subTest(flags=flags):
                self.assertFalse(runtime.valid_soa(response(flags=flags), 123))
        self.assertFalse(runtime.valid_soa(response(ident=124), 123))
        self.assertFalse(runtime.valid_soa(response(kind=1), 123))
        self.assertFalse(runtime.valid_soa(response()[:-1], 123))

    def test_compression_loop_rejected(self):
        with self.assertRaises(ValueError):
            runtime.name_at(b'\xc0\x00', 0)

    def test_only_api_checks_a_new_writable_connection(self):
        with patch.object(runtime, 'dns_probe') as probe, patch.object(runtime.subprocess, 'run') as run:
            runtime.ready('reader')
            self.assertEqual(probe.call_args_list[0].args, (False,))
            self.assertEqual(probe.call_args_list[1].args, (True,))
            run.assert_not_called()
            run.return_value.returncode = 0
            runtime.ready('api')
            self.assertEqual(run.call_args.args[0][-3:], ['zone', 'list', 'health.test'])
            run.return_value.returncode = 1
            with self.assertRaises(ValueError):
                runtime.ready('api')

    def test_failed_dns_never_reports_ready(self):
        with patch.object(runtime, 'dns_probe', side_effect=socket.timeout), patch.object(runtime.subprocess, 'run') as run:
            with self.assertRaises(socket.timeout):
                runtime.ready('api')
            run.assert_not_called()

    def test_local_database_selection_has_no_cross_site_fallback(self):
        self.assertEqual(runtime.database_service('reader', 'msk'), 'powerdns-postgres-msk.database.svc')
        self.assertEqual(runtime.database_service('reader', 'fin'), 'powerdns-postgres-fin.database.svc')
        self.assertEqual(runtime.database_service('api', 'home'), runtime.TLS_HOST)
        with self.assertRaises(ValueError):
            runtime.database_service('reader', 'home')

    def test_render_keeps_tls_identity_and_read_only_reader(self):
        reader = runtime.render('reader', 'msk', '192.0.2.1')
        self.assertIn('gpgsql-host=unified-postgres.database.svc\n', reader)
        self.assertIn('hostaddr=192.0.2.1 sslmode=verify-full', reader)
        self.assertIn('default_transaction_read_only=on', reader)
        self.assertIn('target_session_attrs=any', reader)
        self.assertNotIn('gpgsql-password=', reader)
        api = runtime.render('api', 'home', '192.0.2.2')
        self.assertIn('target_session_attrs=read-write', api)
        self.assertNotIn('default_transaction_read_only=on', api)
        self.assertNotIn('api-key=', api)
        with self.assertRaises(ValueError):
            runtime.render('reader', 'msk', '192.0.2.1 options=unsafe')

    def test_runtime_secret_accepts_only_the_promised_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'ca.crt').write_text('test CA fixture')
            (directory / 'credentials.conf').write_text('gpgsql-password=fixture-value\n')
            self.assertEqual(set(runtime.credentials('reader', directory)), {'gpgsql-password'})
            for value in ('gpgsql-password=fixture\napi=yes\n', 'gpgsql-password=one\ngpgsql-password=two\n', 'gpgsql-password=bad#comment\n', 'gpgsql-password=bad\\\n'):
                (directory / 'credentials.conf').write_text(value)
                with self.assertRaises(ValueError):
                    runtime.credentials('reader', directory)
            (directory / 'credentials.conf').write_text('gpgsql-password=fixture\napi-key=api-fixture\nwebserver-password=web-fixture\n')
            self.assertEqual(len(runtime.credentials('api', directory)), 3)
            with self.assertRaises(ValueError):
                runtime.credentials('reader', directory)
            (directory / 'credentials.conf').write_text('gpgsql-password=fixture\napi-key=duplicate\nwebserver-password=duplicate\n')
            with self.assertRaises(ValueError):
                runtime.credentials('api', directory)


if __name__ == '__main__':
    unittest.main()
