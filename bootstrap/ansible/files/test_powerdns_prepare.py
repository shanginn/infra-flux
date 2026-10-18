"""Offline recovery and secret-boundary checks; no cluster access."""
import base64
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('powerdns-prepare.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.state = {'managed_by': p.OWNER, 'format': 1, 'cluster_uid': 'test-cluster',
            'ca_sha256': 'a' * 64, 'schema_sha256': 'b' * 64, 'postgres_ca': 'test-ca',
            'api_key': 'legacy-key-' + 'a' * 32, 'api_password': 'b' * 40,
            'reader_password': 'c' * 40, 'webserver_password': 'd' * 40}

    def test_configuration_injection_rejected_for_every_credential(self):
        for key in ('api_key', 'api_password', 'reader_password', 'webserver_password'):
            for suffix in ('\nallow-dnsupdate-from=0.0.0.0/0', '\r', '#comment', ' value'):
                with self.subTest(key=key, suffix=suffix), self.assertRaises(RuntimeError):
                    p.validate_state({**self.state, key: self.state[key] + suffix})

    def test_reader_has_no_write_or_api_credentials(self):
        data = p.secret_data(self.state)
        self.assertEqual(set(data), {'credentials.conf', 'ca.crt'})
        config = base64.b64decode(data['credentials.conf']).decode()
        self.assertEqual(config, 'gpgsql-password=' + self.state['reader_password'] + '\n')
        for key in ('api_key', 'api_password', 'webserver_password'):
            self.assertNotIn(self.state[key], config)

    def test_recovery_identity_ignores_progress_but_binds_all_credentials(self):
        identity = p.recovery_identity(self.state)
        self.assertEqual(identity, p.recovery_identity({**self.state, 'prepared': True}))
        for key in self.state:
            changed = copy.deepcopy(self.state)
            changed[key] = 2 if key == 'format' else str(changed[key]) + 'different'
            self.assertNotEqual(identity, p.recovery_identity(changed), key)

    def test_foreign_or_modified_secret_is_never_adopted(self):
        data = p.secret_data(self.state, True)
        obj = {'type': 'Opaque', 'metadata': {'annotations': {'infra.shanginn.io/managed-by': p.OWNER}}, 'data': data}
        p.verify_secret(obj, data)
        for mutation in ('owner', 'password', 'type', 'extra'):
            bad = copy.deepcopy(obj)
            if mutation == 'owner': bad['metadata']['annotations']['infra.shanginn.io/managed-by'] = 'foreign'
            if mutation == 'password': bad['data']['credentials.conf'] = 'different'
            if mutation == 'type': bad['type'] = 'kubernetes.io/tls'
            if mutation == 'extra': bad['data']['extra'] = 'unexpected'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                p.verify_secret(bad, data)

    def test_shared_webserver_and_api_credential_rejected(self):
        with self.assertRaises(RuntimeError):
            p.validate_state({**self.state, 'webserver_password': self.state['api_key']})

    def test_embedded_remote_program_is_valid_python(self):
        compile(p.SQL, '<powerdns-bootstrap-sql>', 'exec')


if __name__ == '__main__':
    unittest.main()
