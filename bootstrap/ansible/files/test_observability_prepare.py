"""Offline credential preservation/CAS tests; never call a cluster or database."""
import base64
import copy
import hashlib
import hmac
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('observability-prepare.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.state = {'managed_by': p.OWNER, 'format': 1, 'cluster_uid': 'test-cluster',
                      'ca_sha256': 'a'*64, 'prepared': True, 'postgres_ca': 'test-ca',
                      'bucket_id': 'test-bucket', 's3_key': {'accessKeyId': 'test-key', 'secretAccessKey': 'test-secret'},
                      'apps': {name: {'database_password': 'test-password-' + name,
                                      'secret_key': 'test-signing-' + name,
                                      'admin_password': 'test-admin-' + name}
                               for name in ('grafana', 'glitchtip')}}
        self.obj = {'type': 'Opaque', 'metadata': {'uid': 'secret-uid', 'resourceVersion': '10',
                    'annotations': {'infra.shanginn.io/managed-by': p.OWNER}}, 'data': p.glitchtip_data(self.state)}
        self.review = {'expected_secret_uid': 'secret-uid', 'expected_secret_resource_version': '10',
                       'expected_secret_data_sha256': p.digest(self.obj['data'])}
        self.saved = []; self.patches = []; self.fail = None
        a = patch.object(p, 'kube', side_effect=self.kube); a.start(); self.addCleanup(a.stop)
        a = patch.object(p, 'save', side_effect=lambda s: self.saved.append(copy.deepcopy(s))); a.start(); self.addCleanup(a.stop)

    def kube(self, args, body=None):
        if args[0] == 'get':
            return copy.deepcopy(self.obj)
        self.assertEqual(args[:5], ['patch', 'secret', 'glitchtip-runtime', '-n', 'error-tracking'])
        self.assertEqual(self.saved[-1][p.TIMEOUT_RECONCILE]['phase'], 'dispatch-intent')
        self.patches.append(copy.deepcopy(body))
        self.assertEqual([x['path'] for x in body], ['/metadata/uid', '/metadata/resourceVersion', '/data', '/data/DATABASE_URL'])
        self.assertEqual(body[0]['value'], self.obj['metadata']['uid'])
        self.assertEqual(body[1]['value'], self.obj['metadata']['resourceVersion'])
        self.assertEqual(body[2]['value'], self.obj['data'])
        if self.fail == 'before':
            raise subprocess.TimeoutExpired('kubectl', 20)
        self.obj['data']['DATABASE_URL'] = body[3]['value']
        self.obj['metadata']['resourceVersion'] = '11'
        if self.fail == 'after':
            raise subprocess.TimeoutExpired('kubectl', 20)
        return copy.deepcopy(self.obj)

    def test_inspection_has_no_writes(self):
        result = p.inspect_timeout(self.state)
        self.assertFalse(result['changed']); self.assertEqual(self.saved, []); self.assertEqual(self.patches, [])

    def test_only_url_changed_and_credentials_preserved(self):
        before = copy.deepcopy(self.obj['data']); identity = p.recovery_identity(self.state)
        result = p.reconcile_timeout(self.state, self.review)
        self.assertTrue(result['verified']); self.assertEqual(len(self.patches), 1)
        self.assertEqual(p.recovery_identity(self.state), identity)
        before['DATABASE_URL'] = self.obj['data']['DATABASE_URL']
        self.assertEqual(before, self.obj['data'])
        self.assertTrue(base64.b64decode(before['DATABASE_URL']).endswith(b'&connect_timeout=5'))

    def test_unchanged_verified_resume_never_patches(self):
        p.reconcile_timeout(self.state, self.review)
        result = p.reconcile_timeout(self.state, self.review)
        self.assertFalse(result['changed']); self.assertEqual(len(self.patches), 1)

    def test_unknown_dispatch_with_readback_success(self):
        self.fail = 'after'
        self.assertTrue(p.reconcile_timeout(self.state, self.review)['verified'])
        self.assertEqual(len(self.patches), 1)

    def test_unknown_uncommitted_dispatch_never_retries(self):
        self.fail = 'before'
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, 'unverified'):
                p.reconcile_timeout(self.state, self.review)
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.state[p.TIMEOUT_RECONCILE]['phase'], 'dispatch-intent')

    def test_unknown_resume_rejects_new_secret_uid(self):
        self.fail = 'before'
        with self.assertRaises(RuntimeError): p.reconcile_timeout(self.state, self.review)
        self.obj['metadata']['uid'] = 'replacement-secret'
        with self.assertRaises(RuntimeError): p.reconcile_timeout(self.state, self.review)
        self.assertEqual(len(self.patches), 1)

    def test_wrong_review_fields_rejected(self):
        for key in self.review:
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'reviewed'):
                p.reconcile_timeout(self.state, {**self.review, key: 'different'})
        self.assertEqual(self.saved, []); self.assertEqual(self.patches, [])

    def test_foreign_owner_rejected(self):
        self.obj['metadata']['annotations']['infra.shanginn.io/managed-by'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'owner'): p.reconcile_timeout(self.state, self.review)
        self.assertEqual(self.patches, [])

    def test_secret_drift_not_adopted_even_with_fresh_review(self):
        self.obj['data']['SECRET_KEY'] = 'changed'
        self.review['expected_secret_data_sha256'] = p.digest(self.obj['data'])
        with self.assertRaisesRegex(RuntimeError, 'legacy'): p.reconcile_timeout(self.state, self.review)
        self.assertEqual(self.saved, []); self.assertEqual(self.patches, [])

    def test_no_patch_when_intent_cannot_be_saved(self):
        with patch.object(p, 'save', side_effect=OSError('disk full')), self.assertRaises(OSError):
            p.reconcile_timeout(self.state, self.review)
        self.assertEqual(self.patches, [])

    def test_new_install_already_has_timeout_without_reconcile(self):
        self.state['glitchtip_connect_timeout'] = 5; self.obj['data'] = p.glitchtip_data(self.state, 5)
        self.review['expected_secret_data_sha256'] = p.digest(self.obj['data'])
        self.assertFalse(p.reconcile_timeout(self.state, self.review)['changed'])
        self.assertEqual(self.saved, []); self.assertEqual(self.patches, [])

    def test_recovery_identity_detects_every_persisted_credential(self):
        original = p.recovery_identity(self.state)
        for app in self.state['apps']:
            for key in self.state['apps'][app]:
                other = copy.deepcopy(self.state); other['apps'][app][key] += '-changed'
                self.assertNotEqual(p.recovery_identity(other), original)
        other = copy.deepcopy(self.state); other['s3_key']['secretAccessKey'] += '-changed'
        self.assertNotEqual(p.recovery_identity(other), original)

    def test_recovery_identity_allows_only_noncredential_progress_difference(self):
        before = p.recovery_identity(self.state)
        self.state.update(glitchtip_connect_timeout=5, prepared=False)
        self.state[p.TIMEOUT_RECONCILE] = {'phase': 'dispatch-intent'}
        self.assertEqual(p.recovery_identity(self.state), before)


class ScramTests(unittest.TestCase):
    def setUp(self):
        namespace = {}; exec(p.SCRAM_VERIFY, namespace); self.matches = namespace['matches_scram']
        salt = b'fixed-test-salt'; self.password = 'test-password-never-used-live'
        salted = hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt, 4096)
        stored = hashlib.sha256(hmac.new(salted, b'Client Key', 'sha256').digest()).digest()
        server = hmac.new(salted, b'Server Key', 'sha256').digest()
        b64 = lambda v: base64.b64encode(v).decode()
        self.verifier = 'SCRAM-SHA-256$4096:' + b64(salt) + '$' + b64(stored) + ':' + b64(server)

    def test_matching_password(self): self.assertTrue(self.matches(self.password, self.verifier))
    def test_changed_password(self): self.assertFalse(self.matches(self.password + 'x', self.verifier))
    def test_malformed_or_costly_verifier(self):
        for bad in (None, 'md5deadbeef', self.verifier.replace('4096:', '999999999:')):
            self.assertFalse(self.matches(self.password, bad))


if __name__ == '__main__': unittest.main()
