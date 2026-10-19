import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('legacy-axfr-policy.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.peers = ['100.64.1.1', '100.64.1.2', '100.64.1.3']
        self.readers = self.peers[::2]
        self.primary = '100.64.1.5'
        self.before = {'tagOwners': {'tag:legacy-pdns-reader': ['infra@'],
                                    'tag:legacy-pdns-writer': ['infra@']},
                       'acls': [{'action': 'accept', 'src': self.peers,
                                 'dst': [p + ':*' for p in self.peers]}],
                       'tests': [{'src': self.peers[0], 'accept': [self.peers[1] + ':22']}]}
        for tag, proto, port in [('reader', 'udp', 5354), ('reader', 'tcp', 5354), ('writer', 'tcp', 18081)]:
            self.before['acls'].append({'action': 'accept', 'src': ['tag:legacy-pdns-' + tag],
                                       'dst': [a + ':' + str(port) for a in self.readers], 'proto': proto})

    def test_preserves_existing_permissions_and_only_adds_dns(self):
        original = copy.deepcopy(self.before)
        after = policy.proposed(self.before, self.readers, self.primary)
        self.assertEqual(self.before, original)
        self.assertEqual(after['acls'][:4], original['acls'])
        self.assertEqual(after['tests'][:1], original['tests'])
        self.assertEqual(after['tagOwners'], original['tagOwners'])
        self.assertEqual([r['proto'] for r in after['acls'][4:]], ['udp', 'tcp'])
        for r in after['acls'][4:]:
            self.assertEqual(r['src'], self.readers)
            self.assertEqual(r['dst'], [self.primary + ':5355'])
        self.assertIn(self.primary + ':8081', after['tests'][1]['deny'])
        self.assertEqual(after['tests'][-1], {'src': self.peers[1], 'deny': [self.primary + ':5355']})

    def test_rejects_replay_or_partial_policy(self):
        for extra in ([], [{'action': 'accept', 'src': ['*'], 'dst': ['*:*']}], self.before['acls'][:1]):
            changed = copy.deepcopy(self.before)
            changed['acls'] = changed['acls'][:3] if not extra else changed['acls'] + extra
            with self.assertRaises(ValueError):
                policy.proposed(changed, self.readers, self.primary)
        after = policy.proposed(self.before, self.readers, self.primary)
        with self.assertRaises(ValueError):
            policy.proposed(after, self.readers, self.primary)

    def test_rejects_wrong_roles_or_broad_destinations(self):
        for readers, primary in [(self.readers, self.peers[1]),
                                  ([self.readers[0]] * 2, self.primary),
                                  (['100.64.1.1', '100.64.1.8'], self.primary),
                                  (self.readers, '203.0.113.1'),
                                  (self.readers, '100.64.1.5/32')]:
            with self.assertRaises(ValueError):
                policy.proposed(self.before, readers, primary)
        changed = copy.deepcopy(self.before)
        changed['acls'][3]['dst'][0] = self.readers[0] + ':*'
        with self.assertRaises(ValueError):
            policy.proposed(changed, self.readers, self.primary)


if __name__ == '__main__':
    unittest.main()
