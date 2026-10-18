"""Scope and inactive-by-default contract for optional legacy API egress."""
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'clusters/rubase/vibesites-dns/legacy-writer-egress'


class LegacyWriterEgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rendered = subprocess.run(['kubectl', 'kustomize', str(DIRECTORY)],
                                  check=True, capture_output=True, text=True).stdout
        cls.documents = list(yaml.safe_load_all(rendered))

    def test_only_exact_writer_selectors_and_private_api_permission(self):
        expected = {
            'legacy-powerdns-app-egress': {'app.kubernetes.io/name': 'vibesites-pi'},
            'legacy-powerdns-worker-egress': {
                'app.kubernetes.io/name': 'vibesites-pi-worker',
                'app.kubernetes.io/component': 'temporal-worker'},
        }
        self.assertEqual({x['metadata']['name'] for x in self.documents}, set(expected))
        self.assertEqual(len(self.documents), 2)
        for document in self.documents:
            self.assertEqual(document['kind'], 'NetworkPolicy')
            self.assertEqual(document['metadata']['namespace'], 'vibesites-pi')
            self.assertEqual(document['spec'], {
                'podSelector': {'matchLabels': expected[document['metadata']['name']]},
                'policyTypes': ['Egress'],
                'egress': [{'to': [
                    {'ipBlock': {'cidr': '${MSK_VPN_ADDRESS}/32'}},
                    {'ipBlock': {'cidr': '${FIN_VPN_ADDRESS}/32'}}],
                    'ports': [{'protocol': 'TCP', 'port': 18081}]}]})

    def test_activation_is_suspended_and_requires_private_cluster_source(self):
        template = yaml.safe_load((DIRECTORY / 'flux-kustomization.example.yaml').read_text())
        self.assertIs(template['spec']['suspend'], True)
        self.assertEqual(template['spec']['path'], './clusters/rubase/vibesites-dns/legacy-writer-egress')
        self.assertEqual(template['spec']['sourceRef'], {'kind': 'GitRepository', 'name': 'flux-system'})
        self.assertEqual(template['spec']['postBuild'], {'substituteFrom': [
            {'kind': 'ConfigMap', 'name': 'legacy-dns-network', 'optional': False}]})

    def test_parent_does_not_activate_optional_component(self):
        parent = yaml.safe_load((DIRECTORY.parent / 'kustomization.yaml').read_text())
        self.assertFalse(any('legacy-writer-egress' in item for item in parent['resources']))
        own = yaml.safe_load((DIRECTORY / 'kustomization.yaml').read_text())
        self.assertEqual(own['resources'], ['network-policy.yaml'])


if __name__ == '__main__':
    unittest.main()
