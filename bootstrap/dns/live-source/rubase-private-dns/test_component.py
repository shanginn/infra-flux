"""Offline whole-render checks for the inactive DNS-only source bridge."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SERVICE = ('Service', 'vibesites-dns', 'vibesites-powerdns-private-dns')


def render(component):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve()
        config = {
            'apiVersion': 'kustomize.config.k8s.io/v1beta1',
            'kind': 'Kustomization',
            'resources': [os.path.relpath(ROOT / 'clusters/rubase/vibesites-dns', path)],
        }
        if component:
            config['components'] = [os.path.relpath(HERE, path)]
        (path / 'kustomization.yaml').write_text(yaml.safe_dump(config))
        raw = subprocess.check_output(
            ['kubectl', 'kustomize', str(path), '--load-restrictor', 'LoadRestrictionsNone'],
            text=True,
        )
        objects = [row for row in yaml.safe_load_all(raw) if row]
        indexed = {(row['kind'], row['metadata'].get('namespace'), row['metadata']['name']): row
                   for row in objects}
        assert len(indexed) == len(objects), 'Duplicate rendered resource'
        return indexed


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before, cls.after = render(False), render(True)

    def test_adds_only_one_service_preserving_all_existing_objects(self):
        self.assertEqual(set(self.after) - set(self.before), {SERVICE})
        self.assertTrue(set(self.before) <= set(self.after))
        for key, value in self.before.items():
            self.assertEqual(value, self.after[key], key)

    def test_exact_private_dns_surface(self):
        self.assertEqual(self.after[SERVICE]['spec'], {
            'type': 'ClusterIP', 'ipFamilyPolicy': 'SingleStack', 'ipFamilies': ['IPv4'],
            'externalIPs': ['${RUBASE_VPN_ADDRESS}'],
            'externalTrafficPolicy': 'Local', 'internalTrafficPolicy': 'Local',
            'selector': {'app': 'powerdns', 'app.kubernetes.io/name': 'powerdns'},
            'ports': [
                {'name': 'dns-udp', 'port': 5355, 'targetPort': 53, 'protocol': 'UDP'},
                {'name': 'dns-tcp', 'port': 5355, 'targetPort': 53, 'protocol': 'TCP'},
            ],
        })

    def test_selects_existing_dns_pod_and_excludes_schema_job(self):
        selector = self.after[SERVICE]['spec']['selector']
        deployment = self.before[('Deployment', 'vibesites-dns', 'vibesites-powerdns')]
        pod = deployment['spec']['template']
        self.assertTrue(selector.items() <= pod['metadata']['labels'].items())
        container = next(c for c in pod['spec']['containers'] if c['name'] == 'powerdns')
        ports = {(p['containerPort'], p['protocol']) for p in container['ports']}
        self.assertTrue({(53, 'TCP'), (53, 'UDP')} <= ports)
        job = self.before[('Job', 'vibesites-dns', 'powerdns-schema-init')]
        self.assertFalse(selector.items() <= job['spec']['template']['metadata']['labels'].items())

    def test_exact_private_substitution_has_no_extra_ports_or_placeholders(self):
        raw = yaml.safe_dump(self.after[SERVICE])
        env = {'PATH': os.environ['PATH'], 'RUBASE_VPN_ADDRESS': '100.64.0.42'}
        output = subprocess.check_output(['flux', 'envsubst', '--strict'], input=raw, text=True, env=env)
        expected = yaml.safe_load(raw)
        expected['spec']['externalIPs'] = ['100.64.0.42']
        self.assertEqual(yaml.safe_load(output), expected)
        self.assertNotIn('${', output)

    def test_missing_private_value_is_rejected(self):
        result = subprocess.run(['flux', 'envsubst', '--strict'],
                                input=yaml.safe_dump(self.after[SERVICE]), text=True,
                                capture_output=True, env={'PATH': os.environ['PATH']})
        self.assertNotEqual(result.returncode, 0)

    def test_no_parent_activation_or_network_policy(self):
        self.assertEqual(yaml.safe_load((HERE / 'kustomization.yaml').read_text())['resources'],
                         ['service.yaml'])
        for folder in ('clusters', 'components', 'infrastructure'):
            for path in (ROOT / folder).rglob('*.yaml'):
                self.assertNotIn('live-source/rubase-private-dns', path.read_text(), str(path))


if __name__ == '__main__':
    unittest.main()
