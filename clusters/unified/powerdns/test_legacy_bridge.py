#!/usr/bin/env python3
"""Offline render guards; optional private substitutions and approved Git baseline."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCES = (
    'MSK_API_LOCAL_SOURCE_CIDR', 'MSK_API_REMOTE_SOURCE_CIDR',
    'FIN_API_LOCAL_SOURCE_CIDR', 'FIN_API_REMOTE_SOURCE_CIDR',
)
KEYS = set(SOURCES) | {
    'MSK_VPN_ADDRESS', 'FIN_VPN_ADDRESS',
    'LEGACY_CONTABO_VPN_CIDR', 'LEGACY_RUBASE_VPN_CIDR',
    'POWERDNS_API_ACCESS_REVISION',
}
BASELINE = None
VALUES = None


def revision(values):
    source = {key: values[key] for key in SOURCES}
    return hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_values(values):
    if not isinstance(values, dict) or set(values) != KEYS:
        raise ValueError('Private ConfigMap must contain exactly the documented nine keys')
    if any(not isinstance(value, str) for value in values.values()):
        raise ValueError('All substitutions must be strings')
    for key in sorted(KEYS - {'POWERDNS_API_ACCESS_REVISION'}):
        try:
            if key.endswith('_CIDR'):
                address = ipaddress.IPv4Network(values[key], strict=True)
                if address.prefixlen != 32:
                    raise ValueError()
                address = address.network_address
            else:
                address = ipaddress.IPv4Address(values[key])
            if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                raise ValueError()
            if key not in SOURCES and address.is_global:
                raise ValueError()
        except ValueError:
            raise ValueError('Invalid private address or exact /32 in ' + key) from None
    identities = [values[key].split('/')[0] for key in (
        'MSK_VPN_ADDRESS', 'FIN_VPN_ADDRESS',
        'LEGACY_CONTABO_VPN_CIDR', 'LEGACY_RUBASE_VPN_CIDR')]
    if len(set(identities)) != 4:
        raise ValueError('VPS and legacy client identities must be distinct')
    if values['POWERDNS_API_ACCESS_REVISION'] != revision(values):
        raise ValueError('API access revision does not match the four measured sources')
    return values


def build(path):
    text = subprocess.check_output(['kubectl', 'kustomize', str(path)], text=True)
    return [obj for obj in yaml.safe_load_all(text) if obj]


def pick(objects, kind, name):
    found = [obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name]
    if len(found) != 1:
        raise AssertionError('Expected one ' + kind + '/' + name)
    return found[0]


def generated(objects, prefix):
    found = [obj for obj in objects if obj['kind'] == 'ConfigMap' and obj['metadata']['name'].startswith(prefix + '-')]
    if len(found) != 1:
        raise AssertionError('Expected one generated ConfigMap ' + prefix)
    return found[0]


def example_values():
    values = dict(zip(SOURCES, ('192.0.2.1/32', '10.1.1.1/32', '198.51.100.1/32', '10.2.2.2/32')))
    values.update(MSK_VPN_ADDRESS='100.64.0.1', FIN_VPN_ADDRESS='100.64.0.2',
                  LEGACY_CONTABO_VPN_CIDR='100.64.0.3/32', LEGACY_RUBASE_VPN_CIDR='100.64.0.4/32')
    values['POWERDNS_API_ACCESS_REVISION'] = revision(values)
    return values


class BridgeRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.objects = build(HERE)

    def test_shared_config_and_reader_reference_stay_original(self):
        cm = generated(self.objects, 'powerdns-config')
        self.assertEqual(cm['data'], {name: (HERE / name).read_text() for name in ('pdns.conf', 'reader.conf', 'api.conf', 'runtime.py')})
        reader = pick(self.objects, 'DaemonSet', 'powerdns-readers')
        volume = next(v for v in reader['spec']['template']['spec']['volumes'] if v['name'] == 'config')
        self.assertEqual(volume['configMap']['name'], cm['metadata']['name'])
        self.assertNotIn('annotations', reader['spec']['template']['metadata'])
        self.assertEqual(reader['spec']['updateStrategy']['type'], 'OnDelete')

    def test_api_config_and_access_revision_are_separate(self):
        cm = generated(self.objects, 'powerdns-api-config')
        self.assertEqual(cm['data'], {'pdns.conf': (HERE / 'pdns.conf').read_text(), 'api.conf': (HERE / 'api-access.conf').read_text(), 'runtime.py': (HERE / 'runtime.py').read_text()})
        api = pick(self.objects, 'Deployment', 'powerdns-api')
        template = api['spec']['template']
        self.assertEqual(template['metadata']['annotations']['infra.shanginn.io/api-access-revision'], '${POWERDNS_API_ACCESS_REVISION}')
        volume = next(v for v in template['spec']['volumes'] if v['name'] == 'config')
        self.assertEqual(volume['configMap']['name'], cm['metadata']['name'])
        self.assertEqual(api['spec']['replicas'], 2)
        self.assertEqual(api['spec']['strategy']['rollingUpdate'], {'maxSurge': 0, 'maxUnavailable': 1})

    def test_bridge_policies_only_exact_source_variables_and_ports(self):
        for name, variables, ports in (
            ('legacy-bridge-readers', ('LEGACY_CONTABO_VPN_CIDR', 'LEGACY_RUBASE_VPN_CIDR'), {(5353, 'UDP'), (5353, 'TCP')}),
            ('legacy-bridge-api', SOURCES + ('LEGACY_RUBASE_VPN_CIDR',), {(8081, 'TCP')}),
        ):
            policy = pick(self.objects, 'NetworkPolicy', name)['spec']
            self.assertEqual(policy['policyTypes'], ['Ingress'])
            self.assertEqual(len(policy['ingress']), 1)
            rule = policy['ingress'][0]
            self.assertEqual(rule['from'], [{'ipBlock': {'cidr': '${' + key + '}'}} for key in variables])
            self.assertEqual({(port['port'], port['protocol']) for port in rule['ports']}, ports)

    def test_private_services_use_only_vpn_entries_and_correct_traffic_policy(self):
        for name, traffic, ports in (
            ('powerdns-legacy-readers', 'Local', {(5354, 5353, 'UDP'), (5354, 5353, 'TCP')}),
            ('powerdns-legacy-api', 'Cluster', {(18081, 8081, 'TCP')}),
        ):
            service = pick(self.objects, 'Service', name)['spec']
            self.assertEqual(service['type'], 'ClusterIP')
            self.assertEqual(service['externalIPs'], ['${MSK_VPN_ADDRESS}', '${FIN_VPN_ADDRESS}'])
            self.assertEqual(service['externalTrafficPolicy'], traffic)
            self.assertEqual(service['internalTrafficPolicy'], traffic)
            self.assertEqual({(port['port'], port['targetPort'], port['protocol']) for port in service['ports']}, ports)
            self.assertTrue(all('nodePort' not in port for port in service['ports']))

    def test_flux_requires_additional_private_source(self):
        objects = list(yaml.safe_load_all((ROOT / 'clusters/unified/flux-system/sync.yaml').read_text()))
        sources = pick(objects, 'Kustomization', 'unified')['spec']['postBuild']['substituteFrom']
        self.assertEqual(sources, [{'kind': 'ConfigMap', 'name': name, 'optional': False} for name in ('unified-network', 'unified-legacy-dns')])

    def test_strict_substitution_preserves_exact_allowlist(self):
        values = validate_values(VALUES if VALUES is not None else example_values())
        text = yaml.safe_dump_all(self.objects, sort_keys=False)
        placeholders = set(re.findall(r'\$\{([A-Z_]+)\}', text))
        self.assertEqual(placeholders, KEYS)
        text = subprocess.check_output(['flux', 'envsubst', '--strict'], input=text, text=True, env={'PATH': os.environ['PATH'], **values})
        self.assertNotIn('${', text)
        objects = list(yaml.safe_load_all(text))
        config = generated(objects, 'powerdns-api-config')['data']['api.conf']
        allow = next(line.split('=', 1)[1] for line in config.splitlines() if line.startswith('webserver-allow-from='))
        self.assertEqual(allow.split(','), ['127.0.0.1', '10.0.0.0/8'] + [values[key] for key in SOURCES])
        policy = pick(objects, 'NetworkPolicy', 'legacy-bridge-api')['spec']
        self.assertEqual(policy['podSelector']['matchLabels'], {
            'app.kubernetes.io/name': 'powerdns', 'app.kubernetes.io/component': 'api',
        })
        admitted = [peer['ipBlock']['cidr'] for peer in policy['ingress'][0]['from']]
        self.assertEqual(admitted, [values[key] for key in SOURCES] + [values['LEGACY_RUBASE_VPN_CIDR']])
        self.assertTrue(all(ipaddress.IPv4Network(value).prefixlen == 32 for value in admitted))
        self.assertNotIn(values['LEGACY_CONTABO_VPN_CIDR'], admitted)
        self.assertNotIn(values['LEGACY_RUBASE_VPN_CIDR'], allow.split(','))

    def test_substitution_contract_rejects_broad_cidr_and_stale_revision(self):
        for key, value in ((SOURCES[0], '10.0.0.0/8'), ('MSK_VPN_ADDRESS', '8.8.8.8'), ('POWERDNS_API_ACCESS_REVISION', '0' * 64)):
            values = example_values()
            values[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_values(values)
        values = example_values()
        del values[SOURCES[0]]
        with self.assertRaises(ValueError):
            validate_values(values)

    def test_approved_baseline_reader_and_original_config_are_unchanged(self):
        if not BASELINE:
            self.skipTest('Supply --baseline-ref for before/after render guard')
        # git archive writes only a reviewed subtree into a fresh local directory.
        with tempfile.TemporaryDirectory(prefix='powerdns-render-baseline-') as folder:
            archive = subprocess.check_output(['git', '-C', str(ROOT), 'archive', BASELINE, 'clusters/unified/powerdns'])
            subprocess.run(['tar', '-xf', '-', '-C', folder], input=archive, check=True)
            before = build(Path(folder) / 'clusters/unified/powerdns')
        self.assertEqual(generated(before, 'powerdns-config'), generated(self.objects, 'powerdns-config'))
        self.assertEqual(pick(before, 'DaemonSet', 'powerdns-readers'), pick(self.objects, 'DaemonSet', 'powerdns-readers'))
        old_api = pick(before, 'Deployment', 'powerdns-api')
        new_api = json.loads(json.dumps(pick(self.objects, 'Deployment', 'powerdns-api')))
        new_api['spec']['template']['metadata'].pop('annotations')
        for volume in new_api['spec']['template']['spec']['volumes']:
            if volume['name'] == 'config':
                volume['configMap']['name'] = generated(before, 'powerdns-config')['metadata']['name']
        self.assertEqual(old_api, new_api)
        for old in before:
            if old['kind'] == 'Deployment' and old['metadata']['name'] == 'powerdns-api':
                continue
            self.assertEqual(old, pick(self.objects, old['kind'], old['metadata']['name']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref', help='Approved Git commit to compare existing reader/API render')
    parser.add_argument('--values', type=Path, help='Private unified-legacy-dns ConfigMap YAML/JSON; values never printed')
    args, remaining = parser.parse_known_args()
    BASELINE = args.baseline_ref
    if args.values:
        obj = yaml.safe_load(args.values.read_text())
        if obj.get('kind') != 'ConfigMap' or obj.get('metadata', {}).get('name') != 'unified-legacy-dns' or obj['metadata'].get('namespace') != 'flux-system':
            parser.error('Expected flux-system/unified-legacy-dns ConfigMap')
        VALUES = validate_values(obj.get('data'))
    unittest.main(argv=[__file__, *remaining])
