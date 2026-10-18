#!/usr/bin/env python3
"""Render isolation and private substitution guards; never contact a cluster."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import unittest

import yaml

HERE = Path(__file__).resolve().parent
ADDRESS_KEYS = ('MSK_VPN_ADDRESS', 'FIN_VPN_ADDRESS', 'LEGACY_POWERDNS_DNS_SERVICE_ADDRESS')
REVISION_KEY = 'LEGACY_DNS_PROXY_CONFIG_REVISION'
PRIVATE_RANGES = tuple(ipaddress.IPv4Network(value) for value in
                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))


def config_revision(values):
    addresses = {key: values[key] for key in ADDRESS_KEYS}
    return hashlib.sha256(json.dumps(addresses, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_values(values):
    if not isinstance(values, dict) or set(values) != set(ADDRESS_KEYS) | {REVISION_KEY}:
        raise ValueError('Expected exactly three addresses and their configuration revision')
    for key in ADDRESS_KEYS:
        value = values[key]
        if not isinstance(value, str):
            raise ValueError('Address must be a literal IPv4 string')
        address = ipaddress.IPv4Address(value)
        if not any(address in network for network in PRIVATE_RANGES):
            raise ValueError('Expected an observed private IPv4 address')
    if len({values[key] for key in ADDRESS_KEYS}) != 3:
        raise ValueError('Entry and old DNS Service addresses must be distinct')
    if values[REVISION_KEY] != config_revision(values):
        raise ValueError('Private configuration revision does not match the addresses')
    return values


def build(path):
    rendered = subprocess.check_output(['kubectl', 'kustomize', str(path)], text=True)
    return [obj for obj in yaml.safe_load_all(rendered) if obj]


class ProxyIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.objects = build(HERE)
        cls.by_kind = {obj['kind']: obj for obj in cls.objects}

    def test_preview_cannot_select_or_replace_old_services(self):
        self.assertEqual(sorted(self.by_kind), ['ConfigMap', 'Deployment', 'NetworkPolicy', 'Service'])
        self.assertEqual(len(self.objects), 4)
        for obj in self.objects:
            self.assertEqual(obj['metadata']['namespace'], 'vibesites-dns')
            self.assertTrue(obj['metadata']['name'].startswith('legacy-pdns-api-proxy'))
        service = self.by_kind['Service']['spec']
        selector = {'app.kubernetes.io/name': 'legacy-pdns-api-proxy'}
        self.assertEqual(service['selector'], selector)
        self.assertEqual(service['type'], 'ClusterIP')
        self.assertFalse(set(service) & {'externalIPs', 'externalName', 'loadBalancerIP'})
        self.assertEqual(self.by_kind['Deployment']['spec']['selector']['matchLabels'], selector)
        self.assertEqual({(p['port'], p['protocol']) for p in service['ports']}, {(8081, 'TCP'), (53, 'UDP'), (53, 'TCP')})
        self.assertTrue(all(isinstance(p['targetPort'], str) for p in service['ports']))

    def test_parent_stays_unchanged_and_example_suspended(self):
        for obj in build(HERE.parent):
            self.assertNotIn('legacy-pdns-api-proxy', obj['metadata']['name'])
        example = yaml.safe_load((HERE / 'flux-kustomization.example.yaml').read_text())
        self.assertTrue(example['spec']['suspend'])
        refs = example['spec']['postBuild']['substituteFrom']
        self.assertEqual({r['name'] for r in refs}, {'legacy-dns-network', 'legacy-dns-proxy'})
        self.assertTrue(all(r['optional'] is False for r in refs))

    def test_credentials_and_process_privileges(self):
        template = self.by_kind['Deployment']['spec']['template']
        spec = template['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertTrue(spec['securityContext']['runAsNonRoot'])
        self.assertFalse(spec.get('hostNetwork', False))
        proxy, dns = spec['containers']
        self.assertEqual(proxy['env'], [{'name': 'PDNS_API_KEY', 'valueFrom': {'secretKeyRef': {'name': 'powerdns-api', 'key': 'api-key', 'optional': False}}}])
        for container in (proxy, dns):
            self.assertRegex(container['image'], r'@sha256:[0-9a-f]{64}$')
            self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
            self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
            self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
            self.assertTrue(all('hostPort' not in p for p in container['ports']))
        self.assertEqual(template['metadata']['annotations']['infra.shanginn.io/private-config-revision'], '${' + REVISION_KEY + '}')

    def test_connections_retry_but_received_writes_do_not(self):
        text = self.by_kind['ConfigMap']['data']['haproxy.cfg']
        self.assertEqual(re.findall(r'^\s*retry-on\s+(.+)$', text, re.M), ['conn-failure'])
        self.assertEqual(re.findall(r'^\s*retries\s+(\d+)$', text, re.M), ['1'])
        self.assertIn('http-reuse never', text)
        self.assertIn('option http-server-close', text)
        self.assertNotRegex(text, r'(?m)^\s*(?:log |option httplog|capture |stats socket|http-request set-header)')
        self.assertIn('http-check expect status 200', text)

    def test_network_scope_and_dns_destination(self):
        policy = self.by_kind['NetworkPolicy']['spec']
        api = policy['ingress'][0]
        self.assertEqual(api['ports'], [{'port': 8081, 'protocol': 'TCP'}])
        self.assertEqual(len(api['from']), 2)
        for peer in api['from']:
            self.assertEqual(peer['namespaceSelector']['matchLabels'], {'kubernetes.io/metadata.name': 'vibesites-pi'})
            self.assertIn(peer['podSelector']['matchLabels']['app.kubernetes.io/name'], ['vibesites-pi', 'vibesites-pi-worker'])
        vpn = policy['egress'][0]
        self.assertEqual(vpn['to'], [{'ipBlock': {'cidr': '${MSK_VPN_ADDRESS}/32'}}, {'ipBlock': {'cidr': '${FIN_VPN_ADDRESS}/32'}}])
        self.assertEqual(vpn['ports'], [{'port': 18081, 'protocol': 'TCP'}])
        corefile = self.by_kind['ConfigMap']['data']['Corefile']
        self.assertIn('forward . ${LEGACY_POWERDNS_DNS_SERVICE_ADDRESS}:53', corefile)
        self.assertNotIn('cache', corefile)
        all_text = json.dumps(self.objects)
        self.assertEqual(set(re.findall(r'\$\{([A-Z_]+)\}', all_text)), set(ADDRESS_KEYS) | {REVISION_KEY})

    def test_bad_substitutions_fail_closed(self):
        good = dict(zip(ADDRESS_KEYS, ('100.64.0.1', '100.64.0.2', '10.43.1.1')))
        good[REVISION_KEY] = config_revision(good)
        validate_values(good)
        for bad in ('', '100.64.0.1/32', '100.64.0.1\n', '127.0.0.1', '8.8.8.8', '0.0.0.1', '255.255.255.255', '192.0.2.1', '::1', None):
            values = {**good, ADDRESS_KEYS[0]: bad}
            with self.assertRaises(ValueError):
                validate_values(values)
        for values in ({**good, ADDRESS_KEYS[0]: good[ADDRESS_KEYS[1]]}, {**good, REVISION_KEY: '0' * 64}, {**good, 'EXTRA': 'value'}):
            with self.assertRaises(ValueError):
                validate_values(values)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--values', type=Path)
    args, remaining = parser.parse_known_args()
    if args.values:
        validate_values(json.loads(args.values.read_text()))
    unittest.main(argv=[__file__, *remaining])
