#!/usr/bin/env python3
"""Offline checks for policy defaults, relay loops and bootstrap boundaries."""
import copy
import importlib.util
from pathlib import Path
import unittest

from jinja2 import Environment, StrictUndefined, UndefinedError
import yaml


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('overlay_settings', ROOT / 'files/overlay-settings.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def identity():
    # Synthetic configuration: these public literals are never contacted.
    return {'local_host': 'msk', 'active_host': 'fin', 'server_url': 'https://vpn.example.org',
            'local_ipv4': ['1.1.1.1', '10.254.254.1', '100.100.0.3'],
            'namespace_addresses': ['10.254.254.1/30', '10.254.254.2/30'],
            'tailnet_prefix': '100.100.0.0/24'}


def record():
    return m.make_relay_record('8.8.8.8', **identity())


def routing():
    return {**identity(), 'record': record()}


def template_context(site='msk'):
    return {'inventory_hostname': site, 'headscale_active_host': 'fin',
            'headscale_hostname': 'vpn.example.org',
            'derp_hosts': {'msk': {'hostname': 'derp-msk.example.org'},
                           'fin': {'hostname': 'derp-fin.example.org'}},
            'overlay_ns_service_address': '10.254.254.2/30',
            'overlay_ns_host_address': '10.254.254.1/30',
            'overlay_tls_port': 8443, 'overlay_derp_port': 8444,
            'overlay_acme_port': 8081, 'overlay_headscale_upstream_ipv4': '8.8.8.8',
            'overlay_ingress_backends': {'msk': '100.100.0.3', 'fin': '100.100.0.1'}}


def render(context):
    env = Environment(undefined=StrictUndefined)
    env.filters['difference'] = lambda a, b: [item for item in a if item not in b]
    return env.from_string((ROOT / 'templates/overlay/haproxy.cfg.j2').read_text()).render(context)


class SettingsTests(unittest.TestCase):
    def test_implicit_allow_all_policy_rejected(self):
        for policy in (None, {}, {'tagOwners': {}}, '{}'):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                m.validate_policy(policy)

    def test_explicit_policy_required_even_for_deny_all(self):
        for policy in ({'acls': []}, {'grants': []}, {'acls': [], 'grants': []}):
            self.assertEqual(m.validate_policy(policy), policy)
        for policy in ({'acls': None}, {'grants': {}}, {'acls': [], 'grants': None}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                m.validate_policy(policy)

    def test_policy_retains_declared_rules_without_default_merge(self):
        policy = {'acls': [{'action': 'accept', 'src': ['100.100.0.1'],
                           'dst': ['100.100.0.2:443']}], 'tests': []}
        self.assertIs(m.validate_policy(policy), policy)
        self.assertNotIn('*', str(policy))
        with self.assertRaises(ValueError): m.validate_policy({'acls': [], 'extra': float('nan')})

    def test_saved_relay_resolves_without_requiring_fresh_private_vars(self):
        self.assertEqual(m.resolve_routing(routing()), {'record': record(), 'upstream_ipv4': '8.8.8.8'})

    def test_saved_relay_identity_and_schema_cannot_drift(self):
        mutations = [{'owner': 'unrelated'}, {'format': 2}, {'format': True},
                     {'active_host': 'home'}, {'standby_host': 'fin'},
                     {'server_url': 'https://another.example.org'}, {'upstream_port': 8443},
                     {'upstream_port': '443'}, {'extra': 'unexpected'}]
        for mutation in mutations:
            changed = {**record(), **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.validate_relay_record(changed, **identity())
        missing = record(); del missing['owner']
        with self.assertRaises(ValueError): m.validate_relay_record(missing, **identity())

    def test_relay_rejects_local_private_overlay_reserved_and_dns_targets(self):
        for target in ('1.1.1.1', '127.0.0.1', '10.254.254.2', '100.100.0.1',
                       '192.0.2.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
                       'vpn.example.org', '8.8.8.8:443', '8.8.8.8\n', '::1', None):
            with self.subTest(target=target), self.assertRaises(ValueError):
                m.make_relay_record(target, **identity())

    def test_relay_requires_local_address_inventory_and_namespace_boundaries(self):
        for mutation in ({'local_ipv4': []}, {'local_ipv4': None},
                         {'namespace_addresses': []}, {'tailnet_prefix': '10.0.0.0/8'},
                         {'namespace_addresses': ['8.8.8.9/30', '8.8.8.10/30']}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.validate_relay_record(record(), **{**identity(), **mutation})

    def test_relay_rejects_ambiguous_https_identity(self):
        for url in ('http://vpn.example.org', 'https://vpn.example.org:443',
                    'https://vpn.example.org/path', 'https://user@vpn.example.org',
                    'https://-vpn.example.org', 'https://vpn.example.org\n'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                m.make_relay_record('8.8.8.8', **{**identity(), 'server_url': url})

    def test_active_coordinator_never_uses_a_relay(self):
        settings = {**routing(), 'local_host': 'fin'}
        with self.assertRaises(ValueError): m.resolve_routing(settings)
        settings['record'] = None
        self.assertEqual(m.resolve_routing(settings), {'record': None, 'upstream_ipv4': None})
        with self.assertRaises(ValueError):
            m.validate_relay_record(record(), **{**identity(), 'local_host': 'fin'})

    def test_missing_saved_relay_never_falls_back_or_creates_it_during_maintenance(self):
        settings = {**routing(), 'record': None, 'expected_upstream': '8.8.8.8'}
        for allow in (None, False, 'true', 1):
            settings['allow_initial_record'] = allow
            with self.subTest(allow=allow), self.assertRaises(ValueError): m.resolve_routing(settings)
        settings['allow_initial_record'] = True
        self.assertEqual(m.resolve_routing(settings)['record'], record())
        del settings['expected_upstream']
        with self.assertRaises(ValueError): m.resolve_routing(settings)

    def test_conflicting_override_never_replaces_saved_relay(self):
        settings = {**routing(), 'expected_upstream': '9.9.9.9'}
        before = copy.deepcopy(settings)
        with self.assertRaises(ValueError): m.resolve_routing(settings)
        self.assertEqual(settings, before)
        settings['expected_upstream'] = '8.8.8.8'
        self.assertEqual(m.resolve_routing(settings)['record'], record())

    def test_active_and_standby_templates_preserve_tls_and_other_backends(self):
        active = render(template_context('fin'))
        standby = render(template_context())
        self.assertIn('server coordinator 10.254.254.2:8443 check', active)
        self.assertIn('server coordinator 8.8.8.8:443 check', standby)
        self.assertNotIn('server coordinator 10.254.254.2:8443', standby)
        for result in (active, standby):
            coordinator = next(line.strip() for line in result.splitlines() if 'server coordinator ' in line)
            self.assertNotIn(' ssl', coordinator)  # Original client TLS, no re-encryption.
            self.assertNotIn('send-proxy', coordinator)
            self.assertIn('server derper 10.254.254.2:8444 check source 10.254.254.1', result)
            self.assertIn('default_backend cluster_ingress_tls', result)
        self.assertIn('server msk 100.100.0.3:32443 check port 32080 send-proxy-v2 source 100.100.0.3', standby)

    def test_template_cannot_render_standby_without_checked_upstream(self):
        context = template_context(); del context['overlay_headscale_upstream_ipv4']
        with self.assertRaises(UndefinedError): render(context)
        context['inventory_hostname'] = 'fin'
        self.assertIn('server coordinator 10.254.254.2:8443 check', render(context))

    def test_bootstrap_blocks_owned_installation_before_any_mutation(self):
        play = yaml.safe_load((ROOT / 'overlay.yml').read_text())[0]
        before = play['pre_tasks']
        self.assertIn('ansible.builtin.stat', before[0])
        guard = before[1]
        self.assertEqual(guard['ansible.builtin.assert']['that'], ['not overlay_marker_stat.stat.exists'])
        self.assertNotIn('when', guard)
        self.assertNotIn('tags', guard)
        policy = next(t for t in play['tasks'] if t.get('ansible.builtin.copy', {}).get('dest') == '{{ overlay_root }}/policy.json')
        self.assertEqual(policy['ansible.builtin.copy']['content'], '{{ headscale_policy | to_nice_json }}\n')
        self.assertNotIn('default(', policy['ansible.builtin.copy']['content'])

    def test_every_router_caller_has_readonly_routing_preflight(self):
        for file in ('overlay.yml', 'ingress-edge.yml'):
            plays = yaml.safe_load((ROOT / file).read_text())
            earliest = plays[0].get('pre_tasks', []) + plays[0].get('tasks', [])
            self.assertTrue(any(t.get('ansible.builtin.include_tasks') == 'tasks/overlay-routing.yml' for t in earliest))
        tasks = yaml.safe_load((ROOT / 'tasks/overlay-routing.yml').read_text())
        for task in tasks:
            self.assertFalse(any(key in task for key in ('ansible.builtin.copy', 'ansible.builtin.template',
                                                        'ansible.builtin.systemd_service')))


if __name__ == '__main__':
    unittest.main()
