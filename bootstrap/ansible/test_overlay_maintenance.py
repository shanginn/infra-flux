#!/usr/bin/env python3
"""Offline regression checks for bounded VPN changes; no SSH or systemd calls."""
import base64
import copy
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'overlay_maintenance_subject', Path(__file__).parent / 'files/overlay-maintenance.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

CORE = ['100.100.0.1', '100.100.0.2', '100.100.0.3']
EDGES = [CORE[0], CORE[2]]
SERVICE = {'ActiveState': 'active', 'MainPID': '123', 'ExecMainStartTimestampMonotonic': '456',
           'config_sha256': 'c' * 64}
NODES = [{'id': i, 'name': 'k8s-' + name, 'ips': [address], 'user': 1}
         for i, (name, address) in enumerate(zip(['fin', 'home', 'msk'], CORE), 1)]


def policy():
    rules = [{'action': 'accept', 'src': CORE[:], 'dst': [a + ':*' for a in CORE]}]
    for tag, protocol, port in [('reader', 'udp', 5354), ('reader', 'tcp', 5354), ('writer', 'tcp', 18081)]:
        rules.append({'action': 'accept', 'src': ['tag:legacy-pdns-' + tag], 'proto': protocol,
                      'dst': [a + ':' + str(port) for a in EDGES]})
    return {'tagOwners': {'tag:legacy-pdns-reader': ['infra@'], 'tag:legacy-pdns-writer': ['infra@']},
            'acls': rules, 'tests': [{'src': CORE[0], 'accept': [CORE[1] + ':6443']}]}


class RelayTests(unittest.TestCase):
    BEFORE = (b'# reviewed edge configuration\nfrontend public_tls\n'
              b'    bind :443\n    default_backend cluster_ingress_tls\n\n'
              b'backend derp\n    server derper 10.254.254.2:8444 check source 10.254.254.1\n\n'
              b'backend headscale\n    mode tcp\n    server coordinator 10.254.254.2:8443 check\n\n'
              b'backend cluster_ingress_tls\n    mode tcp\n'
              b'    server msk 100.100.0.3:32443 check port 32080 send-proxy-v2\n')

    def test_only_coordinator_address_changes_other_bytes_are_preserved(self):
        result = m.relay_config(self.BEFORE, '10.254.254.2', '8.8.8.8')
        expected = self.BEFORE.replace(b'    server coordinator 10.254.254.2:8443 check\n',
                                       b'    server coordinator 8.8.8.8:443 check\n')
        self.assertEqual(result, expected)
        self.assertEqual(result.count(b'server coordinator '), 1)

    def test_ambiguous_absent_commented_and_wrong_backend_matches_rejected(self):
        old = b'    server coordinator 10.254.254.2:8443 check\n'
        variants = [self.BEFORE.replace(old, b''), self.BEFORE.replace(old, old + old),
                    self.BEFORE.replace(b'backend headscale\n', b'backend other\n'),
                    self.BEFORE.replace(old, b'#' + old),
                    self.BEFORE + b'backend headscale\n    mode tcp\n',
                    self.BEFORE.replace(old, old + b'    server extra 9.9.9.9:443 check\n'),
                    self.BEFORE.replace(old, b'    server coordinator 9.9.9.9:443 check\n') + old,
                    self.BEFORE.replace(b'\n', b'\r\n')]
        for before in variants:
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                m.relay_config(before, '10.254.254.2', '8.8.8.8')


class PolicyTests(unittest.TestCase):
    def test_exact_mesh_and_two_identical_edges_are_accepted_without_mutation(self):
        value = policy(); before = copy.deepcopy(value)
        self.assertEqual(m.policy_shape(value, CORE), EDGES)
        self.assertEqual(value, before)

    def test_privilege_broadening_or_loss_of_core_mesh_is_rejected(self):
        mutations = [lambda p: p.update(grants=[]),
                     lambda p: p['tagOwners'].update({'tag:legacy-pdns-reader': ['*']}),
                     lambda p: p['acls'][0].update(src=['*']),
                     lambda p: p['acls'][0].update(dst=['*:*']),
                     lambda p: p['acls'][0].update(proto='tcp'),
                     lambda p: p['acls'][0]['src'].pop(),
                     lambda p: p['acls'].append(copy.deepcopy(p['acls'][0])),
                     lambda p: p['acls'][1].update(proto='tcp'),
                     lambda p: p['acls'][3].update(proto='udp'),
                     lambda p: p['acls'][1].update(src=['tag:legacy-pdns-writer']),
                     lambda p: p['acls'][3].update(dst=[a + ':5432' for a in EDGES]),
                     lambda p: p['acls'][1].update(dst=['*:5354', EDGES[1] + ':5354']),
                     lambda p: p['acls'][1].update(dst=[EDGES[0] + ':5354'] * 2),
                     lambda p: p['acls'][1]['dst'].append(CORE[1] + ':5354'),
                     lambda p: p['acls'][2].update(dst=[CORE[0] + ':5354', CORE[1] + ':5354']),
                     lambda p: p.update(tests=[])]
        for i, mutate in enumerate(mutations):
            value = policy(); mutate(value)
            with self.subTest(mutation=i), self.assertRaises(RuntimeError):
                m.policy_shape(value, CORE)

    def test_offline_existing_node_is_identity_stable_but_not_apply_ready(self):
        rows = [{'id': n['id'], 'given_name': n['name'], 'ip_addresses': n['ips'],
                 'user': {'id': n['user']}, 'online': n['id'] != 2} for n in NODES]
        with patch.object(m, 'command', return_value=json.dumps(rows).encode()):
            self.assertEqual(m.hs_nodes(require_online=False), NODES)
            with self.assertRaises(RuntimeError): m.hs_nodes()
        rows.append(copy.deepcopy(rows[0]))
        with patch.object(m, 'command', return_value=json.dumps(rows).encode()), self.assertRaises(RuntimeError):
            m.hs_nodes(require_online=False)


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.root = self.directory / 'operations'; self.root.mkdir()
        self.overlay = self.directory / 'overlay'; self.overlay.mkdir()
        self.paths = {'policy': self.overlay / 'policy.json', 'relay': self.overlay / 'haproxy.cfg'}
        self.stack.enter_context(patch.object(m, 'ROOT', self.root))
        self.stack.enter_context(patch.object(m, 'OVERLAY', self.overlay))
        self.stack.enter_context(patch.object(m, 'PATHS', self.paths))
        # File ownership checks belong to trusted(); these fixtures are regular
        # user-owned temporary files, while real atomic write/fsync paths run.
        self.stack.enter_context(patch.object(m, 'trusted', side_effect=lambda p, private=False: p.read_bytes()))
        self.command = self.stack.enter_context(patch.object(m, 'command', side_effect=AssertionError('Unexpected external command')))
        self.reload = self.stack.enter_context(patch.object(m, 'reload'))
        self.service = self.stack.enter_context(patch.object(m, 'service', return_value=SERVICE.copy()))
        self.nodes = self.stack.enter_context(patch.object(m, 'hs_nodes', return_value=copy.deepcopy(NODES)))
        self.stack.enter_context(patch.object(m, 'identity', return_value={'coordinator': True}))
        self.health = self.stack.enter_context(patch.object(m, 'health', return_value=CORE[:]))
        self.tls = self.stack.enter_context(patch.object(m, 'tls_health'))

    def record(self, kind='policy', phase='applied'):
        before, after = b'original reviewed configuration\n', b'candidate reviewed configuration\n'
        value = {'owner': m.OWNER, 'id': 'a' * 32, 'kind': kind, 'node': 'fin', 'phase': phase,
                 'cluster_uid': 'fixture-cluster', 'ca_sha256': 'b' * 64, 'service': SERVICE.copy(),
                 'before': base64.b64encode(before).decode(), 'before_sha256': m.sha(before),
                 'after': base64.b64encode(after).decode(), 'after_sha256': m.sha(after),
                 'vpn_nodes': copy.deepcopy(NODES)}
        if kind == 'relay':
            value.update(relay_record=base64.b64encode(b'{"fixture":"owned"}\n').decode(), server_host='vpn.example.org')
            (self.overlay / 'coordinator-relay.json').write_bytes(base64.b64decode(value['relay_record']))
        self.paths[kind].write_bytes(after)
        m.save(value)
        return value

    def confirm_settings(self, record):
        return {'operation': record['id'], 'node': record['node'], 'cluster_uid': record['cluster_uid'],
                'ca_sha256': record['ca_sha256'], 'expected_after_sha256': record['after_sha256']}

    def test_rollback_restores_only_reviewed_bytes_and_persists_completion(self):
        record = self.record()
        result = m.rollback(record)
        self.assertEqual(result, {'phase': 'rolled-back', 'changed': True})
        self.assertEqual(self.paths['policy'].read_bytes(), base64.b64decode(record['before']))
        self.assertEqual(self.paths['policy'].stat().st_mode & 0o777, 0o644)
        self.assertEqual(m.load(record['id'])['phase'], 'rolled-back')
        self.nodes.assert_called_once_with(require_online=False)
        self.reload.assert_called_once_with('policy')

    def test_rollback_preserves_independent_configuration_edit(self):
        record = self.record(); self.paths['policy'].write_bytes(b'independent edit')
        with self.assertRaises(RuntimeError): m.rollback(record)
        self.assertEqual(self.paths['policy'].read_bytes(), b'independent edit')
        self.assertEqual(m.load(record['id'])['phase'], 'applied')
        self.reload.assert_not_called()

    def test_rollback_never_restores_broad_policy_after_membership_drift(self):
        record = self.record()
        changed = copy.deepcopy(NODES); changed[1]['id'] = 99
        self.nodes.return_value = changed
        with self.assertRaises(RuntimeError): m.rollback(record)
        self.assertEqual(self.paths['policy'].read_bytes(), base64.b64decode(record['after']))
        self.assertEqual(m.load(record['id'])['phase'], 'applied')
        self.reload.assert_not_called()

    def test_restarted_service_is_not_reloaded_or_rolled_back_automatically(self):
        record = self.record(); self.service.return_value = {**SERVICE, 'ExecMainStartTimestampMonotonic': '999'}
        with self.assertRaises(RuntimeError): m.rollback(record)
        self.assertEqual(self.paths['policy'].read_bytes(), base64.b64decode(record['after']))
        self.assertEqual(m.load(record['id'])['phase'], 'applied')
        self.reload.assert_not_called()

    def test_terminal_rollback_is_noop_even_when_live_access_is_unavailable(self):
        for phase in ('confirmed', 'rolled-back'):
            with self.subTest(phase=phase), patch.object(m, 'trusted', side_effect=AssertionError('No live inspection expected')):
                self.assertEqual(m.rollback({'phase': phase}), {'phase': phase, 'changed': False})
        self.nodes.assert_not_called(); self.service.assert_not_called(); self.reload.assert_not_called()

    def test_relay_rollback_removes_only_its_own_marker(self):
        record = self.record('relay')
        self.assertTrue(m.rollback(record)['changed'])
        self.assertFalse((self.overlay / 'coordinator-relay.json').exists())
        self.nodes.assert_not_called()
        record = self.record('relay'); marker = self.overlay / 'coordinator-relay.json'
        marker.write_bytes(b'unrelated record'); self.reload.reset_mock()
        with self.assertRaises(RuntimeError): m.rollback(record)
        self.assertEqual(marker.read_bytes(), b'unrelated record')
        self.assertEqual(self.paths['relay'].read_bytes(), base64.b64decode(record['after']))
        self.reload.assert_not_called()

    def test_operation_identity_and_corrupted_recovery_content_are_rejected(self):
        record = self.record()
        for fields in ({'owner': 'unrelated'}, {'id': 'c' * 32}, {'kind': 'other'},
                       {'before_sha256': '0' * 64}, {'after': record['after'] + '!!'}):
            altered = {**record, **fields}
            m.atomic(m.record_path(record['id']), m.canonical(altered))
            with self.subTest(fields=fields), self.assertRaises((RuntimeError, ValueError)):
                m.load(record['id'])
        with self.assertRaises(RuntimeError): m.record_path('../other')

    def test_confirm_is_durable_before_timer_cancellation(self):
        record = self.record(); events = []; actual_save = m.save
        def save(value):
            actual_save(value); events.append(('saved', value['phase']))
        def command(argv, *args, **kwargs):
            self.assertEqual(argv, ['systemctl', 'stop', 'infra-overlay-rollback-' + record['id'] + '.timer'])
            self.assertEqual(m.load(record['id'])['phase'], 'confirmed')
            events.append(('timer', 'stop')); return b''
        self.command.side_effect = command
        with patch.object(m, 'save', side_effect=save):
            self.assertEqual(m.confirm(self.confirm_settings(record))['phase'], 'confirmed')
        self.assertEqual(events, [('saved', 'confirmed'), ('timer', 'stop')])
        self.assertIn('confirmed_at', m.load(record['id']))

    def test_failed_confirmation_save_leaves_timer_armed_and_record_unconfirmed(self):
        record = self.record()
        with patch.object(m, 'save', side_effect=OSError('disk full')), self.assertRaises(OSError):
            m.confirm(self.confirm_settings(record))
        self.command.assert_not_called()
        self.assertEqual(m.load(record['id'])['phase'], 'applied')

    def test_timer_cancel_failure_cannot_undo_a_durably_confirmed_change(self):
        record = self.record(); self.command.side_effect = RuntimeError('systemd unavailable')
        with self.assertRaises(RuntimeError): m.confirm(self.confirm_settings(record))
        persisted = m.load(record['id'])
        self.assertEqual(persisted['phase'], 'confirmed')
        self.assertEqual(m.rollback(persisted), {'phase': 'confirmed', 'changed': False})
        self.assertEqual(self.paths['policy'].read_bytes(), base64.b64decode(record['after']))
        self.reload.assert_not_called()

    def test_unhealthy_cluster_or_changed_membership_cannot_confirm(self):
        record = self.record()
        self.health.side_effect = RuntimeError('unhealthy')
        with self.assertRaises(RuntimeError): m.confirm(self.confirm_settings(record))
        self.health.side_effect = None; self.nodes.return_value = []
        with self.assertRaises(RuntimeError): m.confirm(self.confirm_settings(record))
        self.command.assert_not_called()
        self.assertEqual(m.load(record['id'])['phase'], 'applied')

    def test_confirm_rechecks_config_after_health_checks(self):
        record = self.record()
        def health(node):
            self.paths['policy'].write_bytes(b'changed during health check')
            return CORE
        self.health.side_effect = health
        with self.assertRaises(RuntimeError): m.confirm(self.confirm_settings(record))
        self.command.assert_not_called()
        self.assertEqual(m.load(record['id'])['phase'], 'applied')
        self.assertEqual(self.paths['policy'].read_bytes(), b'changed during health check')

    def test_relay_confirm_rechecks_marker_after_tls_health(self):
        record = self.record('relay'); marker = self.overlay / 'coordinator-relay.json'
        self.tls.side_effect = lambda *args: marker.write_bytes(b'changed marker')
        with self.assertRaises(RuntimeError): m.confirm(self.confirm_settings(record))
        self.command.assert_not_called()
        self.assertEqual(m.load(record['id'])['phase'], 'applied')
        self.assertEqual(marker.read_bytes(), b'changed marker')

    def apply_fixture(self):
        before = b'{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}\n'
        self.paths['policy'].write_bytes(before); (self.overlay / 'active-coordinator').touch()
        helper = self.directory / 'helper.py'; helper.write_bytes(b'reviewed helper')
        settings_file = self.directory / 'settings.py'; settings_file.write_bytes(b'reviewed settings')
        self.stack.enter_context(patch.object(m, 'HELPER', helper))
        self.stack.enter_context(patch.object(m, 'SETTINGS', settings_file))
        self.stack.enter_context(patch.object(m, 'module', return_value=types.SimpleNamespace(validate_policy=lambda value: value)))
        settings = {'kind': 'policy', 'node': 'fin', 'cluster_uid': 'fixture-cluster', 'ca_sha256': 'b' * 64,
                    'helper_sha256': m.sha(helper.read_bytes()), 'settings_sha256': m.sha(settings_file.read_bytes()),
                    'expected_headscale_config_sha256': SERVICE['config_sha256'],
                    'expected_before_sha256': m.sha(before), 'policy': policy()}
        def command(argv, payload=None, **kwargs):
            if argv[:len(m.KUBE)] == m.KUBE:
                return json.dumps({'items': [{'metadata': {'name': name}, 'status': {'addresses': [
                    {'type': 'InternalIP', 'address': address}]}} for name, address in zip(['fin','home','msk'], CORE)]}).encode()
            if argv[:len(m.HS)] == m.HS:
                self.assertEqual(argv[len(m.HS):], ['policy', 'check', '--file', '/dev/stdin'])
                self.assertEqual(json.loads(payload), settings['policy']); return b'Policy is valid\n'
            if argv[0] == 'systemd-run': return b''
            if argv[:2] == ['systemctl', 'is-active']: return b'active\n'
            raise AssertionError('Unexpected command: ' + repr(argv))
        self.command.side_effect = command
        return settings, command

    def test_apply_requires_active_timer_before_replacing_configuration(self):
        settings, normal = self.apply_fixture(); before = self.paths['policy'].read_bytes()
        def command(argv, payload=None, **kwargs):
            if argv[:2] == ['systemctl', 'is-active']: return b'inactive\n'
            return normal(argv, payload, **kwargs)
        self.command.side_effect = command
        with self.assertRaises(RuntimeError): m.apply(settings)
        self.assertEqual(self.paths['policy'].read_bytes(), before)
        self.reload.assert_not_called()

    def test_apply_persists_armed_state_before_reload_then_records_applied(self):
        settings, normal = self.apply_fixture(); events = []
        def command(argv, payload=None, **kwargs):
            if argv[0] == 'systemd-run':
                saved = json.loads(next(self.root.glob('*.json')).read_text())
                self.assertEqual(saved['phase'], 'prepared')
                self.assertEqual(m.sha(self.paths['policy'].read_bytes()), settings['expected_before_sha256'])
                events.append('timer-created')
            if argv[:2] == ['systemctl', 'is-active']: events.append('timer-active')
            return normal(argv, payload, **kwargs)
        def reload(kind):
            saved = json.loads(next(self.root.glob('*.json')).read_text())
            self.assertEqual(saved['phase'], 'armed')
            self.assertEqual(self.paths[kind].read_bytes(), m.canonical(settings['policy']))
            self.assertEqual(events, ['timer-created', 'timer-active'])
            events.append('reload')
        self.command.side_effect = command; self.reload.side_effect = reload
        result = m.apply(settings)
        self.assertEqual(result['phase'], 'applied')
        self.assertEqual(m.load(result['operation'])['phase'], 'applied')
        self.assertEqual(events, ['timer-created', 'timer-active', 'reload'])

    def test_apply_cas_preserves_edit_between_validation_and_replacement(self):
        settings, normal = self.apply_fixture()
        def command(argv, payload=None, **kwargs):
            if argv[:2] == ['systemctl', 'is-active']:
                self.paths['policy'].write_bytes(b'independent edit after validation')
            return normal(argv, payload, **kwargs)
        self.command.side_effect = command
        with self.assertRaises(RuntimeError): m.apply(settings)
        self.assertEqual(self.paths['policy'].read_bytes(), b'independent edit after validation')
        self.reload.assert_not_called()

    def test_apply_rejects_home_as_legacy_edge_before_arming_timer(self):
        settings, normal = self.apply_fixture()
        for rule in settings['policy']['acls'][1:]:
            rule['dst'] = [entry.replace(CORE[2], CORE[1]) for entry in rule['dst']]
        with self.assertRaises(RuntimeError): m.apply(settings)
        self.assertFalse(any(call.args[0][0] == 'systemd-run' for call in self.command.call_args_list))
        self.reload.assert_not_called()


if __name__ == '__main__':
    unittest.main()
