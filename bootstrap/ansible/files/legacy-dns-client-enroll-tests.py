#!/usr/bin/env python3
"""Offline safety tests: no server, package manager or service manager calls."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('enroll', Path(__file__).with_name('legacy-dns-client-enroll.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def record(phase='staged'):
    return {'phase': phase, 'operation': 'test-operation', 'deadline': 2000,
            'hostname': 'legacy-test', 'server_url': 'https://vpn.example.org',
            'guard': {'machine_id_sha256': 'machine'}, 'baseline': {'network': {}, 'firewall': {}},
            'node': {'ID': 'node-1', 'PublicKey': 'nodekey:test', 'TailscaleIPs': ['100.96.0.8'], 'Tags': []}}


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = []
        self.fake = types.SimpleNamespace(
            output=Mock(side_effect=lambda argv, **kw: self.events.append(('command', argv)) or ''),
            service=Mock(return_value={'MainPID': '0', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}),
            inactive_never_started=Mock(), sync_directory=Mock(),
            secure_directory=Mock(), secure_regular=Mock(), no_client_process=Mock(),
            DROP=self.root / 'preparation.conf', DROP_CONTENT='[Unit]\nConditionPathExists=/absent\n')
        self.patch('p', self.fake, create=True)
        self.patch('RUNTIME', self.root / 'runtime')
        self.patch('KEY', self.root / 'runtime' / 'key')
        self.patch('HOSTS', self.root / 'hosts')
        self.patch('assert_files', Mock(side_effect=lambda *a, **k: self.events.append(('files', k))))
        self.patch('timer_armed', Mock(side_effect=lambda *a, **k: self.events.append(('timer', None))))
        self.patch('daemon_owned', Mock(return_value={'MainPID': '42'}))
        self.patch('assert_protected', Mock())
        self.patch('baseline_for', Mock(return_value={'network': {}, 'firewall': {}}))
        self.patch('no_network_remnants', Mock())
        self.patch('save', Mock(side_effect=lambda r: self.events.append(('saved', r['phase']))))
        self.patch('disarm', Mock(side_effect=lambda: self.events.append(('disarm', None))))
        self.patch('atomic', Mock(side_effect=self.write))

    def patch(self, name, value, **kwargs):
        context = patch.object(m, name, value, **kwargs)
        context.start(); self.addCleanup(context.stop)

    def write(self, path, data, *args):
        self.events.append(('write', path.name))
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)

    def test_stage_arms_durable_timer_before_owned_hosts_change_and_keeps_gate(self):
        for name in ('RECORD', 'CONFIG', 'DROP', 'HELPER', 'PREPARE'):
            self.patch(name, self.root / name.lower())
        self.patch('DIRECTORY', self.root)
        self.patch('UNIT_DIR', self.root)
        m.HELPER.write_text('enrollment source')
        m.PREPARE.write_text('preparation source')
        self.fake.STATE = self.root / 'prepared.json'
        self.fake.STATE.write_text('owned preparation')
        self.fake.DROP.write_text(self.fake.DROP_CONTENT)
        m.HOSTS.write_bytes(b'127.0.0.1 localhost\n')
        hosts_identity = lambda: {'sha256': m.sha(m.HOSTS.read_bytes()), 'mode': 0o644, 'uid': 0, 'gid': 0, 'link': None}
        baseline = {'machine_id_sha256': 'machine', 'boot_id': 'boot', 'os': {}, 'arch': 'amd64',
                    'services': {}, 'hosts': hosts_identity(), 'resolver': {}, 'other_packages_sha256': 'packages',
                    'network': {'admin_address': '192.0.2.9', 'admin_route': {}}, 'firewall': {}}
        self.fake.read_state = Mock(return_value={'phase': 'verified', 'baseline': baseline})
        self.fake.verify_prepared = Mock(side_effect=lambda: self.events.append(('prepared', True)))
        self.fake.baseline = Mock(return_value=baseline)
        self.fake.paths_absent = Mock()
        self.fake.file_identity = Mock(side_effect=lambda path: hosts_identity())
        def output(argv, **kw):
            self.events.append(('command', argv))
            return 'not-found\n' if '--property=LoadState' in argv else ''
        self.fake.output.side_effect = output
        settings = {'operation': 'stage-test', 'rollback_seconds': 600,
                    'prepare_receipt_sha256': m.sha(self.fake.STATE.read_bytes()),
                    'admin_address': '192.0.2.9', 'expected_guard': m.guard(baseline),
                    'server_url': 'https://vpn.example.org', 'hostname': 'legacy-example',
                    'coordinator_evidence_sha256': 'a' * 64, 'relay_ipv4': '1.1.1.1'}
        result = m.stage(settings)
        self.assertEqual(result['phase'], 'staged')
        self.assertTrue(self.fake.DROP.exists())
        intent = self.events.index(('saved', 'stage-intent'))
        config = self.events.index(('write', m.CONFIG.name))
        timer = self.events.index(('command', ['systemctl', 'enable', '--now', m.UNIT + '.timer']))
        hosts = self.events.index(('write', m.HOSTS.name))
        self.assertLess(intent, config)
        self.assertLess(timer, hosts)
        self.assertFalse(any(e == ('command', ['systemctl', 'start', 'tailscaled.service']) for e in self.events))

    def test_interrupted_stage_is_not_replaced_by_another_operation(self):
        self.patch('RECORD', self.root / 'operation.json')
        m.RECORD.write_text('{"phase":"stage-intent"}')
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            m.stage({'operation': 'a-new-operation'})
        self.fake.output.assert_not_called()

    def test_start_persists_intent_before_gate_removal_or_start(self):
        self.fake.DROP.write_text(self.fake.DROP_CONTENT)
        self.patch('client_check', Mock(return_value={'state': 'NeedsLogin'}))
        result = m.start(record(), {})
        self.assertEqual(result['phase'], 'needs-login')
        start = self.events.index(('command', ['systemctl', 'start', 'tailscaled.service']))
        self.assertLess(self.events.index(('saved', 'start-intent')), start)
        self.assertFalse(self.fake.DROP.exists())
        self.assertFalse(any(e[0] == 'command' and 'enable' in e[1] for e in self.events))

    def test_uncertain_start_is_never_replayed(self):
        with self.assertRaisesRegex(RuntimeError, 'single-use'):
            m.start(record('start-intent'), {})
        self.fake.output.assert_not_called()

    def test_wrong_first_state_leaves_intent_and_timer(self):
        self.fake.DROP.write_text(self.fake.DROP_CONTENT)
        self.patch('client_check', Mock(side_effect=RuntimeError('Unexpected client login state')))
        r = record()
        with self.assertRaises(RuntimeError):
            m.start(r, {})
        self.assertEqual(r['phase'], 'start-intent')
        m.disarm.assert_not_called()

    def test_registration_key_erased_after_command_failure(self):
        self.patch('client_check', Mock(return_value={'state': 'NeedsLogin'}))
        self.fake.output.side_effect = RuntimeError('Command failed')
        r = record('needs-login')
        with self.assertRaisesRegex(RuntimeError, 'Command failed'):
            m.register(r, {'auth_key': 'test-secret-key-0000000000000000'})
        self.assertEqual(r['phase'], 'register-intent')
        self.assertFalse(m.KEY.exists())
        self.assertFalse(m.RUNTIME.exists())
        self.assertNotIn('test-secret', json.dumps(r))
        m.disarm.assert_not_called()

    def test_registration_refuses_preexisting_key_directory(self):
        self.patch('client_check', Mock(return_value={'state': 'NeedsLogin'}))
        m.RUNTIME.mkdir()
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            m.register(record('needs-login'), {'auth_key': 'test-secret-key-0000000000000000'})
        self.fake.output.assert_not_called()

    def test_registration_refuses_boot_enable_before_confirmation(self):
        self.fake.service.return_value['UnitFileState'] = 'enabled'
        with self.assertRaisesRegex(RuntimeError, 'enabled before'):
            m.register(record('needs-login'), {'auth_key': 'test-secret-key-0000000000000000'})
        self.assertFalse(m.RUNTIME.exists())

    def test_rollback_restores_gate_before_stop_and_retains_state(self):
        self.patch('guard', Mock(return_value={'machine_id_sha256': 'machine'}))
        r = record('register-intent')
        result = m.rollback(r)
        gate = self.events.index(('write', self.fake.DROP.name))
        stop = self.events.index(('command', ['systemctl', 'stop', 'tailscaled.service']))
        self.assertLess(gate, stop)
        self.assertTrue(result['state_retained'])
        self.assertEqual(r['phase'], 'rolled-back')
        m.assert_protected.assert_not_called()
        self.assertTrue(self.fake.DROP.exists())

    def test_rollback_ownership_failure_never_stops_foreign_daemon(self):
        m.daemon_owned.side_effect = RuntimeError('Client process executable differs')
        with self.assertRaises(RuntimeError):
            m.rollback(record('registered'))
        self.assertTrue(self.fake.DROP.exists())
        self.assertFalse(any(e == ('command', ['systemctl', 'stop', 'tailscaled.service']) for e in self.events))

    def test_rollback_relay_not_appended_finishes_without_rewriting_hosts(self):
        self.patch('guard', Mock(return_value={'machine_id_sha256': 'machine'}))
        before = b'127.0.0.1 localhost\n192.0.2.2 unrelated\n'
        m.HOSTS.write_bytes(before)
        r = record('stage-intent')
        r['hosts_line'] = '1.1.1.1 vpn.example.org # infra-flux legacy-dns coordinator relay\n'
        self.assertEqual(m.rollback(r)['phase'], 'rolled-back')
        self.assertEqual(m.HOSTS.read_bytes(), before)
        self.assertNotIn(('write', m.HOSTS.name), self.events)

    def test_rollback_relay_already_removed_finishes_after_interrupted_cleanup(self):
        self.patch('guard', Mock(return_value={'machine_id_sha256': 'machine'}))
        unrelated = b'127.0.0.1 localhost\n192.0.2.3 changed-by-another-service\n'
        m.HOSTS.write_bytes(unrelated)
        r = record('rollback-intent')
        r['hosts_line'] = '1.1.1.1 vpn.example.org # infra-flux legacy-dns coordinator relay\n'
        self.assertEqual(m.rollback(r)['phase'], 'rolled-back')
        self.assertEqual(m.HOSTS.read_bytes(), unrelated)
        self.assertNotIn(('write', m.HOSTS.name), self.events)

    def test_duplicate_owned_relay_refuses_cleanup_after_containing_daemon(self):
        line = '1.1.1.1 vpn.example.org # infra-flux legacy-dns coordinator relay\n'
        before = b'127.0.0.1 localhost\n' + line.encode() * 2
        m.HOSTS.write_bytes(before)
        r = record('registered'); r['hosts_line'] = line
        with self.assertRaisesRegex(RuntimeError, 'duplicated'):
            m.rollback(r)
        self.assertTrue(self.fake.DROP.exists())
        self.assertIn(('command', ['systemctl', 'stop', 'tailscaled.service']), self.events)
        self.assertEqual(m.HOSTS.read_bytes(), before)
        self.assertEqual(r['phase'], 'rollback-intent')
        m.disarm.assert_not_called()

    def test_rollback_after_confirmation_is_noop(self):
        result = m.rollback(record('confirmed'))
        self.assertFalse(result['changed'])
        m.assert_files.assert_not_called()
        self.fake.output.assert_not_called()

    def test_confirm_node_mismatch_never_enables(self):
        self.patch('client_check', Mock(return_value=record()['node']))
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            m.confirm(record('registered'), {'expected_node': {}})
        self.fake.output.assert_not_called()

    def test_confirm_requires_coordinator_key_revocation(self):
        self.patch('client_check', Mock(return_value=record()['node']))
        with self.assertRaisesRegex(RuntimeError, 'Expire'):
            m.confirm(record('registered'), {'expected_node': record()['node'],
                      'external_evidence_sha256': 'a' * 64, 'key_expired': False})
        self.fake.output.assert_not_called()

    def test_confirm_deadline_race_retains_intent_for_rollback(self):
        self.patch('client_check', Mock(return_value=record()['node']))
        self.fake.service.return_value['UnitFileState'] = 'enabled'
        m.timer_armed.side_effect = [None, RuntimeError('Enrollment deadline expired')]
        r = record('registered')
        with self.assertRaisesRegex(RuntimeError, 'expired'):
            m.confirm(r, {'expected_node': r['node'], 'external_evidence_sha256': 'a' * 64, 'key_expired': True})
        self.assertEqual(r['phase'], 'confirm-intent')
        m.disarm.assert_not_called()

    def test_confirm_persists_before_disarming_waiting_rollback(self):
        self.patch('client_check', Mock(return_value=record()['node']))
        self.fake.service.return_value['UnitFileState'] = 'enabled'
        r = record('registered')
        m.confirm(r, {'expected_node': r['node'], 'external_evidence_sha256': 'a' * 64, 'key_expired': True})
        self.assertLess(self.events.index(('saved', 'confirmed')), self.events.index(('disarm', None)))
        self.assertFalse(m.rollback(r)['changed'])


class PureGuardsTests(unittest.TestCase):
    def test_rollback_rechecks_disappeared_pid_but_never_identity_mismatch(self):
        with patch.object(m, '_daemon_owned_once', side_effect=[FileNotFoundError(), {'MainPID': '0'}]) as check, \
                patch.object(m.time, 'sleep'):
            self.assertEqual(m.daemon_owned(record(), allow_inactive=True), {'MainPID': '0'})
            self.assertEqual(check.call_count, 2)
        for exception, rollback in ((RuntimeError('wrong executable'), True), (FileNotFoundError(), False)):
            with patch.object(m, '_daemon_owned_once', side_effect=exception) as check, self.assertRaises(type(exception)):
                m.daemon_owned(record(), allow_inactive=rollback)
            self.assertEqual(check.call_count, 1)

    def test_rollback_process_reread_is_bounded(self):
        with patch.object(m, '_daemon_owned_once', side_effect=FileNotFoundError()) as check, \
                patch.object(m.time, 'sleep'), self.assertRaises(FileNotFoundError):
            m.daemon_owned(record(), allow_inactive=True)
        self.assertEqual(check.call_count, 3)

    def test_owned_auto_restart_without_pid_can_be_stopped_only_by_rollback(self):
        service = {'MainPID': '0', 'ActiveState': 'activating', 'SubState': 'auto-restart'}
        fake = types.SimpleNamespace(service=Mock(return_value=service))
        with patch.object(m, 'p', fake, create=True):
            self.assertEqual(m.daemon_owned(record(), allow_inactive=True), service)
            with self.assertRaisesRegex(RuntimeError, 'not active'):
                m.daemon_owned(record())
            service['SubState'] = 'start'
            with self.assertRaisesRegex(RuntimeError, 'Unexpected inactive'):
                m.daemon_owned(record(), allow_inactive=True)

    def test_owned_notify_start_can_be_stopped_but_never_treated_as_ready(self):
        service = {'MainPID': '42', 'ActiveState': 'activating', 'SubState': 'start'}
        fake = types.SimpleNamespace(service=Mock(return_value=service))
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / '42'; proc.mkdir()
            (proc / 'exe').symlink_to('/usr/sbin/tailscaled')
            args = [b'/usr/sbin/tailscaled', b'--config=' + str(m.CONFIG).encode(),
                    b'--state=/var/lib/tailscale/tailscaled.state', b'--socket=/run/tailscale/tailscaled.sock']
            (proc / 'cmdline').write_bytes(b'\0'.join(args) + b'\0')
            with patch.object(m, 'p', fake, create=True), patch.object(m, 'PROC', Path(directory)):
                self.assertEqual(m.daemon_owned(record(), allow_inactive=True), service)
                with self.assertRaisesRegex(RuntimeError, 'not active'):
                    m.daemon_owned(record())
                (proc / 'cmdline').write_bytes(b'/usr/sbin/tailscaled\0--config=/foreign\0')
                with self.assertRaisesRegex(RuntimeError, 'configuration differs'):
                    m.daemon_owned(record(), allow_inactive=True)

    def test_startup_config_is_keyless_and_explicit(self):
        c = m.config_for({'server_url': 'https://vpn.example.org', 'hostname': 'legacy-example'})
        self.assertNotIn('authKey', c)
        self.assertEqual(c['netfilterMode'], 'off')
        for key in ('acceptDNS', 'acceptRoutes', 'advertiseExitNode', 'runSSHServer', 'runWebClient', 'remoteConfig'):
            self.assertIs(c[key], False)
        self.assertTrue(c['enabled'])

    def test_cloud_and_url_credentials_refused(self):
        for url in ('http://vpn.example.org', 'https://user:secret@vpn.example.org',
                    'https://controlplane.tailscale.com', 'https://vpn.example.org/path'):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                m.config_for({'server_url': url, 'hostname': 'legacy-example'})

    def test_hosts_removal_preserves_concurrent_unrelated_changes(self):
        before = b'127.0.0.1 localhost\n'
        after, line = m.hosts_append(before, 'vpn.example.org', '1.1.1.1')
        self.assertEqual(m.hosts_remove(after + b'192.0.2.2 other\n', line), before + b'192.0.2.2 other\n')

    def test_absent_owned_line_leaves_hosts_bytes_unchanged(self):
        current = b'127.0.0.1 localhost\n192.0.2.2 other\n'
        self.assertEqual(m.hosts_remove(current, b'absent owned line\n'), current)

    def test_hosts_duplicate_and_competing_alias_refused(self):
        for before in (b'127.0.0.1 localhost VPN.EXAMPLE.ORG\n', b'127.0.0.1 localhost'):
            with self.assertRaises(RuntimeError):
                m.hosts_append(before, 'vpn.example.org', '1.1.1.1')
        with self.assertRaises(RuntimeError):
            m.hosts_remove(b'line\nline\n', b'line\n')

    def test_persistent_deadline_has_explicit_operation(self):
        values = m.unit_contents(record())
        timer = next(v for k, v in values.items() if k.suffix == '.timer')
        service = next(v for k, v in values.items() if k.suffix == '.service')
        self.assertIn(b'Persistent=true', timer)
        self.assertIn(b'OnCalendar=1970-01-01 00:33:20 UTC', timer)
        self.assertIn(b'rollback test-operation', service)

    def test_register_arguments_never_contain_key_or_reset(self):
        args = m.up_arguments(record())
        self.assertIn('--auth-key=file:' + str(m.KEY), args)
        self.assertNotIn('--reset', args)
        self.assertNotIn('--force-reauth', args)
        self.assertIn('--netfilter-mode=off', args)

    def test_preferences_accept_omitted_empty_operator_but_refuse_dns(self):
        r = record()
        prefs = {'ControlURL': r['server_url'], 'Hostname': r['hostname'], 'CorpDNS': False,
                 'RouteAll': False, 'NetfilterMode': 0, 'RunSSH': False, 'RunWebClient': False,
                 'RemoteConfig': False, 'WantRunning': True, 'ExitNodeIP': ''}
        fake = types.SimpleNamespace(output=Mock(side_effect=[json.dumps({'BackendState': 'NeedsLogin'}), json.dumps(prefs)]))
        with patch.object(m, 'p', fake, create=True), patch.object(m, 'no_firewall_remnants'):
            self.assertEqual(m.client_check(r, 'NeedsLogin'), {'state': 'NeedsLogin'})
        prefs['CorpDNS'] = True
        fake.output.side_effect = [json.dumps({'BackendState': 'NeedsLogin'}), json.dumps(prefs)]
        with patch.object(m, 'p', fake, create=True), self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            m.client_check(r, 'NeedsLogin')

    def test_transient_backend_wait_never_repeats_start(self):
        r = record()
        prefs = {'ControlURL': r['server_url'], 'Hostname': r['hostname'], 'CorpDNS': False,
                 'RouteAll': False, 'NetfilterMode': 0, 'RunSSH': False, 'RunWebClient': False,
                 'RemoteConfig': False, 'WantRunning': True}
        fake = types.SimpleNamespace(output=Mock(side_effect=[
            json.dumps({'BackendState': 'Starting'}), json.dumps({'BackendState': 'NeedsLogin'}), json.dumps(prefs)]))
        with patch.object(m, 'p', fake, create=True), patch.object(m, 'no_firewall_remnants'), patch.object(m.time, 'sleep'):
            self.assertEqual(m.client_check(r, 'NeedsLogin'), {'state': 'NeedsLogin'})
        self.assertTrue(all(call.args[0][0] == '/usr/bin/tailscale' for call in fake.output.call_args_list))

    def test_transient_backend_wait_has_deadline(self):
        fake = types.SimpleNamespace(output=Mock(return_value=json.dumps({'BackendState': 'Starting'})))
        with patch.object(m, 'p', fake, create=True), patch.object(m.time, 'monotonic', side_effect=[10, 31]), \
                self.assertRaisesRegex(RuntimeError, 'login state'):
            m.client_check(record(), 'NeedsLogin')

    def test_expired_timer_does_not_require_peer_connectivity(self):
        with patch.object(m.time, 'time', return_value=2001), self.assertRaisesRegex(RuntimeError, 'expired'):
            m.timer_armed(record())


if __name__ == '__main__':
    unittest.main()
