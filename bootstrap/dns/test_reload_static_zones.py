import copy
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('reload_static', Path(__file__).with_name('reload-static-zones.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def guard():
    files = {f'zone{i}.test': 'a' * 64 for i in range(20)}
    files.update({'vibesites.ru': 'b' * 64, 'vibesites.rf': 'c' * 64})
    return {'version': 1, 'cluster_uid': 'cluster-uid', 'deployment_uid': 'deployment-uid',
            'template_sha256': 'd' * 64, 'pod_name': 'bind9-pod', 'pod_uid': 'pod-uid',
            'container_id': 'containerd://' + 'e' * 64, 'restarts': 0, 'pid_start': '100',
            'configmap_uid': 'cm-uid', 'configmap_resource_version': '123',
            'config_sha256': {name: 'f' * 64 for name in m.CONFIG_FILES}, 'zone_sha256': files,
            'zones': [{'name': 'example.test', 'file': 'zone0.test', 'before_serial': 4, 'expected_serial': 5}]}


def soa(serial):
    return ('ns.example.test.', 'hostmaster.example.test.', str(serial), '10', '20', '30', '40')


class FakeRemote(m.Remote):
    def __init__(self, g):
        super().__init__('kubectl', g)
        self.sent = 0
        self.bad_identity = False
        self.bad_content = False
        self.dynamic_after = 4

    def identity(self):
        m.require(not self.bad_identity, 'Pod identity changed')
        return {}

    def content(self, volumes):
        m.require(not self.bad_content, 'Projected zone data differs')
        return {'example.test': {}, 'vibesites.ru': {}}

    def soas(self, names):
        return {n: soa((5 if self.sent else 4) if n == 'example.test' else (self.dynamic_after if self.sent else 4)) for n in names}

    def signal(self):
        m.require(not self.signal_attempted, 'A signal was already attempted')
        self.signal_attempted = True
        self.sent += 1


class GuardTests(unittest.TestCase):
    def test_valid_guard(self):
        self.assertEqual(m.validate_guard(guard())['version'], 1)

    def test_known_dynamic_name_or_file_rejected(self):
        for field, value in [('name', 'vibesites.ru'), ('name', 'xn--80aacc0bc7ayl4g.xn--p1ai'), ('file', 'vibesites.rf')]:
            with self.subTest(field=field, value=value):
                g = guard(); g['zones'][0][field] = value
                with self.assertRaisesRegex(RuntimeError, 'Dynamic'):
                    m.validate_guard(g)

    def test_incomplete_or_invalid_guard_rejected(self):
        changes = [('template_sha256', 'x'), ('restarts', True), ('pid_start', '100;kill'),
                   ('container_id', 'containerd://x'), ('zone_sha256', {'zone0.test': 'a' * 64}),
                   ('config_sha256', {'named.conf': 'a' * 64})]
        for field, value in changes:
            with self.subTest(field=field):
                g = guard(); g[field] = value
                with self.assertRaises(RuntimeError): m.validate_guard(g)

    def test_duplicate_targets_and_json_keys_rejected(self):
        g = guard(); g['zones'] *= 2
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'): m.validate_guard(g)
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'): m.parse_json('{"a":1,"a":2}')

    def test_serial_wrap_and_regression(self):
        g = guard(); g['zones'][0].update(before_serial=2**32 - 1, expected_serial=0)
        m.validate_guard(g)
        for expected in (4, 3, 4 + 2**31):
            g = guard(); g['zones'][0]['expected_serial'] = expected
            with self.assertRaisesRegex(RuntimeError, 'advance'): m.validate_guard(g)

    def test_path_traversal_rejected(self):
        g = guard(); g['zone_sha256']['../outside'] = g['zone_sha256'].pop('zone0.test')
        with self.assertRaisesRegex(RuntimeError, 'filename'): m.validate_guard(g)

    def test_actual_configuration_maps_static_and_dynamic(self):
        source = Path(__file__).resolve().parents[2] / 'components/bind9/base/configs/named.conf.local'
        declarations = m.zone_declarations(source.read_text())
        self.assertEqual(sum(d['static'] for d in declarations.values()), 20)
        self.assertEqual(declarations['shanginn.io']['file'], '/etc/bind/zones/shanginn.io')
        for name in m.DYNAMIC: self.assertFalse(declarations[name]['static'])

    def test_unknown_include_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'Nested'):
            m.zone_declarations('include "other.conf";')

    def test_soa_requires_authoritative_response_not_query_echo(self):
        answer = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\n;; flags: qr aa; QUERY: 1, ANSWER: 1;\nexample.test. 300 IN SOA ns.example.test. hostmaster.example.test. 4 10 20 30 40\n'
        self.assertEqual(m.parse_soa(answer, 'example.test')[2], '4')
        for bad in (answer.replace('qr aa', 'rd'), answer.replace('qr aa', 'qr aa ra'), answer.replace('NOERROR', 'REFUSED'), answer + answer.splitlines()[-1] + '\n'):
            with self.assertRaises(RuntimeError): m.parse_soa(bad, 'example.test')

    def test_private_input_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guard.json'; path.write_text(json.dumps(guard())); path.chmod(0o600)
            self.assertEqual(m.private_json(path), guard())
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'private'): m.private_json(path)


class OperationTests(unittest.TestCase):
    def test_remote_bootstrap_preserves_shell_sensitive_source_and_arguments(self):
        value = 'single\' double" backslash\\ dollar$(false) backtick`false`\nUnicode: имя'
        source = 'import json,sys\nprint(json.dumps({' + repr('value') + ':' + repr(value) + ',"args":sys.argv[1:]}))\n'
        for profile, execute in [('kubectl', False), ('minikube', True)]:
            with self.subTest(profile=profile, execute=execute):
                command = m.remote_command(source, profile, execute)
                self.assertNotIn('\n', command)
                self.assertNotIn('$(false)', command)
                self.assertNotIn('`false`', command)
                self.assertNotIn('\\', command)
                tokens = shlex.split(command)
                self.assertEqual(tokens[:2], ['python3', '-c'])
                expected = ['--remote', '--profile', profile] + (['--execute'] if execute else [])
                self.assertEqual(tokens[3:], expected)
                result = subprocess.run([sys.executable] + tokens[1:], capture_output=True, text=True, check=True)
                self.assertEqual(json.loads(result.stdout), {'value': value, 'args': expected})

    def test_remote_bootstrap_refuses_shell_in_profile(self):
        with self.assertRaisesRegex(RuntimeError, 'profile'):
            m.remote_command('pass', 'kubectl; false', False)

    def test_check_only_never_sends_signal(self):
        remote = FakeRemote(guard())
        self.assertEqual(remote.run(False)['state'], 'validated')
        self.assertEqual(remote.sent, 0)

    def test_identity_or_content_failure_never_sends_signal(self):
        for attr in ('bad_identity', 'bad_content'):
            remote = FakeRemote(guard()); setattr(remote, attr, True)
            with self.assertRaises(RuntimeError): remote.run(True)
            self.assertEqual(remote.sent, 0)

    def test_changed_prior_serial_never_sends_signal(self):
        g = guard(); g['zones'][0]['before_serial'] = 3
        remote = FakeRemote(g)
        with self.assertRaisesRegex(RuntimeError, 'prior serial'): remote.run(True)
        self.assertEqual(remote.sent, 0)

    def test_success_sends_exactly_one_signal(self):
        remote = FakeRemote(guard())
        self.assertEqual(remote.run(True)['state'], 'verified')
        self.assertEqual(remote.sent, 1)

    def test_non_target_dynamic_change_detected_without_retry(self):
        remote = FakeRemote(guard()); remote.dynamic_after = 6
        with self.assertRaisesRegex(RuntimeError, 'Non-target SOA'): remote.run(True)
        self.assertEqual(remote.sent, 1)

    def test_uncertain_signal_cannot_be_repeated(self):
        remote = m.Remote('kubectl', guard())
        calls = []
        def failing(args):
            calls.append(args)
            raise RuntimeError('timeout')
        remote.inside = failing
        with self.assertRaisesRegex(RuntimeError, 'timeout'): remote.signal()
        with self.assertRaisesRegex(RuntimeError, 'already attempted'): remote.signal()
        self.assertEqual(len(calls), 1)
        self.assertTrue(remote.signal_attempted)
        self.assertTrue(calls[0][-1].endswith('kill -HUP 1'))
        self.assertIn('sha256sum /etc/bind/zones/zone0.test', calls[0][-1])

    def test_target_success_does_not_hide_other_zone_change(self):
        before = {'example.test': soa(4), 'other.test': soa(6)}
        after = {'example.test': soa(5), 'other.test': soa(7)}
        with self.assertRaisesRegex(RuntimeError, 'Non-target'): m.verify_after(before, after, guard()['zones'])


if __name__ == '__main__':
    unittest.main()
