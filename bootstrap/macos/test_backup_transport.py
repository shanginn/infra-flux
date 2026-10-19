"""Transport and uncertain-restore regressions; no SSH or backup repository I/O."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


b = load('backup_transport_subject', 'backup.py')
v = load('postgres_transport_subject', 'verify-postgres.py')


class Transport(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.sql = self.root / 'input.sql'
        self.sql.write_bytes(b'SELECT 1;')
        self.sql.chmod(0o600)
        self.metadata = {'sql_bytes': self.sql.stat().st_size, 'sql_sha256': 'a' * 64}

    def tearDown(self):
        self.temporary.cleanup()

    def test_rejects_options_shell_text_wrong_types_and_loops(self):
        for chain in (None, 'gateway,relay', ['-F'], ['user@host'], ['host:22'],
                      ['$(command)'], ['a,b'], ['a b'], ['a\nb'], ['a', 'a'],
                      ['homelab-vpn'], ['a', 'b', 'c', 'd'], [1]):
            with self.subTest(chain=chain), self.assertRaises(RuntimeError):
                b.ssh_jump_options(chain, 'homelab-vpn')
        self.assertEqual(b.ssh_jump_options([], 'home'), [])
        self.assertEqual(b.ssh_jump_options(['gateway', 'relay'], 'home'), ['-J', 'gateway,relay'])

    def test_restore_override_rejected_for_other_components(self):
        job = {'component': 'node-config', 'ssh_aliases': ['home'], 'restore_ssh_jump_chain': []}
        with self.assertRaises(RuntimeError):
            b.validate_jump_chains([job])

    def test_export_keeps_destination_and_hostkey_policy(self):
        job = {'component': 'node-config', 'ssh_aliases': ['homelab-vpn'], 'max_bytes': 1024,
               'ssh_jump_chain': ['gateway', 'relay']}
        process = unittest.mock.MagicMock()
        process.__enter__.return_value.stdout = io.BytesIO(b'bounded stream')
        process.__enter__.return_value.wait.return_value = 0
        with patch.object(b.subprocess, 'Popen', return_value=process) as call, \
                patch.object(b.sys, 'stdout', types.SimpleNamespace(buffer=io.BytesIO())):
            b.export(job, 'homelab-vpn')
        args = call.call_args.args[0]
        self.assertEqual(args[-2], 'homelab-vpn')
        self.assertEqual(args[args.index('-J') + 1], 'gateway,relay')
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertNotIn('-S', args)
        self.assertNotIn('HostKeyAlias=', ' '.join(args[:-1]))

    def test_restore_keeps_reviewed_host_identity_and_has_no_retry(self):
        proof = {'restore_completed': True, 'pg_amcheck_completed': True, 'scratch_removed': True,
                 'sql_sha256': self.metadata['sql_sha256']}
        with patch.object(v.subprocess, 'run', return_value=types.SimpleNamespace(
                returncode=0, stdout=json.dumps(proof).encode())) as call:
            self.assertEqual(v.verify_restore(self.metadata, self.sql, 'homelab-vpn',
                                             ssh_jump_chain=['gateway', 'relay']), proof)
        args = call.call_args.args[0]
        self.assertEqual(args[-2], 'homelab-vpn')
        self.assertEqual(args[args.index('-J') + 1], 'gateway,relay')
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertEqual(call.call_count, 1)
        with patch.object(v.subprocess, 'run') as call:
            with self.assertRaises(RuntimeError):
                v.verify_restore(self.metadata, self.sql, 'different-host', ssh_jump_chain=['gateway'])
            with self.assertRaises(RuntimeError):
                v.verify_restore(self.metadata, self.sql, 'homelab-vpn', ssh_jump_chain=['-F'])
            call.assert_not_called()

    def test_default_restore_route_unchanged(self):
        proof = {'restore_completed': True, 'pg_amcheck_completed': True, 'scratch_removed': True,
                 'sql_sha256': self.metadata['sql_sha256']}
        with patch.object(v.subprocess, 'run', return_value=types.SimpleNamespace(
                returncode=0, stdout=json.dumps(proof).encode())) as call:
            v.verify_restore(self.metadata, self.sql, 'homelab-vpn')
        self.assertNotIn('-J', call.call_args.args[0])

    def test_overlay_alias_keeps_home_restore_and_strict_hostkey_checks(self):
        proof = {'restore_completed': True, 'pg_amcheck_completed': True, 'scratch_removed': True,
                 'sql_sha256': self.metadata['sql_sha256']}
        with patch.object(v.subprocess, 'run', return_value=types.SimpleNamespace(
                returncode=0, stdout=json.dumps(proof).encode())) as call:
            self.assertEqual(v.verify_restore(self.metadata, self.sql, 'homelab-overlay',
                                             ssh_jump_chain=['gateway', 'relay']), proof)
        args = call.call_args.args[0]
        self.assertEqual(args[-2], 'homelab-overlay')
        self.assertEqual(args[args.index('-J') + 1], 'gateway,relay')
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn("marker['node_name']=='home'", v.REMOTE_RESTORE)
        self.assertIn("marker['ca_sha256']==expected['ca_sha256']", v.REMOTE_RESTORE)
        self.assertEqual(call.call_count, 1)

    def test_overlay_failure_is_not_retried_and_alias_variants_are_rejected(self):
        with patch.object(v.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh',4260)) as call:
            with self.assertRaises(subprocess.TimeoutExpired):
                v.verify_restore(self.metadata,self.sql,'homelab-overlay')
            self.assertEqual(call.call_count,1)
        with patch.object(v.subprocess, 'run') as call:
            for alias in ('homelab-overlay-2','root@homelab-overlay','homelab-overlay -o StrictHostKeyChecking=no'):
                with self.subTest(alias=alias), self.assertRaises(RuntimeError):
                    v.verify_restore(self.metadata,self.sql,alias)
            with self.assertRaises(RuntimeError):
                v.verify_restore(self.metadata,self.sql,'homelab-overlay',ssh_jump_chain=['homelab-overlay'])
            call.assert_not_called()

    def test_backup_passes_restore_chain_separately_from_export(self):
        job = {'name': 'pg', 'component': 'postgres', 'max_bytes': 1024, 'cluster_name': 'test',
               'restore_ssh_alias': 'homelab-vpn', 'restore_ssh_jump_chain': ['gateway', 'relay']}
        module = types.SimpleNamespace(read_stream=lambda *args: self.metadata,
                                       verify_restore=unittest.mock.Mock(return_value={'verified': True}))
        process = unittest.mock.MagicMock()
        process.__enter__.return_value.wait.return_value = 0
        with patch.object(b, 'STATE', self.root), patch.object(b, 'load_exporter', return_value=module), \
                patch.object(b.subprocess, 'Popen', return_value=process):
            b.verify_large({'restic': 'restic'}, job, 'snapshot', {})
        self.assertEqual(module.verify_restore.call_args.kwargs, {'ssh_jump_chain': ['gateway', 'relay']})

    def job(self):
        return {'name': 'pg', 'component': 'postgres', 'ssh_aliases': ['first', 'second']}

    def test_export_failure_can_use_next_source(self):
        responses = [RuntimeError('source unavailable'),
                     types.SimpleNamespace(stdout=b'{"message_type":"summary","snapshot_id":"pending"}\n'),
                     types.SimpleNamespace(stdout=b'{"message_type":"changed","new_snapshot_id":"verified"}\n')]
        with patch.object(b, 'restic', side_effect=responses) as call, \
                patch.object(b, 'verify', return_value={'restore_completed': True}) as verify:
            outcome = b.backup_job({'_path': '/fixture.json'}, self.job())
        self.assertEqual(outcome['source'], 'second')
        self.assertEqual(call.call_count, 3)
        self.assertEqual(verify.call_count, 1)

    def test_uncertain_or_failed_restore_never_retries_other_source_or_tags_verified(self):
        for error in (subprocess.TimeoutExpired('ssh', 4260), RuntimeError('restore unconfirmed')):
            with self.subTest(error=type(error).__name__), patch.object(b, 'restic', return_value=types.SimpleNamespace(
                    stdout=b'{"message_type":"summary","snapshot_id":"pending"}\n')) as call, \
                    patch.object(b, 'verify', side_effect=error) as verify:
                with self.assertRaises(type(error)):
                    b.backup_job({'_path': '/fixture.json'}, self.job())
                self.assertEqual(call.call_count, 1)
                self.assertEqual(verify.call_count, 1)

    def test_installer_rejects_bad_chain_before_writing_configuration(self):
        with patch.dict(sys.modules, {'backup': b}):
            installer = load('transport_installer', 'install.py')
        source = self.root / 'config.json'
        source.write_text(json.dumps({'jobs': [{'component': 'node-config', 'ssh_aliases': ['home'],
                                               'ssh_jump_chain': ['bad,host']}]}))
        responses = [types.SimpleNamespace(stdout='restic 0.19.1 test'),
                     types.SimpleNamespace(stdout='--stdin-from-command')]
        with patch.object(sys, 'argv', ['install.py', '--config', str(source)]), \
                patch.object(installer.sys, 'platform', 'darwin'), patch.object(installer.os, 'geteuid', return_value=501), \
                patch.object(installer.shutil, 'which', return_value='/fixture/restic'), \
                patch.object(installer.subprocess, 'run', side_effect=responses), patch.object(installer, 'atomic_json') as write:
            with self.assertRaises(RuntimeError):
                installer.main()
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
