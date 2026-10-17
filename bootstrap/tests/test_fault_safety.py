#!/usr/bin/env python3
"""Offline checks for dangerous paths; no SSH, systemd or firewall operations."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fault', Path(__file__).with_name('node-fault.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


class SafetyTests(unittest.TestCase):
    def test_vpn_ssh_route_is_rejected(self):
        with patch.dict(f.os.environ, {'SSH_CONNECTION': '100.64.0.1 1 100.64.0.2 22'}), patch.object(f, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps([{'dev': 'tailscale0'}]).encode())):
            with self.assertRaises(RuntimeError): f.ssh_path_safe()

    def test_original_wireguard_route_is_accepted(self):
        with patch.dict(f.os.environ, {'SSH_CONNECTION': '10.1.0.1 1 10.1.0.2 22'}), patch.object(f, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps([{'dev': 'wg0'}]).encode())):
            self.assertEqual(f.ssh_path_safe(), 'wg0')

    def test_rollback_only_deletes_exact_owned_rules(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b'')
        with patch.object(f, 'command', side_effect=run):
            f.partition({'token': 'a'*32, 'firewalls': ['/usr/sbin/iptables', '/usr/sbin/ip6tables']}, remove=True)
        self.assertEqual(sum('-D' in c for c in calls), 8)
        for c in calls:
            self.assertNotIn('-F', c)
            self.assertIn('tailscale0', c)
            self.assertIn('infra-fault:' + 'a'*32, c)

    def test_delayed_timer_does_not_reopen_finished_test(self):
        state = {'phase': 'finished'}
        with patch.object(f, 'command') as run, patch.object(f, 'atomic') as save:
            self.assertIs(f.rollback(state), state)
            run.assert_not_called(); save.assert_not_called()

    def test_existing_global_fault_is_not_replaced(self):
        existing = {'metadata': {'annotations': {f.ANNOTATION: f.OWNER}}, 'data': {'phase': 'active', 'token': 'old'}}
        with patch.object(f, 'ensure_namespace'), patch.object(f, 'kube', return_value=json.dumps(existing).encode()) as kube:
            with self.assertRaises(RuntimeError): f.acquire_global({'token': 'new', 'node': 'home', 'kind': 'reboot'})
            self.assertEqual(kube.call_count, 1)

    def test_recovery_failure_does_not_release_global_lock(self):
        state = {'ca_sha256': 'test'}
        with patch.object(f, 'rollback', return_value=state), patch.object(f, 'recovery_gate', side_effect=RuntimeError('replica not recovered')), patch.object(f, 'require_global') as current, patch.object(f, 'kube') as kube:
            with self.assertRaises(RuntimeError): f.finish(state)
            current.assert_not_called(); kube.assert_not_called()


if __name__ == '__main__': unittest.main()
