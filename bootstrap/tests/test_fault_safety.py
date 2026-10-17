#!/usr/bin/env python3
"""Offline checks for dangerous paths; no SSH, systemd or firewall operations."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fault', Path(__file__).with_name('node-fault.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


def nft_fixture():
    """nft JSON shape; counters are deliberately nonzero."""
    token = 'a' * 32
    table = 'infra_fault_' + token
    comment = 'infra-fault:' + token
    objects = [{'metainfo': {'json_schema_version': 1}},
               {'table': {'family': 'inet', 'name': table, 'handle': 51, 'comment': comment}}]
    for hook, directions in [('input', ['iifname']), ('output', ['oifname']), ('forward', ['iifname', 'oifname'])]:
        objects.append({'chain': {'family': 'inet', 'table': table, 'name': hook, 'handle': len(objects),
                                 'type': 'filter', 'hook': hook, 'prio': -450, 'policy': 'accept'}})
        for direction in directions:
            objects.append({'rule': {'family': 'inet', 'table': table, 'chain': hook, 'handle': len(objects),
                'comment': comment, 'expr': [
                    {'match': {'op': '==', 'left': {'meta': {'key': direction}}, 'right': 'tailscale0'}},
                    {'counter': {'packets': 7, 'bytes': 512}}, {'drop': None}]}})
    return objects


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

    def test_nft_readback_requires_effective_shape(self):
        state = {'token': 'a' * 32}
        proof = f.nft_shape(state, nft_fixture())
        self.assertTrue(proof['valid'])
        self.assertEqual(sum(c['packets'] for c in proof['counters']), 28)
        changes = [
            lambda obj: obj[1]['table'].update(flags=['dormant']),
            lambda obj: obj[2]['chain'].update(prio=0),
            lambda obj: obj[3]['rule']['expr'].__setitem__(2, {'accept': None}),
            lambda obj: obj[3]['rule']['expr'][0]['match'].update(right='eth0'),
            lambda obj: obj.pop(),
            lambda obj: obj.append({'set': {'name': 'unrelated'}}),
        ]
        for change in changes:
            with self.subTest(change=change):
                objects = nft_fixture(); change(objects)
                with self.assertRaises(RuntimeError): f.nft_shape(state, objects)

    def test_nft_foreign_owner_or_replacement_blocks_deletion(self):
        state = {'token': 'a' * 32, 'partition_backend': 'nft-inet-v1', 'partition_table_handle': 51}
        for changed in ({'comment': 'another-owner'}, {'handle': 999}):
            objects = nft_fixture(); objects[1]['table'].update(changed)
            tablelist = {'nftables': [objects[1]]}
            replies = [subprocess.CompletedProcess([], 0, json.dumps(tablelist).encode()),
                       subprocess.CompletedProcess([], 0, json.dumps({'nftables': objects}).encode())]
            with self.subTest(changed=changed), patch.object(f, 'command', side_effect=replies) as run:
                with self.assertRaises(RuntimeError): f.partition(state, remove=True)
                self.assertTrue(all('delete' not in c.args[0] for c in run.call_args_list))

    def test_nft_rollback_removes_owned_table_even_if_rule_damaged(self):
        state = {'token': 'a' * 32, 'partition_backend': 'nft-inet-v1', 'partition_table_handle': 51}
        objects = nft_fixture(); objects.pop()
        with patch.object(f, 'nft_read', side_effect=[objects, None]), patch.object(f, 'command') as run:
            f.partition(state, remove=True)
        run.assert_called_once_with([f.NFT, 'delete', 'table', 'inet', 'handle', '51'], timeout=5)
        self.assertFalse(state['partition_before_rollback']['valid'])

    def test_nft_absent_table_is_idempotent_on_rollback(self):
        with patch.object(f, 'nft_read', return_value=None), patch.object(f, 'command') as run:
            f.partition({'token': 'a' * 32, 'partition_backend': 'nft-inet-v1'}, remove=True)
            run.assert_not_called()

    def test_nft_creation_refuses_collision_without_mutation(self):
        with patch.object(f, 'nft_read', return_value=nft_fixture()), patch.object(f, 'command') as run:
            with self.assertRaises(RuntimeError):
                f.partition({'token': 'a' * 32, 'partition_backend': 'nft-inet-v1'})
            run.assert_not_called()

    def test_nft_preflight_rejects_forward_bypass_and_stale_tables(self):
        for obj in ({'flowtable': {'name': 'fastpath'}}, {'table': {'name': 'infra_fault_previous'}}):
            replies = [subprocess.CompletedProcess([], 0, b'nftables v1.1'),
                       subprocess.CompletedProcess([], 0, json.dumps({'nftables': [obj]}).encode())]
            with self.subTest(obj=obj), patch.object(f, 'command', side_effect=replies) as run:
                with self.assertRaises(RuntimeError): f.nft_preflight({'token': 'a' * 32})
                self.assertEqual(run.call_count, 2)

    def test_nft_batch_cannot_escape_ownership(self):
        for token in ('', 'bad; flush ruleset', 'A' * 32, 'a' * 31):
            with self.subTest(token=token), self.assertRaises(RuntimeError): f.nft_batch({'token': token})
        batch = f.nft_batch({'token': 'a' * 32}).decode()
        self.assertEqual(batch.count('counter drop'), 4)
        self.assertEqual(batch.count('priority -450'), 3)
        self.assertNotIn('flush', batch)
        self.assertNotIn('eth0', batch)

    def test_first_restoration_timestamp_is_retained(self):
        state = {'phase': 'rolled-back', 'kind': 'service-stop', 'unit': 'infra-derper.service', 'rollback_unix': 123.0}
        with patch.object(f, 'command'), patch.object(f, 'atomic'), patch.object(f, 'boot_id', return_value='same'):
            f.rollback(state)
        self.assertEqual(state['rollback_unix'], 123.0)

    def test_status_reports_rule_loss_without_reapplying(self):
        state = {'token': 'a' * 32, 'partition_backend': 'nft-inet-v1', 'phase': 'triggered'}
        unchanged = copy.deepcopy(state)
        with patch.object(f, 'nft_read', return_value=None), patch.object(f, 'boot_id', return_value='boot'), patch.object(f, 'command') as run:
            result = f.status(state)
            run.assert_not_called()
        self.assertFalse(result['partition_observation']['valid'])
        self.assertEqual(state, unchanged)

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
