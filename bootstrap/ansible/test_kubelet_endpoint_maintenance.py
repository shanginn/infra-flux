#!/usr/bin/env python3
"""Offline negative fixtures; no remote calls or host configuration reads."""
import argparse
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

BASE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('kubelet_maintenance', BASE / 'files/kubelet-endpoint-maintenance.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.load_common((BASE / 'files/etcd-probe-maintenance.py').read_text())
CA = m.sha(b'fixture-ca')
RAW = b'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: Zml4dHVyZS1jYQ==\n    server: https://192.0.2.1:6443\n  name: unified\n'


def config():
    return {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'node',
            'clusters': [{'name': 'unified', 'cluster': {'server': 'https://192.0.2.1:6443', 'certificate-authority-data': base64.b64encode(b'fixture-ca').decode()}}],
            'users': [{'name': 'kubelet', 'user': {'client-certificate': m.CERT, 'client-key': m.CERT}}],
            'contexts': [{'name': 'node', 'context': {'cluster': 'unified', 'user': 'kubelet'}}]}


def record():
    return {'phase': 'config-written', 'kubelet_before': {'pid': 123, 'start_ticks': 10, 'start_monotonic_us': 100},
            'lease_before': {'uid': 'lease-uid', 'renew_time': '2026-10-17T17:00:00Z'},
            'workloads_before': {'container': {'pid': 456, 'start_ticks': 20}}, 'dispatch_unix': 1792256401,
            'owner': m.OWNER, 'node': 'home', 'token': 'a'*32}


def recovery():
    return ({'pid': 124, 'start_ticks': 30, 'start_monotonic_us': 300},
            {'uid': 'lease-uid', 'renew_time': '2026-10-17T17:00:03Z'}, {'container': {'pid': 456, 'start_ticks': 20}})


class SafetyTests(unittest.TestCase):
    def test_common_source_pin_rejects_any_drift(self):
        with self.assertRaises(RuntimeError): m.load_common((BASE / 'files/etcd-probe-maintenance.py').read_text() + '\n')

    def test_patch_preserves_every_other_byte(self):
        before = config(); after = copy.deepcopy(before); after['clusters'][0]['cluster']['server'] = m.ENDPOINT
        with patch.object(m, 'decode', return_value=after): result = m.patch_config(RAW, before, CA)
        self.assertEqual(result, RAW.replace(b'https://192.0.2.1:6443', m.ENDPOINT.encode()))

    def test_duplicate_or_quoted_server_scalar_is_rejected(self):
        for raw in [RAW+RAW, RAW.replace(b'https://192.0.2.1:6443', b'"https://192.0.2.1:6443"')]:
            with self.subTest(raw=raw), self.assertRaises(RuntimeError): m.patch_config(raw, config(), CA)

    def test_semantic_difference_outside_endpoint_is_rejected(self):
        candidate = config(); candidate['clusters'][0]['cluster']['server'] = m.ENDPOINT
        candidate['users'][0]['user']['client-key'] = '/foreign'
        with patch.object(m, 'decode', return_value=candidate), self.assertRaises(RuntimeError): m.patch_config(RAW, config(), CA)

    def test_wrong_ca_context_or_credentials_rejected(self):
        mutations = [lambda x: x['clusters'][0]['cluster'].update({'insecure-skip-tls-verify': True}),
                     lambda x: x['clusters'][0]['cluster'].update({'certificate-authority-data': 'eA=='}),
                     lambda x: x['users'][0]['user'].update({'exec': {'command': '/foreign'}}),
                     lambda x: x['users'][0]['user'].update({'client-key': '/foreign'}),
                     lambda x: x.update({'current-context': 'foreign'}),
                     lambda x: x['contexts'][0]['context'].update({'user': 'foreign'})]
        for mutate in mutations:
            obj = config(); mutate(obj)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): m.config_shape(obj, CA)

    def test_restart_intent_durable_before_exact_bounded_dispatch(self):
        state = record(); operations = []
        with patch.object(m, 'kubelet_process', return_value=state['kubelet_before']), patch.object(m.common, 'save_record', side_effect=lambda r: operations.append(('save', r['phase']))), patch.object(m, 'command', side_effect=lambda a, **kw: operations.append(('command', a, kw))):
            m.restart_once(state)
        self.assertEqual(operations[0], ('save', 'restart-intent'))
        self.assertEqual(operations[1], ('command', ['/usr/bin/systemctl', '--no-block', 'restart', 'kubelet.service'], {'timeout': 8}))

    def test_unknown_dispatch_never_restarts_on_resume(self):
        state = record()
        with patch.object(m, 'kubelet_process', return_value=state['kubelet_before']), patch.object(m.common, 'save_record'), patch.object(m, 'command', side_effect=subprocess.TimeoutExpired('systemctl', 8)) as dispatch:
            m.restart_once(state); m.restart_once(state)
        self.assertEqual(dispatch.call_count, 1); self.assertEqual(state['dispatch_status'], 'unknown')

    def test_already_changed_process_blocks_restart(self):
        state = record()
        with patch.object(m, 'kubelet_process', return_value={'pid': 999}), patch.object(m, 'command') as dispatch, self.assertRaises(RuntimeError):
            m.restart_once(state)
        dispatch.assert_not_called()

    def test_same_pid_or_stale_lease_or_replaced_lease_rejected(self):
        state = record(); process, lease, workloads = recovery()
        m.validate_recovery(state, process, lease, workloads)
        cases = [(state['kubelet_before'], lease, workloads), (process, state['lease_before'], workloads),
                 (process, {**lease, 'uid': 'new-lease'}, workloads)]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(RuntimeError): m.validate_recovery(state, *values)

    def test_requires_renewal_after_first_observed_new_process(self):
        state = record(); process, lease, workloads = recovery()
        state.update(observed_new_process=process, observed_new_lease=lease)
        with self.assertRaises(RuntimeError): m.validate_recovery(state, process, lease, workloads)
        m.validate_recovery(state, process, {**lease, 'renew_time': '2026-10-17T17:00:13Z'}, workloads)
        with self.assertRaises(RuntimeError): m.validate_recovery(state, {**process, 'pid': 500}, {**lease, 'renew_time': '2026-10-17T17:00:13Z'}, workloads)

    def test_changed_or_missing_workload_pid_rejected(self):
        state = record(); process, lease, workloads = recovery()
        for values in ({}, {'container': {'pid': 999, 'start_ticks': 20}}, {'container': {'pid': 456, 'start_ticks': 21}}):
            with self.subTest(values=values), self.assertRaises(RuntimeError): m.validate_recovery(state, process, lease, values)

    def test_wrong_preimage_prevents_all_writes_or_health(self):
        args = argparse.Namespace(node='home', ca_sha256='c'*64, expected_sha256='f'*64)
        with patch.object(m, 'inspect', return_value=({'config_sha256': 'a'*64}, b'old', b'new', b'marker', None)), patch.object(m, 'health') as health, patch.object(m.common, 'atomic') as write:
            with self.assertRaises(RuntimeError): m.apply(args)
            health.assert_not_called(); write.assert_not_called()

    def test_active_foreign_lock_never_overwritten(self):
        lock = {'metadata': {'annotations': {m.common.ANNOTATION: m.common.FAULT_OWNER}}, 'data': {'phase': 'active', 'kind': 'reboot', 'token': 'foreign'}}
        with patch.object(m.common, 'fault_lock', return_value=lock), patch.object(m.common, 'kube') as kube:
            with self.assertRaises(RuntimeError): m.common.acquire(record())
            kube.assert_not_called()

    def test_split_duplicate_or_foreign_kubeconfig_flags_rejected(self):
        good = [b'/usr/bin/kubelet', b'--kubeconfig=/etc/kubernetes/kubelet.conf', b'--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf']
        m.validate_kubelet_argv(good)
        for extra in ([b'--kubeconfig', b'/foreign'], [good[1]], [good[2]], [b'--kubeconfig=/foreign'], [b'--bootstrap-kubeconfig', b'/foreign']):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError): m.validate_kubelet_argv(good+extra)

    def test_review_binds_machine_node_uid_ca_and_bootstrap(self):
        proof = {'node': 'home', 'node_uid': 'uid', 'machine_id': 'machine', 'ca_sha256': 'ca', 'bootstrap_sha256': 'bootstrap', 'other': 'ignored'}
        review = {k:v for k,v in proof.items() if k != 'other'}
        m.validate_review(proof, json.dumps(review))
        for key in review:
            with self.subTest(key=key), self.assertRaises(RuntimeError): m.validate_review(proof, json.dumps({**review, key: 'wrong'}))
        with self.assertRaises(RuntimeError): m.validate_review(proof, '{}')

    def test_oversized_workload_inventory_rejected_before_inspection(self):
        with patch.object(m, 'command', return_value=json.dumps({'containers': [{}]*129}).encode()) as command:
            with self.assertRaises(RuntimeError): m.workloads()
        self.assertEqual(command.call_count, 1)

    def test_workload_inventory_has_overall_deadline(self):
        data = {'containers': [{'id': 'container', 'state': 'CONTAINER_RUNNING'}]}
        with patch.object(m, 'command', return_value=json.dumps(data).encode()) as command, patch.object(m.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaises(RuntimeError): m.workloads()
        self.assertEqual(command.call_count, 1)

    def test_shared_health_and_lock_target_our_endpoint_and_owner(self):
        self.assertEqual(m.common.OWNER, m.OWNER); self.assertEqual(m.common.ROOT, m.ROOT)
        with patch.object(m, 'command', return_value=b'{}') as command:
            m.common.kube(['get', 'nodes'])
        self.assertIn('--server='+m.ENDPOINT, command.call_args.args[0])


if __name__ == '__main__': unittest.main()
