#!/usr/bin/env python3
"""Offline safety checks. No SSH, Kubernetes API or host files are accessed."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('maintenance', Path(__file__).parent / 'files/etcd-probe-maintenance.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
VALUES = {'failureThreshold': 30, 'periodSeconds': 10, 'timeoutSeconds': 5}
TEXT = b'''apiVersion: v1
kind: Pod
metadata:
  name: etcd
  namespace: kube-system
spec:
  containers:
  - name: etcd
    livenessProbe:
      failureThreshold: 8
      timeoutSeconds: 15
    startupProbe:
      failureThreshold: 60
      httpGet:
        host: 127.0.0.1
        path: /readyz
        port: probe-port
        scheme: HTTP
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 15
    volumeMounts:
    - name: etcd-data
      mountPath: /var/lib/etcd
'''


def fixture():
    return {'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': 'etcd', 'namespace': 'kube-system', 'labels': {'component': 'etcd'}},
        'spec': {'hostNetwork': True, 'containers': [{
            'name': 'etcd', 'image': 'registry.k8s.io/etcd:3.6.8-0',
            'command': ['etcd', '--name=home', '--data-dir=/var/lib/etcd', '--listen-peer-urls=https://192.0.2.1:2380'],
            'startupProbe': {**m.NATIVE, 'initialDelaySeconds': 10,
                'httpGet': {'host': '127.0.0.1', 'path': '/readyz', 'port': 'probe-port', 'scheme': 'HTTP'}},
            'livenessProbe': {'failureThreshold': 8, 'timeoutSeconds': 15}}]}}


def record():
    return {'owner': m.OWNER, 'node': 'home', 'token': 'a' * 32,
            'before_sha256': m.sha(TEXT), 'after_sha256': 'b' * 64,
            'values': VALUES, 'member_ids': [1, 2, 3]}


def current_lock():
    return {'metadata': {'uid': 'stable-uid', 'resourceVersion': '17', 'annotations': {m.ANNOTATION: m.FAULT_OWNER}},
            'data': {'phase': 'active', 'kind': m.OWNER, 'node': 'home', 'token': 'a' * 32}}


class MaintenanceSafetyTests(unittest.TestCase):
    def test_text_patch_preserves_all_other_bytes(self):
        result = m.patch_text(TEXT, fixture(), VALUES)
        expected = TEXT.replace(b'failureThreshold: 60', b'failureThreshold: 30').replace(
            b'      timeoutSeconds: 15\n    volumeMounts:', b'      timeoutSeconds: 5\n    volumeMounts:')
        self.assertEqual(result, expected)
        self.assertIn(b'livenessProbe:\n      failureThreshold: 8\n      timeoutSeconds: 15', result)

    def test_missing_duplicate_or_noninteger_scalar_is_rejected(self):
        cases = [TEXT.replace(b'      timeoutSeconds: 15', b'      timeoutSeconds: "15"'),
                 TEXT.replace(b'      timeoutSeconds: 15', b'      timeoutSeconds: 15\n      timeoutSeconds: 15'),
                 TEXT + b'    startupProbe:\n      timeoutSeconds: 15\n']
        for data in cases:
            with self.subTest(data=data), self.assertRaises(RuntimeError): m.patch_text(data, fixture(), VALUES)

    def test_semantic_guard_rejects_unrelated_change(self):
        before = fixture(); after = copy.deepcopy(before)
        after['spec']['containers'][0]['startupProbe'].update(VALUES)
        m.validate_only_probe_changed(before, after, VALUES)
        after['spec']['containers'][0]['livenessProbe']['timeoutSeconds'] = 5
        with self.assertRaises(RuntimeError): m.validate_only_probe_changed(before, after, VALUES)

    def test_unknown_probe_identity_or_image_is_rejected(self):
        m.validate_manifest(fixture(), 'home', '192.0.2.1', m.NATIVE)
        mutations = [lambda x: x['spec']['containers'][0]['startupProbe']['httpGet'].update(path='/livez'),
                     lambda x: x['spec']['containers'][0]['startupProbe'].update(initialDelaySeconds=0),
                     lambda x: x['spec']['containers'][0].update(image='registry.k8s.io/etcd:3.7.0-0'),
                     lambda x: x['spec']['containers'].append({'name': 'another-container'}),
                     lambda x: x['spec']['containers'][0]['command'].append('--name=home')]
        for mutate in mutations:
            obj = fixture(); mutate(obj)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): m.validate_manifest(obj, 'home', '192.0.2.1', m.NATIVE)

    def test_aggressive_or_overlapping_timeouts_are_rejected(self):
        for values in ({**VALUES, 'failureThreshold': 1}, {**VALUES, 'timeoutSeconds': 11}, {**VALUES, 'failureThreshold': True}):
            with self.subTest(values=values), self.assertRaises(RuntimeError): m.validate_policy(values)

    def test_preimage_mismatch_prevents_health_or_writes(self):
        args = argparse.Namespace(node='home', ca_sha256='ca', expected_sha256='f'*64)
        proof = {'manifest_sha256': m.sha(TEXT)}
        with patch.object(m, 'inspect', return_value=(proof, TEXT, b'candidate', b'bootstrap', None)), patch.object(m, 'health') as health, patch.object(m, 'atomic') as write:
            with self.assertRaises(RuntimeError): m.apply(args, VALUES)
            health.assert_not_called(); write.assert_not_called()

    def test_active_fault_is_never_overwritten(self):
        lock = current_lock(); lock['data'].update(kind='reboot', token='other-token')
        with patch.object(m, 'fault_lock', return_value=lock), patch.object(m, 'kube') as kube:
            with self.assertRaises(RuntimeError): m.acquire(record())
            kube.assert_not_called()

    def test_cas_preserves_resource_version(self):
        lock = current_lock(); lock['data']['phase'] = 'free'
        r = record()
        with patch.object(m, 'fault_lock', return_value=lock), patch.object(m, 'kube', return_value=json.dumps(lock).encode()) as kube, patch.object(m, 'save_record'):
            m.acquire(r)
        self.assertEqual(kube.call_args.args[1]['metadata']['resourceVersion'], '17')
        self.assertEqual(r['global_uid'], 'stable-uid')

    def test_crash_after_lock_acquisition_can_bind_uid_on_resume(self):
        r = record()
        with patch.object(m, 'fault_lock', return_value=current_lock()), patch.object(m, 'kube') as kube, patch.object(m, 'save_record') as save:
            m.acquire(r)
            kube.assert_not_called(); save.assert_called_once()
        self.assertEqual(r['global_uid'], 'stable-uid')

    def test_recreated_lock_is_not_released(self):
        r = record(); r['global_uid'] = 'older-uid'
        with patch.object(m, 'fault_lock', return_value=current_lock()), patch.object(m, 'kube') as kube:
            with self.assertRaises(RuntimeError): m.release(r)
            kube.assert_not_called()

    def test_bootstrap_change_after_health_prevents_manifest_write(self):
        r = record(); proof = {'manifest_sha256': m.sha(TEXT)}
        args = argparse.Namespace(node='home', ca_sha256='ca', expected_sha256=m.sha(TEXT))
        with patch.object(m, 'inspect', return_value=(proof, TEXT, b'candidate', b'bootstrap', r)), patch.object(m, 'lock_available'), patch.object(m, 'health', return_value={'member_ids': [1,2,3]}), patch.object(m, 'acquire'), patch.object(m, 'trusted', side_effect=[TEXT, b'changed-bootstrap']), patch.object(m, 'atomic') as write:
            with self.assertRaises(RuntimeError): m.apply(args, VALUES)
            write.assert_not_called()

    def test_runtime_requires_new_spec_and_successful_startup(self):
        pod = {'metadata': {'annotations': {'kubernetes.io/config.source': 'file'}},
            'spec': {'nodeName': 'home', 'containers': [{'name': 'etcd', 'startupProbe': VALUES}]},
            'status': {'containerStatuses': [{'ready': True, 'started': True, 'state': {'running': {}}, 'containerID': 'new-container'}]}}
        with patch.object(m, 'kube', return_value=json.dumps(pod).encode()):
            self.assertEqual(m.runtime_probe('home', VALUES), 'new-container')
        pod['status']['containerStatuses'][0]['started'] = False
        with patch.object(m, 'kube', return_value=json.dumps(pod).encode()), self.assertRaises(RuntimeError): m.runtime_probe('home', VALUES)

    def test_atomic_write_leaves_no_extra_manifest_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'etcd.yaml'; path.write_bytes(b'old')
            m.atomic(path, b'new')
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_parser_uses_client_dry_run(self):
        with patch.object(m, 'command', return_value=b'{}') as command:
            m.parse_manifest(TEXT)
        argv = command.call_args.args[0]
        self.assertIn('--dry-run=client', argv)
        self.assertNotIn('apply', argv)
        self.assertEqual(command.call_args.args[1], TEXT)


if __name__ == '__main__': unittest.main()
