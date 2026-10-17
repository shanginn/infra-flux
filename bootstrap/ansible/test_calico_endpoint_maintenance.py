#!/usr/bin/env python3
"""Offline safety checks; no Kubernetes/SSH mutation or host-file access."""
import argparse
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('calico_maintenance', Path(__file__).parent / 'files/calico-endpoint-maintenance.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def ds():
    env = [{'configMapRef': {'name': m.ENDPOINT_NAME, 'optional': True}}]
    return {'kind': 'DaemonSet', 'metadata': {'name': 'calico-node', 'namespace': 'kube-system', 'uid': 'ds-owned',
        'managedFields': [{'manager': 'infra-flux-bootstrap', 'operation': 'Apply'}]}, 'spec': {
        'selector': {'matchLabels': {'k8s-app': 'calico-node'}}, 'template': {'spec': {
            'hostNetwork': True, 'serviceAccountName': 'calico-node',
            'initContainers': [{'name': name, 'image': 'quay.io/calico/calico:v3.33.0', 'envFrom': env} for name in ('upgrade-ipam', 'install-cni')],
            'containers': [{'name': 'calico-node', 'image': 'quay.io/calico/node:v3.33.0', 'envFrom': env}]}}}}


def pod():
    return {'metadata': {'name': 'calico-node-owned', 'namespace': 'kube-system', 'uid': 'old-pod',
        'ownerReferences': [{'kind': 'DaemonSet', 'name': 'calico-node', 'uid': 'ds-owned', 'controller': True}]},
        'spec': {**copy.deepcopy(ds()['spec']['template']['spec']), 'nodeName': 'home'},
        'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}


def record():
    return {'owner': m.OWNER, 'node': 'home', 'token': 'a' * 32, 'global_uid': 'lock-owned',
        'review': {'pod_uid': 'old-pod', 'ds_uid': 'ds-owned', 'ds_spec_sha256': m.validate_daemonset(ds())}}


def lock():
    return {'metadata': {'uid': 'lock-owned', 'resourceVersion': '123', 'annotations': {m.ANNOTATION: m.FAULT_OWNER}},
        'data': {'phase': 'active', 'kind': m.OWNER, 'token': 'a' * 32, 'node': 'home'}}


class SafetyTests(unittest.TestCase):
    def test_exact_uid_precondition_on_delete(self):
        with patch.object(m, 'kube', return_value=b'{}') as kube: m.delete_exact(pod())
        argv, body = kube.call_args.args
        self.assertEqual(argv, ['delete', '--raw=/api/v1/namespaces/kube-system/pods/calico-node-owned', '-f', '-'])
        self.assertEqual(body['preconditions'], {'uid': 'old-pod'})
        self.assertNotIn('gracePeriodSeconds', body)
        self.assertNotIn('--force', argv)

    def test_delete_rejects_an_unrelated_namespace(self):
        p = pod(); p['metadata']['namespace'] = 'production'
        with patch.object(m, 'kube') as kube, self.assertRaises(RuntimeError): m.delete_exact(p)
        kube.assert_not_called()

    def test_daemonset_owner_version_env_and_tls_are_bound(self):
        m.validate_daemonset(ds())
        mutations = [lambda d: d['metadata'].update(managedFields=[]),
            lambda d: d['spec']['template']['spec'].update(hostNetwork=False),
            lambda d: d['spec']['template']['spec']['containers'][0].update(image='quay.io/calico/node:v3.34.0'),
            lambda d: d['spec']['template']['spec']['initContainers'][1].update(envFrom=[]),
            lambda d: d['spec']['template']['spec']['containers'][0].update(env=[{'name': 'SKIP_TLS_VERIFY', 'value': 'true'}])]
        for mutate in mutations:
            d = ds(); mutate(d)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): m.validate_daemonset(d)

    def test_pod_uid_owner_node_and_template(self):
        m.validate_pod(pod(), ds(), 'home', True)
        mutations = [lambda p: p['metadata']['ownerReferences'][0].update(uid='foreign'),
            lambda p: p['spec'].update(nodeName='fin'),
            lambda p: p['spec']['containers'][0].update(envFrom=[]),
            lambda p: p['metadata'].update(deletionTimestamp='now')]
        for mutate in mutations:
            p = pod(); mutate(p)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): m.validate_pod(p, ds(), 'home', True)

    def test_active_fault_never_acquired(self):
        active = lock(); active['data'].update(kind='reboot', token='another')
        with patch.object(m, 'fault_lock', return_value=active), patch.object(m, 'kube') as kube, self.assertRaises(RuntimeError): m.acquire(record())
        kube.assert_not_called()

    def test_lock_cas_keeps_resource_version(self):
        current = lock(); current['data']['phase'] = 'free'
        with patch.object(m, 'fault_lock', return_value=current), patch.object(m, 'save_record'), patch.object(m, 'kube', return_value=json.dumps(current).encode()) as kube:
            m.acquire(record())
        self.assertEqual(kube.call_args.args[1]['metadata']['resourceVersion'], '123')

    def test_replaced_lock_cannot_be_released(self):
        current = lock(); current['metadata']['uid'] = 'foreign'
        with patch.object(m, 'fault_lock', return_value=current), patch.object(m, 'kube') as kube, self.assertRaises(RuntimeError): m.release(record())
        kube.assert_not_called()

    def test_config_allows_endpoint_and_token_rotation_only(self):
        before = {'shape': {'users': [{'name': 'calico'}]}, 'server': 'https://old',
            'token_sha256': 'old', 'token_identity': {'sub': 'cni'}, 'serviceaccount': {'uid': 'sa'}}
        after = {**copy.deepcopy(before), 'server': m.ENDPOINT, 'token_sha256': 'new'}
        m.config_equivalent(before, after)
        for key, value in [('shape', {'users': []}), ('serviceaccount', {'uid': 'foreign'}), ('server', 'https://other')]:
            changed = copy.deepcopy(after); changed[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): m.config_equivalent(before, changed)

    def test_config_decoder_does_not_return_token_and_rejects_tls_bypass(self):
        claims = {'sub': 'system:serviceaccount:kube-system:calico-cni-plugin', 'iss': 'owned', 'aud': ['api'],
            'kubernetes.io': {'serviceaccount': {'name': 'calico-cni-plugin', 'uid': 'sa'}}}
        token = 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'
        obj = {'clusters': [{'name': 'local', 'cluster': {'server': m.ENDPOINT, 'certificate-authority-data': base64.b64encode(b'ca').decode()}}],
            'users': [{'name': 'calico', 'user': {'token': token}}], 'contexts': [{'name': 'calico-context'}]}
        with patch.object(m, 'command', return_value=json.dumps(obj).encode()), patch.object(m, 'trusted', return_value=b'ca'):
            result = m.cni_config(b'private')
        self.assertNotIn(token, json.dumps(result))
        obj['clusters'][0]['cluster']['insecure-skip-tls-verify'] = True
        with patch.object(m, 'command', return_value=json.dumps(obj).encode()), self.assertRaises(RuntimeError): m.cni_config(b'private')

    def test_wrong_review_prevents_health_lock_or_mutation(self):
        args = argparse.Namespace(node='home', ca_sha256='ca', review_json='{}')
        with patch.object(m, 'inspect', return_value=({'review': {'pod_uid': 'current'}}, b'raw', b'marker', ds(), pod(), None)), patch.object(m, 'health') as health, patch.object(m, 'acquire') as acquire, patch.object(m, 'delete_exact') as delete:
            with self.assertRaises(RuntimeError): m.apply(args)
        health.assert_not_called(); acquire.assert_not_called(); delete.assert_not_called()

    def test_probe_has_no_credentials_or_host_access_and_is_bounded(self):
        with patch.object(m, 'get', return_value={'spec': {'clusterIP': '192.0.2.1'}}): p = m.network_pod(record())
        s = p['spec']; self.assertFalse(s['hostNetwork']); self.assertFalse(s['automountServiceAccountToken'])
        self.assertEqual(s['activeDeadlineSeconds'], 180); self.assertEqual(s['nodeName'], 'home')
        self.assertTrue(s['containers'][0]['securityContext']['readOnlyRootFilesystem'])
        self.assertTrue(all('hostPath' not in v and 'secret' not in v for v in s['volumes']))
        self.assertIn('@sha256:', s['containers'][0]['image'])

    def test_probe_cleanup_ownership_binds_uid_and_spec(self):
        with patch.object(m, 'get', return_value={'spec': {'clusterIP': '192.0.2.1'}}): wanted = m.network_pod(record())
        p = copy.deepcopy(wanted); p['metadata']['uid'] = 'probe-uid'
        r = {**record(), 'network_pod_uid': 'probe-uid'}
        m.validate_network_pod(p, wanted, r)
        for mutate in (lambda p: p['metadata'].update(uid='foreign'), lambda p: p['spec'].update(hostNetwork=True),
                       lambda p: p['metadata']['annotations'].update({m.ANNOTATION: 'foreign'})):
            changed = copy.deepcopy(p); mutate(changed)
            with self.assertRaises(RuntimeError): m.validate_network_pod(changed, wanted, r)

    def test_endpoint_config_cannot_adopt_unknown_owner(self):
        cm = {'metadata': {'annotations': {m.ANNOTATION: 'another'}}, 'data': m.ENDPOINT_DATA}
        with patch.object(m, 'get', return_value=cm), self.assertRaises(RuntimeError): m.endpoint_config(True)
        with patch.object(m, 'get', return_value=None): self.assertIsNone(m.endpoint_config())
        with patch.object(m, 'get', return_value=None), self.assertRaises(RuntimeError): m.endpoint_config(True)

    def test_api_omits_only_default_false_host_network(self):
        with patch.object(m, 'get', return_value={'spec': {'clusterIP': '192.0.2.1'}}): wanted = m.network_pod(record())
        actual = copy.deepcopy(wanted); actual['metadata']['uid'] = 'probe-uid'
        del actual['spec']['hostNetwork']
        m.validate_network_pod(actual, wanted, record())
        actual['spec']['hostNetwork'] = True
        with self.assertRaises(RuntimeError): m.validate_network_pod(actual, wanted, record())
        del actual['spec']['hostNetwork']; del actual['spec']['automountServiceAccountToken']
        with self.assertRaises(RuntimeError): m.validate_network_pod(actual, wanted, record())

    def test_verified_rerun_never_deletes(self):
        r = {**record(), 'phase': 'verified', 'member_ids': [1,2,3], 'network_cleanup': True, 'network_proof': {'dns_resolved': True}}
        args = argparse.Namespace(node='home', ca_sha256='ca', review_json=json.dumps(r['review']))
        with patch.object(m, 'inspect', return_value=({'review': r['review']}, b'raw', b'marker', ds(), pod(), r)), patch.object(m, 'endpoint_config'), patch.object(m, 'lock_available'), patch.object(m, 'health', return_value={'member_ids':[1,2,3]}), patch.object(m, 'node_pod'), patch.object(m, 'authenticated_cni_read'), patch.object(m, 'validate_recorded_runtime'), patch.object(m, 'delete_exact') as delete:
            result = m.apply(args)
        self.assertFalse(result['changed']); delete.assert_not_called()


if __name__ == '__main__': unittest.main()
