import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import jinja2
import yaml

P = Path(__file__).parent
s = importlib.util.spec_from_file_location('memory_maintenance', P/'files/kubelet-memory-maintenance.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
RAW = b'''apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
systemReserved:
  cpu: "1"
  memory: 4Gi
evictionHard:
  memory.available: 200Mi
serverTLSBootstrap: true
'''


class MemoryMaintenance(unittest.TestCase):
    def test_only_memory_scalar_changes(self):
        for raw in (RAW, RAW.replace(b'memory: 4Gi', b'memory: "4Gi"'), RAW.replace(b'\n', b'\r\n')):
            after = m.patch_memory(raw)
            self.assertEqual(after, raw.replace(b'4Gi', b'2Gi'))
            expected = yaml.safe_load(raw); expected['systemReserved']['memory'] = '2Gi'
            self.assertEqual(yaml.safe_load(after), expected)

    def test_rejects_home_other_cpu_and_prior_or_partial_change(self):
        for before in (RAW.replace(b'4Gi', b'8Gi'), RAW.replace(b'4Gi', b'2Gi'), RAW.replace(b'cpu: "1"', b'cpu: "2"'), RAW.replace(b'memory: 4Gi', b'memory: 4Gi\n  pid: "100"')):
            with self.assertRaises(RuntimeError): m.patch_memory(before)

    def test_rejects_duplicate_and_noncanonical_yaml(self):
        for before in (RAW + b'systemReserved: {}\n', RAW.replace(b'  memory: 4Gi', b'  memory: 4Gi\n  memory: 4Gi'), RAW.replace(b'  memory: 4Gi', b'  memory: 4096Mi'), RAW.replace(b'  memory: 4Gi', b'  memory: &memory 4Gi')):
            with self.assertRaises(RuntimeError): m.patch_memory(before)

    def test_actual_template_vps_only_and_explicit_override(self):
        env = jinja2.Environment(undefined=jinja2.StrictUndefined); env.filters['to_json'] = json.dumps
        t = env.from_string((P/'templates/kubeadm-kubelet-patch.yaml.j2').read_text())
        for site, memory, cpu in [('home', '8Gi', '2'), ('msk', '2Gi', '1'), ('fin', '2Gi', '1')]:
            result = yaml.safe_load(t.render(site=site, unified_node_vpn_ip='100.64.1.1'))
            self.assertEqual(result['systemReserved'], {'cpu': cpu, 'memory': memory})
            self.assertEqual(result['enforceNodeAllocatable'], ['pods'])
        self.assertEqual(yaml.safe_load(t.render(site='fin', unified_node_vpn_ip='100.64.1.1', unified_system_reserved_memory='3Gi'))['systemReserved']['memory'], '3Gi')

    def test_existing_record_directory_forbids_apply_before_inspection(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(m, 'ROOT', Path(d)), mock.patch.object(m, 'inspect') as inspect:
            with self.assertRaisesRegex(RuntimeError, 'no replay'): m.apply('msk', {})
            inspect.assert_not_called()

    def test_review_is_exact(self):
        proof = {'node': 'msk', 'protected': {'bootstrap': 'a'}, 'configz_before': {'systemReserved': {'memory': '4Gi'}}}
        m.validate_review(proof, copy.deepcopy(proof))
        for changed in ({**proof, 'node': 'fin'}, {**proof, 'protected': {}}, {**proof, 'extra': True}):
            with self.assertRaises(RuntimeError): m.validate_review(proof, changed)

    def restart_fixture(self, fail=None):
        events = []; record = {'phase': 'files-written', 'kubelet_before': {'pid': 1}}
        def persist(r): events.append(('persist', r['phase']))
        def command(*a, **kw):
            events.append(('restart', a[0]))
            if fail: raise fail
        base = types.SimpleNamespace(kubelet_process=lambda: {'pid': 1}, command=command)
        common = types.SimpleNamespace(save_record=persist)
        return record, events, base, common

    def test_restart_intent_is_durable_before_single_dispatch(self):
        record, events, base, common = self.restart_fixture()
        with mock.patch.object(m, 'base', base), mock.patch.object(m, 'common', common):
            m.restart_once(record)
            with self.assertRaises(RuntimeError): m.restart_once(record)
        self.assertEqual([e[0] for e in events], ['persist', 'restart', 'persist'])
        self.assertEqual(events[0], ('persist', 'restart-intent'))
        self.assertEqual(record['phase'], 'restart-accepted')
        self.assertEqual(events[1][1], ['/usr/bin/systemctl', '--no-block', 'restart', 'kubelet.service'])

    def test_lost_ack_is_unknown_and_cannot_redispatch(self):
        record, events, base, common = self.restart_fixture(subprocess.TimeoutExpired('systemctl', 8))
        with mock.patch.object(m, 'base', base), mock.patch.object(m, 'common', common):
            with self.assertRaisesRegex(RuntimeError, 'unknown'): m.restart_once(record)
            with self.assertRaises(RuntimeError): m.restart_once(record)
        self.assertEqual(record['phase'], 'restart-unknown')
        self.assertEqual(sum(e[0]=='restart' for e in events), 1)

    def test_failed_intent_persist_never_dispatches(self):
        record, _, base, common = self.restart_fixture(); common.save_record = mock.Mock(side_effect=OSError('disk full')); base.command = mock.Mock()
        with mock.patch.object(m, 'base', base), mock.patch.object(m, 'common', common):
            with self.assertRaises(OSError): m.restart_once(record)
        base.command.assert_not_called()

    def test_config_replacement_retains_mode_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'config'; p.write_bytes(RAW); p.chmod(0o644)
            m.replace_config(p, m.patch_memory(RAW), 0o644)
            self.assertEqual(p.read_bytes(), RAW.replace(b'4Gi', b'2Gi'))
            self.assertEqual(p.stat().st_mode&0o777, 0o644)
            self.assertEqual([x.name for x in Path(d).iterdir()], ['config'])

    def test_unknown_readback_never_adopts_or_verifies(self):
        record = {'node': 'msk', 'phase': 'restart-unknown'}
        common = types.SimpleNamespace(trusted=lambda *a: b'bytes', fault_lock=lambda: {'phase': 'active'})
        with mock.patch.object(m, 'read_record', return_value=record), mock.patch.object(m, 'common', common), mock.patch.object(m, 'base', types.SimpleNamespace(BOOTSTRAP=Path('/not-used'))), mock.patch.object(m, 'verify_after') as verify:
            result = m.readback('msk')
        self.assertFalse(result['verified']); self.assertFalse(result['adopted']); verify.assert_not_called()

    def test_verified_readback_requires_owned_released_lock(self):
        record = {'node': 'msk', 'phase': 'verified', 'global_uid': 'lock1', 'token': 'token'}
        held = {'metadata': {'uid': 'lock1'}, 'data': {'phase': 'free', 'kind': m.OWNER, 'node': 'msk', 'token': 'token'}}
        common = types.SimpleNamespace(trusted=lambda *a: b'bytes', fault_lock=lambda: held)
        with mock.patch.object(m, 'read_record', return_value=record), mock.patch.object(m, 'common', common), mock.patch.object(m, 'base', types.SimpleNamespace(BOOTSTRAP=Path('/not-used'))), mock.patch.object(m, 'verify_after', return_value={'healthy': True}):
            self.assertTrue(m.readback('msk')['verified'])
            held['data']['phase'] = 'active'
            with self.assertRaisesRegex(RuntimeError, 'released'): m.readback('msk')
            held['data']['phase'] = 'free'; held['data']['token'] = 'other'
            with self.assertRaises(RuntimeError): m.readback('msk')

    def test_playbook_scope_one_vps_and_no_installer(self):
        play = yaml.safe_load((P/'kubelet-memory-maintenance.yml').read_text())[0]
        self.assertEqual(play['vars']['kubelet_memory_action'], 'inspect')
        self.assertIn("ansible_play_hosts_all in [['msk'], ['fin']]", play['tasks'][0]['ansible.builtin.assert']['that'])
        self.assertEqual(set(k for task in play['tasks'] for k in task if k.startswith('ansible.builtin.')), {'ansible.builtin.assert', 'ansible.builtin.command', 'ansible.builtin.debug'})


if __name__ == '__main__': unittest.main()
