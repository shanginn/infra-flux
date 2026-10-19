import copy
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import subprocess
import types
import unittest
from unittest import mock

import yaml

P = Path(__file__).parent
spec = importlib.util.spec_from_file_location('capacity', P / 'files/postgres/capacity.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture():
    members = {}
    for site in m.SITES:
        members[site] = {'system_id': '123', 'postmaster_started': site + '-old', 'recovery': site != 'home',
                         'settings': {'max_connections': {'setting': '100', 'pending_restart': False},
                                      'shared_buffers': {'setting': '65536', 'pending_restart': False}},
                         'lsn': 'A/100', 'replication': [], 'role': 'primary' if site == 'home' else 'replica',
                         'pending_restart': False, 'pending_reason': {}, 'dcs_sha256': 'before',
                         'dcs_100_sha256': 'before', 'dcs_200_sha256': 'after', 'dcs_max_connections': 100,
                         'patroni_start_ticks': site + '-unchanged'}
    members['home']['replication'] = [{'name': 'unified-pg-' + s + '-0', 'state': 'streaming',
                                      'sync_state': 'async', 'replay_lsn': 'A/100'} for s in ('msk', 'fin')]
    return {'cluster_uid': 'cluster', 'host_machine_id': 'machine', 'host_boot_id': 'boot',
            'pins': {s: {'pod': 'unified-pg-' + s + '-0', 'pod_uid': s + '-pod', 'container_id': s + '-cid'} for s in m.SITES},
            'members': members}


def advance(before, step):
    after = copy.deepcopy(before)
    if step == 'patch':
        for v in after['members'].values():
            v.update(dcs_sha256='after', dcs_max_connections=200, pending_restart=True,
                     pending_reason={'max_connections': {'old_value': '100', 'new_value': '200'}})
            v['settings']['max_connections']['pending_restart'] = True
    else:
        v = after['members'][step.removeprefix('restart-')]
        v.update(postmaster_started=step + '-new', pending_restart=False, pending_reason={})
        v['settings']['max_connections'] = {'setting': '200', 'pending_restart': False}
    return after


class Capacity(unittest.TestCase):
    def test_exact_healthy_sequence(self):
        value = fixture(); completed = []
        m.check_phase(value, completed)
        for step in m.STEPS:
            after = advance(value, step); m.transition(value, after, step)
            completed.append(step); m.check_phase(after, completed); value = after

    def test_rejects_primary_role_systemid_replication_and_other_pending(self):
        cases = []
        for key, value in [('system_id', 'other'), ('recovery', False)]:
            bad = fixture(); bad['members']['fin'][key] = value; cases.append(bad)
        bad = fixture(); bad['members']['home']['replication'][0]['state'] = 'catchup'; cases.append(bad)
        bad = fixture(); bad['members']['home']['settings']['shared_buffers']['pending_restart'] = True; cases.append(bad)
        bad = fixture(); bad['members']['msk']['dcs_sha256'] = 'other'; cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(RuntimeError): m.check_phase(bad, [])

    def test_pending_reason_is_only_exact_capacity_change(self):
        base = advance(fixture(), 'patch')
        for reason in ({}, {'shared_buffers': {}}, {'max_connections': {'old_value': '100', 'new_value': '300'}}):
            bad = copy.deepcopy(base); bad['members']['msk']['pending_reason'] = reason
            with self.assertRaises(RuntimeError): m.check_phase(bad, ['patch'])

    def test_unrelated_identity_settings_or_other_restart_refused(self):
        before = advance(fixture(), 'patch')
        for variant in ('pod', 'cid', 'patroni', 'other_postmaster', 'setting', 'dcs'):
            after = advance(before, 'restart-msk')
            if variant == 'pod': after['pins']['msk']['pod_uid'] = 'new'
            if variant == 'cid': after['pins']['msk']['container_id'] = 'new'
            if variant == 'patroni': after['members']['msk']['patroni_start_ticks'] = 'new'
            if variant == 'other_postmaster': after['members']['fin']['postmaster_started'] = 'new'
            if variant == 'setting': after['members']['msk']['settings']['shared_buffers']['setting'] = '1'
            if variant == 'dcs': after['members']['msk']['dcs_sha256'] = 'unrelated'
            with self.subTest(variant=variant), self.assertRaises(RuntimeError): m.transition(before, after, 'restart-msk')

    def test_patch_cannot_hide_other_configuration_change(self):
        before = fixture(); after = advance(before, 'patch')
        after['members']['home']['dcs_sha256'] = 'unrelated'
        with self.assertRaisesRegex(RuntimeError, 'Unrelated DCS'): m.transition(before, after, 'patch')

    def test_replay_barrier_checks_both_standbys(self):
        value = fixture(); m.replay_barrier(value, 'A/100')
        value['members']['fin']['lsn'] = 'A/FF'
        with self.assertRaisesRegex(RuntimeError, 'replayed'): m.replay_barrier(value, 'A/100')

    def run_step(self, request, before, after, calls, error=None):
        def rpc(*args, **kwargs):
            step = request['action']; intent = m.read(m.ROOT / (step + '.intent.json'))
            self.assertEqual(intent['operation'], request['operation']); calls.append(step)
            if error: raise error
            return {'status': 200}
        with mock.patch.object(m, 'observe', return_value=before), mock.patch.object(m, 'metadata', return_value=before['pins']), \
             mock.patch.object(m, 'pod_rpc', side_effect=rpc), mock.patch.object(m, 'wait_after', return_value=after):
            return m.execute(request)

    def test_durable_intent_before_each_single_rpc_and_all_steps_in_order(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(m, 'ROOT', Path(tmp) / 'state'):
            current = fixture(); request = {'enabled': True, 'operation': 'a' * 32, 'cluster_uid': 'cluster', 'review': copy.deepcopy(current)}
            calls = []
            for step in m.STEPS:
                request['action'] = step; after = advance(current, step)
                result = self.run_step(request, current, after, calls); self.assertTrue(result['verified'])
                with self.assertRaisesRegex(RuntimeError, 'already attempted|out of order'): m.execute(request)
                current = after
            self.assertEqual(calls, list(m.STEPS))

    def test_lost_rpc_ack_never_replayed_or_adopted(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(m, 'ROOT', Path(tmp) / 'state'):
            before = fixture(); request = {'enabled': True, 'action': 'patch', 'operation': 'a' * 32, 'cluster_uid': 'cluster', 'review': before}; calls = []
            result = self.run_step(request, before, advance(before, 'patch'), calls, TimeoutError('lost response'))
            self.assertFalse(result['verified']); self.assertTrue(result['outcome_unknown'])
            with self.assertRaisesRegex(RuntimeError, 'readback only'): m.execute(request)
            request['operation'] = 'b' * 32
            with self.assertRaisesRegex(RuntimeError, 'Original operation'): m.execute(request)
            with mock.patch.object(m, 'observe', return_value=advance(before, 'patch')):
                observed = m.main({'action': 'readback', 'cluster_uid': 'cluster'})
            self.assertFalse(observed['adopted_unknown']); self.assertFalse(observed['recorded_steps']['patch']['verified'])
            self.assertEqual(calls, ['patch'])

    def test_intent_without_result_blocks_every_mutation(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(m, 'ROOT', Path(tmp) / 'state'):
            before = fixture(); request = {'enabled': True, 'action': 'patch', 'operation': 'a' * 32, 'cluster_uid': 'cluster', 'review': before}
            self.run_step(request, before, advance(before, 'patch'), [])
            (m.ROOT / 'patch.result.json').unlink()
            with mock.patch.object(m, 'pod_rpc') as rpc, self.assertRaisesRegex(RuntimeError, 'unknown'): m.execute(request)
            rpc.assert_not_called()

    def test_initial_wrong_pin_and_disabled_action_never_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(m, 'ROOT', Path(tmp) / 'state'):
            before = fixture(); request = {'enabled': False, 'action': 'patch', 'operation': 'a' * 32, 'cluster_uid': 'cluster', 'review': before}
            with self.assertRaisesRegex(RuntimeError, 'opt-in'): m.execute(request)
            request['enabled'] = True; observed = copy.deepcopy(before); observed['pins']['fin']['container_id'] = 'other'
            with mock.patch.object(m, 'observe', return_value=observed), mock.patch.object(m, 'pod_rpc') as rpc:
                with self.assertRaisesRegex(RuntimeError, 'preimage'): m.execute(request)
                rpc.assert_not_called()
            self.assertEqual({p.name for p in m.ROOT.iterdir()}, {'lock'})
            request['review'] = observed
            self.assertTrue(self.run_step(request, observed, advance(observed, 'patch'), [])['verified'])

    def test_rpc_nonzero_and_timeout_preserve_private_raw_before_error(self):
        for reply in (types.SimpleNamespace(returncode=1, stdout=b'{"phase":"failed"}', stderr=b'exact diagnostic\n'),
                      subprocess.TimeoutExpired('kubectl', 100, output=b'partial output', stderr=b'partial error')):
            with self.subTest(reply=reply), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / 'rpc.json'; pin = fixture()['pins']['msk']
                patch = mock.patch.object(m.subprocess, 'run', side_effect=reply) if isinstance(reply, Exception) else mock.patch.object(m.subprocess, 'run', return_value=reply)
                with patch as run, self.assertRaises(RuntimeError): m.pod_rpc(pin, 'restart', {}, artifact=p)
                saved = m.read(p); self.assertEqual(p.stat().st_mode & 0o777, 0o600)
                self.assertEqual(base64.b64decode(saved['streams']['stdout']['base64']), reply.stdout)
                self.assertEqual(base64.b64decode(saved['streams']['stderr']['base64']), reply.stderr)
                run.assert_called_once()

    def test_rpc_diagnostic_bound_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'rpc.json'; raw = b'x' * (1024 * 1024 + 1)
            with mock.patch.object(m.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1, stdout=b'', stderr=raw)), self.assertRaises(RuntimeError):
                m.pod_rpc(fixture()['pins']['msk'], 'restart', {}, artifact=p)
            value = m.read(p)['streams']['stderr']; self.assertTrue(value['truncated'])
            self.assertEqual(len(base64.b64decode(value['base64'])), 1024 * 1024)

    def test_inspect_default_has_no_journal_or_rpc_mutation(self):
        with mock.patch.object(m, 'observe', return_value=fixture()) as observe, mock.patch.object(m, 'execute') as execute:
            self.assertFalse(m.main({'cluster_uid': 'cluster'})['changed']); observe.assert_called_once(); execute.assert_not_called()

    def run_embedded_dispatch(self, action, before, observed=None):
        calls = []
        config = {'postgresql': {'parameters': {'max_connections': 200}}}
        before = copy.deepcopy(before); before['dcs_200_sha256'] = m.digest(config)
        actual = copy.deepcopy(before if observed is None else observed)
        def api(path, data, method):
            calls.append((path, data, method))
            return 200, json.dumps(config).encode() if action == 'patch' else b'restarted'
        namespace = {'p': {'action': action, 'expected': before}, 'observe': lambda: actual, 'need': m.need,
                     'stable': lambda v: {k: x for k, x in v.items() if k not in ['lsn', 'replication']},
                     'digest': m.digest, 'api': api, 'json': json, 'hashlib': hashlib}
        code = 'before=observe()\n' + m.POD.split('before=observe()\n', 1)[1]
        with contextlib.redirect_stdout(io.StringIO()): exec(compile(code, '<actual-pod-dispatch>', 'exec'), namespace)
        return calls

    def test_actual_embedded_restart_requests_role_pending_and_timeout_only(self):
        before = advance(fixture(), 'patch')['members']
        for site in ('msk', 'home'):
            self.assertEqual(self.run_embedded_dispatch('restart', before[site]),
                             [('/restart', {'role': before[site]['role'], 'restart_pending': True, 'timeout': 60}, 'POST')])

    def test_actual_embedded_patch_changes_only_capacity(self):
        self.assertEqual(self.run_embedded_dispatch('patch', fixture()['members']['home']),
                         [('/config', {'postgresql': {'parameters': {'max_connections': 200}}}, 'PATCH')])

    def test_actual_embedded_immediate_drift_refuses_before_api(self):
        before = advance(fixture(), 'patch')['members']['msk']; changed = copy.deepcopy(before)
        changed['postmaster_started'] = 'unexpected'
        with self.assertRaisesRegex(RuntimeError, 'Immediate member preimage'): self.run_embedded_dispatch('restart', before, changed)

    def test_playbook_has_one_host_explicit_actions_and_no_installer(self):
        play = yaml.safe_load((P / 'postgres-capacity.yml').read_text())[0]
        self.assertEqual(play['hosts'], 'msk'); self.assertEqual(play['vars']['postgres_capacity_action'], 'inspect')
        self.assertFalse(play['vars']['postgres_capacity_enabled'])
        self.assertEqual({k for t in play['tasks'] for k in t if k.startswith('ansible.builtin.')}, {'ansible.builtin.assert', 'ansible.builtin.command'})


if __name__ == '__main__': unittest.main()
