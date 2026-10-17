#!/usr/bin/env python3
"""Offline behavioral tests: no Kubernetes access, no sockets, no secrets."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('publisher', ROOT / 'controller.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
CFG = publisher.settings(ROOT / 'settings.json')


def seed():
    state = json.loads((ROOT / 'state.json').read_text())
    state['settings_hash'] = publisher.config_hash(CFG)
    return state


class Api:
    def __init__(self):
        self.data = {
            'lease': {'metadata': {'resourceVersion': '1'}, 'spec': {}},
            'zone': {'metadata': {'resourceVersion': '1'}, 'data': {'state.json': json.dumps(seed())}},
        }
        self.hook = None

    def request(self, resource, body=None):
        if body is None:
            return copy.deepcopy(self.data[resource])
        if self.hook:
            hook, self.hook = self.hook, None
            hook()
        if body['metadata']['resourceVersion'] != self.data[resource]['metadata']['resourceVersion']:
            raise RuntimeError('409 Conflict')
        self.data[resource] = copy.deepcopy(body)
        self.data[resource]['metadata']['resourceVersion'] = str(int(body['metadata']['resourceVersion']) + 1)
        return copy.deepcopy(self.data[resource])


class Behavior(unittest.TestCase):
    def test_three_failures_remove_two_successes_restore(self):
        state = seed()
        initial = state['serial']
        for _ in range(2):
            state = publisher.next_state(state, {'msk': False, 'fin': True}, CFG, 100)
            self.assertEqual(set(state['active']), {'fin', 'msk'})
            self.assertEqual(state['serial'], initial)
        state = publisher.next_state(state, {'msk': False, 'fin': True}, CFG, 100)
        self.assertEqual(state['active'], ['fin'])
        self.assertEqual(state['serial'], initial + 1)
        state = publisher.next_state(state, {'msk': True, 'fin': True}, CFG, 100)
        self.assertEqual(state['active'], ['fin'])
        state = publisher.next_state(state, {'msk': True, 'fin': True}, CFG, 100)
        self.assertEqual(set(state['active']), {'fin', 'msk'})
        self.assertEqual(state['serial'], initial + 2)

    def test_both_down_retain_last_nonempty_not_original_seed(self):
        state = seed()
        for _ in range(3):
            state = publisher.next_state(state, {'msk': False, 'fin': True}, CFG, 100)
        serial = state['serial']
        for _ in range(3):
            state = publisher.next_state(state, {'msk': False, 'fin': False}, CFG, 100)
        self.assertEqual(state['active'], ['fin'])
        self.assertTrue(state['all_down'])
        self.assertEqual(state['serial'], serial)
        self.assertIn('ns-msk IN A ', publisher.zone_text(state, CFG))
        self.assertNotIn('ingress IN A ' + CFG['targets']['msk'], publisher.zone_text(state, CFG))

    def test_counters_survive_leader_change(self):
        state = seed()
        for _ in range(2):
            state = publisher.next_state(state, {'msk': False, 'fin': True}, CFG, 100)
        resumed = json.loads(json.dumps(state))
        resumed = publisher.next_state(resumed, {'msk': False, 'fin': True}, CFG, 101)
        self.assertEqual(resumed['active'], ['fin'])

    def test_failed_intermediate_probe_resets_recovery_counter(self):
        state = seed()
        for _ in range(3):
            state = publisher.next_state(state, {'msk': False, 'fin': True}, CFG, 100)
        for success in [True, False, True]:
            state = publisher.next_state(state, {'msk': success, 'fin': True}, CFG, 101)
        self.assertFalse(state['health']['msk']['up'])

    def test_monotonic_serial_even_backwards_clock(self):
        state = seed()
        state['settings_hash'] = 'old'
        new = publisher.next_state(state, {'msk': True, 'fin': True}, CFG, 1)
        self.assertEqual(new['serial'], state['serial'] + 1)
        state['serial'] = 2**32 - 1
        with self.assertRaises(ValueError):
            publisher.next_state(state, {'msk': True, 'fin': True}, CFG, 1)

    def test_invalid_state_cannot_replace_file(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(publisher, 'ZONE', Path(tmp) / 'zone'):
            publisher.atomic_zone('previous-good-zone')
            state = seed()
            state['active'] = []
            with self.assertRaises(ValueError):
                publisher.atomic_zone(publisher.zone_text(state, CFG))
            self.assertEqual(publisher.ZONE.read_text(), 'previous-good-zone')

    def test_lease_contender_waits_observed_duration(self):
        api = Api()
        old = publisher.Publisher(CFG, api, 'old')
        new = publisher.Publisher(CFG, api, 'new')
        with patch.object(publisher.time, 'monotonic', return_value=100):
            self.assertTrue(old.lease())
            self.assertFalse(new.lease())
        with patch.object(publisher.time, 'monotonic', return_value=136):
            self.assertFalse(new.lease())
        with patch.object(publisher.time, 'monotonic', return_value=138):
            self.assertTrue(new.lease())
            new.publish({'msk': True, 'fin': True})
            old.renewed_at = 138  # Even a locally fresh clock cannot bypass API ownership.
            with self.assertRaisesRegex(RuntimeError, 'leadership lost'):
                old.publish({'msk': False, 'fin': False})
        self.assertEqual(api.data['zone']['metadata']['annotations'][publisher.OWNER], 'new')

    def test_new_zone_epoch_rejects_stale_publisher(self):
        api = Api()
        agent = publisher.Publisher(CFG, api, 'old')
        agent.lease()
        api.data['zone']['metadata']['annotations'] = {publisher.FENCE: '5', publisher.OWNER: 'new'}
        with self.assertRaisesRegex(RuntimeError, 'fenced'):
            agent.publish({'msk': True, 'fin': True})

    def test_conflict_prevents_old_write(self):
        api = Api()
        agent = publisher.Publisher(CFG, api, 'old')
        agent.lease()
        def another_write():
            api.data['zone']['metadata']['resourceVersion'] = '2'
            api.data['zone']['metadata']['annotations'] = {publisher.FENCE: '5', publisher.OWNER: 'new'}
        api.hook = another_write
        with self.assertRaisesRegex(RuntimeError, '409'):
            agent.publish({'msk': False, 'fin': False})
        self.assertEqual(api.data['zone']['metadata']['annotations'][publisher.OWNER], 'new')

    def test_expired_local_leadership_does_not_write(self):
        api = Api()
        agent = publisher.Publisher(CFG, api, 'old')
        with patch.object(publisher.time, 'monotonic', return_value=100):
            agent.lease()
        with patch.object(publisher.time, 'monotonic', return_value=116):
            with self.assertRaisesRegex(RuntimeError, 'renewal too old'):
                agent.publish({'msk': False, 'fin': False})


if __name__ == '__main__':
    unittest.main()
