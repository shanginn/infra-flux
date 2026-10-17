#!/usr/bin/env python3
"""Local safety tests; no service, device or filesystem maintenance is executed."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parent / 'files' / 'swap-maintenance.py'
spec = importlib.util.spec_from_file_location('swap_maintenance', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
TEST_UUID = '12345678-1234-1234-1234-123456789abc'
OTHER_UUID = '12345678-1234-1234-1234-123456789def'
ORIGINAL = ('# Existing host configuration\nUUID=root-example / ext4 defaults 0 1\n'
            '/dev/mapper/data /srv ext4 defaults 0 2\n'
            '# infra-flux kubeadm disabled swap: UUID=' + TEST_UUID + ' none swap sw 0 0\n').encode()


class SafetyTests(unittest.TestCase):
    def test_root_mounts_and_original_bytes_are_preserved(self):
        proposed = m.candidate(ORIGINAL, TEST_UUID)
        self.assertTrue(proposed.startswith(ORIGINAL))
        extra = proposed[len(ORIGINAL):].decode().splitlines()
        self.assertEqual([line.split()[2:4] for line in extra if not line.startswith('#')], [['swap', 'noauto']])

    def test_reviewed_entry_is_idempotent(self):
        proposed = m.candidate(ORIGINAL, TEST_UUID)
        self.assertEqual(m.candidate(proposed, TEST_UUID), proposed)

    def test_wrong_partition_requires_review(self):
        with self.assertRaises(RuntimeError):
            m.candidate(ORIGINAL, OTHER_UUID)

    def test_existing_active_swap_is_not_rewritten(self):
        with self.assertRaises(RuntimeError):
            m.candidate(ORIGINAL + ('UUID=' + OTHER_UUID + ' none swap defaults 0 0\n').encode(), TEST_UUID)

    def test_changed_owned_block_is_not_silently_overwritten(self):
        proposed = m.candidate(ORIGINAL, TEST_UUID).replace(b'swap noauto 0 0', b'swap defaults 0 0')
        with self.assertRaises(RuntimeError):
            m.candidate(proposed, TEST_UUID)

    def test_duplicate_bootstrap_identity_is_rejected(self):
        with self.assertRaises(RuntimeError):
            m.candidate(ORIGINAL + ORIGINAL.splitlines(keepends=True)[-1], TEST_UUID)

    def test_inspection_never_reloads_or_writes(self):
        with patch.object(sys, 'argv', ['probe', 'inspect', '--node', 'home', '--device', '/dev/sda2', '--uuid', TEST_UUID, '--partuuid', OTHER_UUID]), \
             patch.object(m, 'inspect', return_value=({'changed': True}, ORIGINAL, m.candidate(ORIGINAL, TEST_UUID))), \
             patch.object(m, 'run') as run, patch.object(m, 'atomic') as atomic, patch('builtins.print'):
            m.main()
            run.assert_not_called(); atomic.assert_not_called()

    def rejected_apply(self, active, expected):
        before = {'changed': True, 'fstab_sha256': 'a' * 64, 'active_swap_count': active}
        with patch.object(sys, 'argv', ['probe', 'apply', '--node', 'home', '--device', '/dev/sda2', '--uuid', TEST_UUID,
                                      '--partuuid', OTHER_UUID, '--ca-sha256', 'c' * 64, '--expected-fstab-sha256', expected]), \
             patch.object(m, 'inspect', return_value=(before, ORIGINAL, m.candidate(ORIGINAL, TEST_UUID))), \
             patch.object(m, 'run') as run, patch.object(m, 'atomic') as atomic:
            with self.assertRaises(RuntimeError):
                m.main()
            run.assert_not_called(); atomic.assert_not_called()

    def test_live_swap_is_not_disabled_by_maintenance(self):
        self.rejected_apply(1, 'a' * 64)

    def test_changed_fstab_preimage_is_not_overwritten(self):
        self.rejected_apply(0, 'b' * 64)


if __name__ == '__main__':
    unittest.main()
