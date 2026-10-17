#!/usr/bin/env python3
"""Run the actual readonly fstab preflight fragment against local fixtures."""
import contextlib
import io
import json
from pathlib import Path
import re
import textwrap
import types
import unittest

SOURCE = Path(__file__).with_name('cluster.yml').read_text()
START = SOURCE.index("            fstab=pathlib.Path('/etc/fstab').read_text().splitlines()")
END = SOURCE.index("          - \"{{ unified_pod_cidr }}\"", START)
FRAGMENT = compile(textwrap.dedent(SOURCE[START:END]), 'cluster-fstab-preflight', 'exec')
MANAGED = '# BEGIN infra-flux: swap noauto\nUUID=synthetic none swap noauto 0 0\n# END infra-flux: swap noauto\n'


def check(fstab, allow):
    capture = io.StringIO()
    fake_path = lambda value: types.SimpleNamespace(read_text=lambda: fstab)
    with contextlib.redirect_stdout(capture):
        exec(FRAGMENT, {'pathlib': types.SimpleNamespace(Path=fake_path), 'json': json,
                        'swaps': [], 'unified_allow_swap_disable': allow})
    return json.loads(capture.getvalue())


class BootstrapSwapGuardTests(unittest.TestCase):
    def test_maintenance_block_refuses_both_old_enable_flag_values(self):
        for allow in (False, True):
            with self.subTest(allow=allow), self.assertRaisesRegex(AssertionError, 'Persistent swap maintenance'):
                check(MANAGED, allow)

    def test_fresh_host_without_maintenance_preserves_bootstrap_preflight(self):
        result = check('# No swap maintenance yet\nUUID=root / ext4 defaults 0 1\n', True)
        self.assertEqual(result, {'active_swap_count': 0, 'fstab_swap_count': 0})

    def test_guard_still_refuses_if_managed_entry_was_already_commented(self):
        with self.assertRaisesRegex(AssertionError, 'Persistent swap maintenance'):
            check(MANAGED.replace('UUID=synthetic', '# infra-flux kubeadm disabled swap: UUID=synthetic'), True)

    def test_original_comment_replacement_would_match_noauto(self):
        # Demonstrate the concrete regression this preflight guards against.
        pattern = r'^([ \t]*[^#\s]\S*[ \t]+\S+[ \t]+swap[ \t]+.*)$'
        self.assertIsNotNone(re.match(pattern, 'UUID=synthetic none swap noauto 0 0'))

    def test_guard_runs_before_swap_permission_and_mutating_play(self):
        self.assertLess(START, SOURCE.index('    - name: Require explicit swap disable guard'))
        self.assertLess(START, SOURCE.index('- name: Prepare private networking and node bootstrap files'))
        self.assertLess(START, SOURCE.index('    - name: Disable unused swap'))

    def test_immutable_fingerprint_comparison_is_retained(self):
        self.assertIn("'playbook': lookup('ansible.builtin.file', playbook_dir ~ '/cluster.yml') | hash('sha256')", SOURCE)
        self.assertIn('not unified_marker_stat.stat.exists or unified_existing.fingerprint == unified_fingerprint', SOURCE)


if __name__ == '__main__':
    unittest.main()
