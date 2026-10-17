#!/usr/bin/env python3
"""Render actual unit content and reject the home boot ordering cycle."""
import pathlib
import unittest
import jinja2
import yaml

PLAY = yaml.safe_load((pathlib.Path(__file__).parent / 'postgres-watchdog.yml').read_text())[0]
CONTENT = next(t['ansible.builtin.copy']['content'] for t in PLAY['tasks'] if
               t.get('ansible.builtin.copy', {}).get('dest') == '/etc/systemd/system/infra-patroni-watchdog.service')


def render(site):
    return jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(CONTENT).render(site=site)


def ordering_cycle(unit):
    # Existing home facts: watchdog After=multi-user; kubelet WantedBy=multi-user.
    # A target's default dependencies order it After services it Wants.
    edges = {'watchdog.service': {'multi-user.target'}, 'multi-user.target': {'kubelet.service'},
             'kubelet.service': set(), 'infra-patroni-watchdog.service': set()}
    for line in unit.splitlines():
        if line.startswith('After='): edges['infra-patroni-watchdog.service'].update(line.split('=', 1)[1].split())
        if line.startswith('Before='):
            for name in line.split('=', 1)[1].split(): edges.setdefault(name, set()).add('infra-patroni-watchdog.service')
        if line.startswith('WantedBy=') and line.endswith('.target'):
            edges.setdefault(line.split('=', 1)[1], set()).add('infra-patroni-watchdog.service')
    visited = set()
    def visit(node, active):
        if node in active: return True
        if node in visited: return False
        visited.add(node)
        return any(visit(other, active | {node}) for other in edges.get(node, set()))
    return any(visit(node, set()) for node in edges)


class WatchdogOrderingTests(unittest.TestCase):
    def test_home_has_no_target_or_kubelet_cycle(self):
        unit = render('home')
        self.assertIn('WantedBy=watchdog.service', unit)
        self.assertIn('Requires=watchdog.service', unit)
        self.assertIn('--preserve-home-watchdog', unit)
        self.assertNotIn('Before=kubelet.service', unit)
        self.assertFalse(ordering_cycle(unit))

    def test_fixture_reproduces_both_legacy_cycles(self):
        unit = render('home')
        self.assertTrue(ordering_cycle(unit.replace('WantedBy=watchdog.service', 'WantedBy=multi-user.target')))
        self.assertTrue(ordering_cycle(unit.replace('[Service]', 'Before=kubelet.service\n[Service]')))

    def test_vps_ordering_unchanged(self):
        for site in ('msk', 'fin'):
            unit = render(site)
            self.assertIn('WantedBy=multi-user.target', unit)
            self.assertIn('Before=kubelet.service', unit)
            self.assertNotIn('Requires=watchdog.service', unit)
            self.assertNotIn('--preserve-home-watchdog', unit)
            self.assertFalse(ordering_cycle(unit))

    def test_migration_removes_only_legacy_link_without_stopping_service(self):
        removals = [t['ansible.builtin.file'] for t in PLAY['tasks'] if t.get('ansible.builtin.file', {}).get('state') == 'absent']
        self.assertEqual(removals, [{'path': '/etc/systemd/system/multi-user.target.wants/infra-patroni-watchdog.service', 'state': 'absent'}])
        self.assertFalse(any(t.get('ansible.builtin.systemd_service', {}).get('state') in ('stopped', 'restarted') for t in PLAY['tasks']))


if __name__ == '__main__': unittest.main()
