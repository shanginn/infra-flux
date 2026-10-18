#!/usr/bin/env python3
"""Offline safety tests: no formatting, mount or service commands are executed."""
import hashlib
import importlib.util
import json
import pathlib
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dns_volume', pathlib.Path(__file__).with_name('dns-volume.py'))
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
REAL_REGULAR = v.regular
REAL_DIRECTORY = v.directory
UID = '11111111-1111-4111-8111-111111111111'


class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        paths = {'ROOT': self.base/'volume', 'IMAGE': self.base/'volume'/'bind.ext4',
                 'MOUNT': self.base/'volume'/'bind', 'DATA': self.base/'volume'/'bind'/'data',
                 'MARK': self.base/'owner.json', 'UNIT': self.base/'dns.mount',
                 'GUARD': self.base/'guard.service', 'MACHINE': self.base/'machine',
                 'STATE': self.base/'state.json', 'CA': self.base/'ca.crt'}
        for k, p in paths.items():
            obj = patch.object(v, k, p); obj.start(); self.addCleanup(obj.stop)
        v.MACHINE.write_bytes(b'machine fixture'); v.CA.write_bytes(b'ca fixture')
        self.ca = hashlib.sha256(v.CA.read_bytes()).hexdigest()
        self.state = {'managed_by': 'infra-flux/ansible/kubeadm', 'cluster_name': 'unified',
                      'node_name': 'msk', 'ca_sha256': self.ca}
        v.STATE.write_text(json.dumps(self.state))
        self.calls = []
        def command(argv, accepted=(0,)):
            self.calls.append(argv)
            if argv[0] == 'kubectl':
                return json.dumps({'metadata': {'uid': UID}})
            raise AssertionError('Unexpected command: '+repr(argv))
        obj = patch.object(v, 'command', side_effect=command); obj.start(); self.addCleanup(obj.stop)
        # Root ownership is independently covered below; path/phase tests run as any CI user.
        def regular(path, mode=None):
            s = path.lstat()
            if not stat.S_ISREG(s.st_mode):
                raise RuntimeError('Untrusted file')
            return s
        def directory(path, mode=None):
            s = path.lstat()
            if not stat.S_ISDIR(s.st_mode):
                raise RuntimeError('Untrusted directory')
            return s
        for name, function in [('regular', regular), ('directory', directory)]:
            obj = patch.object(v, name, side_effect=function); obj.start(); self.addCleanup(obj.stop)
        obj = patch.object(v.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=50*1024**3, f_frsize=1))
        obj.start(); self.addCleanup(obj.stop)

    def prepare(self):
        return v.prepare(UID, self.ca, 'msk')

    def fail_readonly(self, text):
        with self.assertRaisesRegex(RuntimeError, text):
            self.prepare()
        self.assertTrue(all(x[0] == 'kubectl' for x in self.calls))

    def record(self, phase='ready', **extra):
        v.ROOT.mkdir(mode=0o711, exist_ok=True); v.MOUNT.mkdir(mode=0o700, exist_ok=True)
        record = {'owner': v.OWNER, 'phase': phase, 'image': str(v.IMAGE), 'mount': str(v.MOUNT),
                  'bytes': v.BYTES, 'node': 'msk', 'cluster_uid': UID, 'ca_sha256': self.ca,
                  'machine_sha256': hashlib.sha256(v.MACHINE.read_bytes()).hexdigest(),
                  'filesystem_uuid': UID, 'root_identity': v.identity(v.ROOT.stat()),
                  'mountpoint_identity': v.identity(v.MOUNT.stat()), 'image_identity': {'device': 1, 'inode': 2}}
        record.update(extra); v.MARK.write_text(json.dumps(record)); return record

    def test_foreign_existing_directory_is_not_adopted(self):
        v.ROOT.mkdir(); self.fail_readonly('unowned path')

    def test_dangling_symlink_is_not_adopted(self):
        v.ROOT.symlink_to(self.base/'absent'); self.fail_readonly('unowned path')

    def test_existing_systemd_unit_is_not_replaced(self):
        v.UNIT.write_text('foreign'); self.fail_readonly('unowned path')

    def test_home_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'two managed VPS'):
            v.prepare(UID, self.ca, 'home')
        self.assertEqual(self.calls, [])

    def test_wrong_node_marker_is_rejected_before_kubectl(self):
        self.state['node_name'] = 'fin'; v.STATE.write_text(json.dumps(self.state))
        self.fail_readonly('expected managed VPS'); self.assertEqual(self.calls, [])

    def test_ca_mismatch_is_rejected(self):
        v.CA.write_bytes(b'foreign'); self.fail_readonly('CA identity')

    def test_cluster_uid_mismatch_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Live cluster UID'):
            v.prepare('22222222-2222-4222-8222-222222222222', self.ca, 'msk')
        self.assertFalse(v.MARK.exists())

    def test_reserve_is_checked_before_creating_any_file(self):
        with patch.object(v.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=v.RESERVE+v.BYTES-1, f_frsize=1)):
            self.fail_readonly('root reserve')
        self.assertFalse(v.MARK.exists())

    def test_foreign_marker_owner_rejected(self):
        self.record(owner='other'); self.fail_readonly('Foreign DNS')

    def test_other_machine_record_rejected(self):
        self.record(machine_sha256='0'*64); self.fail_readonly('Machine identity')

    def test_unrecorded_interrupted_creation_is_not_adopted(self):
        self.record('intent'); self.fail_readonly('Unrecorded directory')

    def test_image_created_without_record_requires_inspection(self):
        self.record('directories'); v.IMAGE.write_bytes(b'foreign')
        self.fail_readonly('Unrecorded image')

    def test_ready_idempotent_does_not_mutate(self):
        record = self.record()
        with patch.object(v, 'verify') as verify, patch.object(v, 'check_enabled'):
            self.assertFalse(self.prepare()); verify.assert_called_once_with(record)
        self.assertTrue(all(x[0] == 'kubectl' for x in self.calls))

    def test_changed_root_inode_blocks_resume(self):
        self.record('formatted', root_identity={'device': 1, 'inode': 2})
        self.fail_readonly('Parent directory identity')

    def test_resume_formatted_never_reformats(self):
        self.record('formatted'); v.UNIT.write_text('foreign replacement')
        with patch.object(v, 'image_shape'):
            self.fail_readonly('Unexpected unit')

    def test_resume_formatting_checks_uuid_without_reformat(self):
        self.record('formatting')
        def command(argv, accepted=(0,)):
            self.calls.append(argv)
            if argv[0] == 'kubectl': return json.dumps({'metadata': {'uid': UID}})
            if argv[0] == 'blkid': return 'different-uuid'
            raise AssertionError('Unexpected mutation: '+repr(argv))
        with patch.object(v, 'image_shape'), patch.object(v, 'mounted', return_value=[]), patch.object(v, 'command', side_effect=command):
            with self.assertRaisesRegex(RuntimeError, 'Incomplete formatting'):
                self.prepare()
        self.assertNotIn('mkfs.ext4', [x[0] for x in self.calls])

    def test_existing_filesystem_signature_never_formats(self):
        self.record('allocated')
        def command(argv, accepted=(0,)):
            self.calls.append(argv)
            if argv[0] == 'kubectl': return json.dumps({'metadata': {'uid': UID}})
            if argv[0] == 'blkid': return 'TYPE=ext4'
            raise AssertionError('Unexpected mutation: '+repr(argv))
        with patch.object(v, 'image_shape'), patch.object(v, 'mounted', return_value=[]), patch.object(v, 'command', side_effect=command):
            with self.assertRaisesRegex(RuntimeError, 'existing filesystem'):
                self.prepare()
        self.assertNotIn('mkfs.ext4', [x[0] for x in self.calls])

    def test_failed_mount_never_creates_data_on_root(self):
        self.record('units'); v.UNIT.write_text(v.mount_unit()); v.GUARD.write_text(v.guard_unit())
        def command(argv, accepted=(0,)):
            self.calls.append(argv)
            if argv[0] == 'kubectl': return json.dumps({'metadata': {'uid': UID}})
            if argv[0] == 'systemctl': return ''
            raise AssertionError('Unexpected command: '+repr(argv))
        with patch.object(v, 'image_shape'), patch.object(v, 'mounted', return_value=[]), patch.object(v, 'check_mount', side_effect=RuntimeError('mount failed')), patch.object(v, 'command', side_effect=command):
            with self.assertRaisesRegex(RuntimeError, 'mount failed'):
                self.prepare()
        self.assertFalse(v.DATA.exists()); self.assertEqual(json.loads(v.MARK.read_text())['phase'], 'units')

    def test_physical_disk_mount_is_rejected(self):
        self.record()
        foreign = [{'target': str(v.MOUNT), 'source': '/dev/sda1', 'fstype': 'ext4', 'options': 'rw,nosuid,nodev,noexec'}]
        with patch.object(v, 'mounted', return_value=foreign):
            with self.assertRaisesRegex(RuntimeError, 'simple loop device'):
                v.check_mount({'filesystem_uuid': UID})

    def test_unsafe_mount_flags_are_rejected(self):
        self.record()
        foreign = [{'target': str(v.MOUNT), 'source': '/dev/loop1', 'fstype': 'ext4', 'options': 'rw'}]
        with patch.object(v, 'mounted', return_value=foreign):
            with self.assertRaisesRegex(RuntimeError, 'mount shape'):
                v.check_mount({'filesystem_uuid': UID})

    def test_changed_image_inode_rejected(self):
        record = self.record(); v.IMAGE.write_bytes(b'')
        with self.assertRaisesRegex(RuntimeError, 'Backing file identity'):
            v.image_shape(record)

    def test_sparse_allocation_requires_extra_root_headroom(self):
        missing = 8*1024**2
        image = types.SimpleNamespace(st_blocks=(v.BYTES-missing)//512)
        with patch.object(v.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=v.RESERVE+missing-1, f_frsize=1)):
            with self.assertRaisesRegex(RuntimeError, 'unallocated image headroom'):
                v.reserve(image)

    def simulated_preparation(self, fail_guard_once=False):
        failed = [False]
        def command(argv, accepted=(0,)):
            self.calls.append(argv)
            if argv[0] == 'kubectl': return json.dumps({'metadata': {'uid': UID}})
            if argv[0] == 'blkid':
                return '' if '-p' in argv else json.loads(v.MARK.read_text())['filesystem_uuid']
            if argv[0] == 'systemctl':
                if argv[1] == 'is-enabled': return 'enabled'
                if argv[1] == 'is-active': return 'active'
                if fail_guard_once and argv[-1] == v.GUARD.name and not failed[0]:
                    failed[0] = True; raise RuntimeError('guard start interrupted')
                return ''
            if argv[0] in ('fallocate', 'mkfs.ext4', 'e2fsck'): return ''
            raise AssertionError('Unexpected command: '+repr(argv))
        for name, kwargs in [('command', {'side_effect': command}), ('image_shape', {}),
                             ('mounted', {'return_value': []}), ('check_mount', {}), ('verify', {})]:
            obj = patch.object(v, name, **kwargs); obj.start(); self.addCleanup(obj.stop)
        obj = patch.object(v.os, 'chown'); obj.start(); self.addCleanup(obj.stop)

    def test_complete_preparation_formats_exact_owned_file_once(self):
        self.simulated_preparation()
        self.assertTrue(self.prepare()); self.assertFalse(self.prepare())
        self.assertEqual(json.loads(v.MARK.read_text())['phase'], 'ready')
        formats = [x for x in self.calls if x[0] == 'mkfs.ext4']
        self.assertEqual(len(formats), 1); self.assertEqual(formats[0][-1], str(v.IMAGE))
        self.assertIn('nodiscard,lazy_itable_init=0,lazy_journal_init=0', formats[0])
        self.assertTrue(v.DATA.is_dir())

    def test_interrupted_guard_start_resumes_without_format_or_reallocation(self):
        self.simulated_preparation(fail_guard_once=True)
        with self.assertRaisesRegex(RuntimeError, 'guard start interrupted'):
            self.prepare()
        self.assertEqual(json.loads(v.MARK.read_text())['phase'], 'data')
        checkpoint = len(self.calls)
        self.assertTrue(self.prepare())
        self.assertEqual(json.loads(v.MARK.read_text())['phase'], 'ready')
        self.assertFalse(any(x[0] in ('mkfs.ext4', 'fallocate') for x in self.calls[checkpoint:]))


class Ownership(unittest.TestCase):
    def test_data_initial_and_kubelet_fsgroup_modes_are_accepted(self):
        for mode in (0o700, 0o2770):
            item = types.SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=53, st_gid=53, st_ino=42)
            with patch.object(pathlib.Path, 'lstat', return_value=item):
                v.check_data({'data_inode': 42})

    def test_data_world_access_and_unexpected_modes_are_rejected(self):
        for mode in (0o777, 0o2777, 0o755, 0o770, 0o2700):
            item = types.SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=53, st_gid=53, st_ino=42)
            with patch.object(pathlib.Path, 'lstat', return_value=item):
                with self.assertRaisesRegex(RuntimeError, 'owner or mode'):
                    v.check_data({'data_inode': 42})

    def test_data_fsgroup_mode_does_not_relax_owner_or_inode(self):
        for uid, gid, inode in [(0, 53, 42), (53, 0, 42), (53, 53, 43)]:
            item = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o2770, st_uid=uid, st_gid=gid, st_ino=inode)
            with patch.object(pathlib.Path, 'lstat', return_value=item):
                with self.assertRaises(RuntimeError):
                    v.check_data({'data_inode': 42})

    def test_data_symlink_is_rejected_even_with_expected_uid_gid(self):
        item = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=53, st_gid=53, st_ino=42)
        with patch.object(pathlib.Path, 'lstat', return_value=item):
            with self.assertRaisesRegex(RuntimeError, 'owner or mode'):
                v.check_data({'data_inode': 42})

    def test_symlink_and_hardlinked_image_are_rejected(self):
        for mode, links in [(stat.S_IFLNK | 0o600, 1), (stat.S_IFREG | 0o600, 2)]:
            item = types.SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0, st_nlink=links)
            with patch.object(pathlib.Path, 'lstat', return_value=item):
                with self.assertRaisesRegex(RuntimeError, 'Untrusted file'):
                    REAL_REGULAR(pathlib.Path('/fixture'), 0o600)

    def test_non_root_owner_and_wrong_private_mode_are_rejected(self):
        item = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=53, st_gid=53, st_nlink=1)
        with patch.object(pathlib.Path, 'lstat', return_value=item):
            with self.assertRaisesRegex(RuntimeError, 'Untrusted file'):
                REAL_REGULAR(pathlib.Path('/fixture'), 0o600)
        item = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0, st_nlink=1)
        with patch.object(pathlib.Path, 'lstat', return_value=item):
            with self.assertRaisesRegex(RuntimeError, 'file mode'):
                REAL_REGULAR(pathlib.Path('/fixture'), 0o600)

    def test_world_writable_or_symlink_parent_is_rejected(self):
        for mode in (stat.S_IFDIR | 0o777, stat.S_IFLNK | 0o711):
            item = types.SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0)
            with patch.object(pathlib.Path, 'lstat', return_value=item):
                with self.assertRaisesRegex(RuntimeError, 'Untrusted directory'):
                    REAL_DIRECTORY(pathlib.Path('/fixture'), 0o711)


if __name__ == '__main__':
    unittest.main()
