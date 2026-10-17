#!/usr/bin/env python3
"""Offline safety tests; never run filesystem formatting, mounts or systemd."""
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('volume', pathlib.Path(__file__).with_name('logging-volume.py'))
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
UID = '11111111-1111-4111-8111-111111111111'

class Guards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.p = pathlib.Path(self.tmp.name)
        self.calls = []
        values = {'ROOT': self.p/'volume', 'IMAGE': self.p/'volume'/'loki.ext4',
                  'MOUNT': self.p/'volume'/'loki', 'DATA': self.p/'volume'/'loki'/'data',
                  'MARK': self.p/'owner.json', 'UNIT': self.p/'loki.mount', 'GUARD': self.p/'guard.service',
                  'MACHINE': self.p/'machine', 'STATE': self.p/'state', 'CA': self.p/'ca'}
        for key, value in values.items():
            p = patch.object(v, key, value); p.start(); self.addCleanup(p.stop)
        v.MACHINE.write_bytes(b'owned machine'); v.CA.write_bytes(b'owned ca')
        self.marker = {'managed_by':'infra-flux/ansible/kubeadm','node_name':'home','cluster_name':'unified',
                       'ca_sha256': hashlib.sha256(v.CA.read_bytes()).hexdigest()}
        v.STATE.write_text(json.dumps(self.marker))
        def command(argv):
            self.calls.append(argv)
            if argv[0] == 'kubectl': return json.dumps({'metadata': {'uid': UID}})
            raise AssertionError('Mutation command unexpectedly reached: '+repr(argv))
        p=patch.object(v, 'command', side_effect=command); p.start(); self.addCleanup(p.stop)
        # Non-root CI can exercise path/ordering guards without pretending to mount anything.
        for key in ['regular','directory']:
            p=patch.object(v,key); p.start(); self.addCleanup(p.stop)
        p=patch.object(v.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=200*1024**3,f_frsize=1)); p.start(); self.addCleanup(p.stop)
    def assert_readonly_failure(self, text):
        with self.assertRaisesRegex(RuntimeError,text): v.prepare(UID)
        self.assertTrue(all(c[0]=='kubectl' for c in self.calls))
    def record(self, **updates):
        v.ROOT.mkdir(mode=0o711, exist_ok=True); v.ROOT.chmod(0o711)
        d={'owner':v.OWNER,'phase':'ready','image':str(v.IMAGE),'mount':str(v.MOUNT),'bytes':v.BYTES,
           'machine_sha256':hashlib.sha256(v.MACHINE.read_bytes()).hexdigest(),'cluster_uid':UID,
           'ca_sha256':self.marker['ca_sha256'],'filesystem_uuid':UID,'image_identity':{'device':1,'inode':2}}
        d.update(updates); v.MARK.write_text(json.dumps(d)); return d
    def test_existing_unowned_directory(self):
        v.ROOT.mkdir(); self.assert_readonly_failure('unowned path')
    def test_dangling_unowned_symlink(self):
        v.ROOT.symlink_to(self.p/'absent'); self.assert_readonly_failure('unowned path')
    def test_existing_unit(self):
        v.UNIT.write_text('foreign unit'); self.assert_readonly_failure('unowned path')
    def test_low_free_space_before_allocation(self):
        with patch.object(v.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=v.RESERVE+v.BYTES-1,f_frsize=1)):
            self.assert_readonly_failure('reserve')
    def test_wrong_node(self):
        self.marker['node_name']='msk'; v.STATE.write_text(json.dumps(self.marker)); self.assert_readonly_failure('owned home')
    def test_changed_ca(self):
        v.CA.write_bytes(b'other ca'); self.assert_readonly_failure('CA ownership')
    def test_changed_cluster_uid(self):
        with self.assertRaisesRegex(RuntimeError,'Live cluster UID'): v.prepare('22222222-2222-4222-8222-222222222222')
    def test_incomplete_intent_never_reformats(self):
        self.record(phase='intent'); self.assert_readonly_failure('Incomplete preparation')
    def test_foreign_owner(self):
        self.record(owner='somebody else'); self.assert_readonly_failure('Foreign logging')
    def test_machine_changed(self):
        self.record(machine_sha256='0'*64); self.assert_readonly_failure('Machine identity')
    def test_image_replaced(self):
        self.record()
        with patch.object(v,'image_shape',return_value={'device':1,'inode':3}): self.assert_readonly_failure('Backing file identity')
    def test_idempotent_prepare_does_not_mutate(self):
        self.record()
        with patch.object(v,'image_shape',return_value={'device':1,'inode':2}),patch.object(v,'verify') as verify,patch.object(v,'check_enabled'):
            self.assertFalse(v.prepare(UID)); verify.assert_called_once()
        self.assertEqual(len(self.calls),1)
    def test_missing_enabled_unit_fails_closed(self):
        self.record()
        with patch.object(v,'image_shape',return_value={'device':1,'inode':2}),patch.object(v,'verify'),patch.object(v,'check_enabled',side_effect=RuntimeError('not enabled')):
            self.assert_readonly_failure('not enabled')
    def test_mount_cannot_be_root_filesystem(self):
        v.ROOT.mkdir(); v.MOUNT.mkdir(mode=0o700)
        self.calls.clear()
        with patch.object(v,'mount_directory'), patch.object(v,'command',return_value=json.dumps({'filesystems':[{'target':str(v.MOUNT),'source':'/dev/sda1','fstype':'ext4','options':'rw,nodev,nosuid,noexec'}]})):
            with self.assertRaisesRegex(RuntimeError,'loop device'): v.check_mount({'filesystem_uuid':UID})
    def test_mount_missing_restriction(self):
        v.ROOT.mkdir(); v.MOUNT.mkdir(mode=0o700)
        with patch.object(v,'mount_directory'), patch.object(v,'command',return_value=json.dumps({'filesystems':[{'target':str(v.MOUNT),'source':'/dev/loop0','fstype':'ext4','options':'rw'}]})):
            with self.assertRaisesRegex(RuntimeError,'mount shape'): v.check_mount({'filesystem_uuid':UID})
    def test_unit_drift_rejected(self):
        v.ROOT.mkdir(mode=0o711); v.ROOT.chmod(0o711)
        v.UNIT.write_text('modified'); v.GUARD.write_text(v.guard_unit())
        with self.assertRaisesRegex(RuntimeError,'unit changed'): v.verify({})
    def test_failed_mount_never_creates_root_data_directory(self):
        def no_mutating_commands(argv):
            self.calls.append(argv)
            if argv[0]=='kubectl': return json.dumps({'metadata':{'uid':UID}})
            return ''  # Simulate utility return only; no fallocate, mkfs or systemctl runs.
        with patch.object(v,'command',side_effect=no_mutating_commands), patch.object(v,'image_shape',return_value={'device':1,'inode':2}), patch.object(v,'check_mount',side_effect=RuntimeError('mount rejected')):
            with self.assertRaisesRegex(RuntimeError,'mount rejected'): v.prepare(UID)
        self.assertTrue(v.MOUNT.is_dir())
        self.assertFalse(v.DATA.exists())
        self.assertEqual(json.loads(v.MARK.read_text())['phase'],'intent')
        self.assertEqual(v.IMAGE.stat().st_size,0)

    def test_post_mount_sparse_shape_keeps_identity(self):
        item=types.SimpleNamespace(st_size=v.BYTES,st_blocks=(v.BYTES-64*1024**2)//512,st_dev=1,st_ino=2)
        with patch.object(v,'regular',return_value=item):
            self.assertEqual(v.image_shape(),{'device':1,'inode':2})
            with self.assertRaisesRegex(RuntimeError,'before formatting'):v.image_shape(require_fully_allocated=True)
    def test_sparse_headroom_must_be_available(self):
        missing=64*1024**2
        item=types.SimpleNamespace(st_size=v.BYTES,st_blocks=(v.BYTES-missing)//512,st_dev=1,st_ino=2)
        with patch.object(v,'regular',return_value=item),patch.object(v.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=v.RESERVE+missing-1,f_frsize=1)):
            with self.assertRaisesRegex(RuntimeError,'unallocated-byte headroom'):v.check_root_reserve()
        with patch.object(v,'regular',return_value=item),patch.object(v.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=v.RESERVE+missing,f_frsize=1)):
            self.assertEqual(v.check_root_reserve()['image_unallocated_bytes'],missing)
    def test_changed_image_length_is_never_accepted(self):
        item=types.SimpleNamespace(st_size=v.BYTES+4096,st_blocks=v.BYTES//512,st_dev=1,st_ino=2)
        with patch.object(v,'regular',return_value=item):
            with self.assertRaisesRegex(RuntimeError,'exactly 4 GiB'):v.image_shape()

    def test_preallocation_never_discarded(self):
        import ast
        tree=ast.parse(pathlib.Path(v.__file__).read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='command' and n.args and isinstance(n.args[0],ast.List)]
        mkfs=[n.args[0].elts for n in calls if n.args[0].elts and isinstance(n.args[0].elts[0],ast.Constant) and n.args[0].elts[0].value=='mkfs.ext4']
        self.assertEqual(len(mkfs),1)
        self.assertIn('nodiscard',[n.value for n in mkfs[0] if isinstance(n,ast.Constant)])
        self.assertEqual(ast.unparse(mkfs[0][-1]),'str(IMAGE)')

    def configure_upgrade(self):
        self.record(); v.ROOT.chmod(0o700); v.MOUNT.mkdir(mode=0o755); v.MOUNT.chmod(0o755)
        script=(self.p/'installed.py').resolve(); script.write_bytes(b'owned reviewed helper fixture')
        for key,value in [('SCRIPT',script),('__file__',str(script))]:
            p=patch.object(v,key,value);p.start();self.addCleanup(p.stop)
        for key in ['verify','check_enabled']:
            p=patch.object(v,key);p.start();self.addCleanup(p.stop)
        p=patch.object(v,'image_shape',return_value={'device':1,'inode':2});p.start();self.addCleanup(p.stop)
        original_fstat=os.fstat
        def root_fstat(fd):
            item=original_fstat(fd)
            return types.SimpleNamespace(st_dev=item.st_dev,st_ino=item.st_ino,st_mode=item.st_mode,st_uid=0,st_gid=0)
        p=patch.object(v.os,'fstat',side_effect=root_fstat);p.start();self.addCleanup(p.stop)
        root=v.ROOT.stat();mount=v.MOUNT.stat()
        return [UID,hashlib.sha256(script.read_bytes()).hexdigest(),root.st_dev,root.st_ino,mount.st_dev,mount.st_ino]
    def test_upgrade_exact_owned_directories_only_and_idempotent(self):
        args=self.configure_upgrade()
        self.assertTrue(v.enable_metrics_traversal(*args))
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o711)
        self.assertEqual(stat.S_IMODE(v.MOUNT.stat().st_mode),0o700)
        self.assertFalse(v.enable_metrics_traversal(*args))
        self.assertTrue(all(c[0]=='kubectl' for c in self.calls))
    def test_upgrade_source_hash_drift_rejected_before_chmod(self):
        args=self.configure_upgrade();args[1]='0'*64
        with self.assertRaisesRegex(RuntimeError,'source differs'):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE(v.MOUNT.stat().st_mode),0o755)
    def test_upgrade_second_directory_inode_drift_rejects_before_any_chmod(self):
        args=self.configure_upgrade();args[5]+=1
        with self.assertRaisesRegex(RuntimeError,'identity changed'):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE(v.MOUNT.stat().st_mode),0o755)
    def test_upgrade_foreign_directory_owner_rejected(self):
        args=self.configure_upgrade(); original_fstat=os.stat(v.ROOT)
        fake=types.SimpleNamespace(st_dev=original_fstat.st_dev,st_ino=original_fstat.st_ino,st_mode=original_fstat.st_mode,st_uid=123,st_gid=0)
        with patch.object(v.os,'fstat',return_value=fake):
            with self.assertRaisesRegex(RuntimeError,'owner or mode'):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)
    def test_upgrade_unexpected_mount_mode_rejected_before_any_chmod(self):
        args=self.configure_upgrade();v.MOUNT.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'owner or mode'):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)
    def test_upgrade_cluster_mismatch_rejected(self):
        args=self.configure_upgrade();args[0]='22222222-2222-4222-8222-222222222222'
        with self.assertRaisesRegex(RuntimeError,'Live cluster UID'):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)
    def test_normal_load_rejects_legacy_parent(self):
        self.record();v.ROOT.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,'traverse-only'):v.load_record()
    def test_root_mode_drift_rejected_even_in_explicit_upgrade(self):
        self.record();v.ROOT.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'traverse-only'):v.load_record(allow_legacy_permissions=True)
    def test_mount_mode_requires_private_or_explicit_legacy(self):
        v.ROOT.mkdir();v.MOUNT.mkdir(mode=0o755)
        item=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0)
        with patch.object(pathlib.Path,'lstat',return_value=item):
            with self.assertRaisesRegex(RuntimeError,'private 0700'):v.mount_directory()
            v.mount_directory(allow_legacy_mode=True)
    def test_upgrade_refuses_symlink_directory(self):
        args=self.configure_upgrade();v.MOUNT.rmdir();v.MOUNT.symlink_to(v.ROOT)
        with self.assertRaises(OSError):v.enable_metrics_traversal(*args)
        self.assertEqual(stat.S_IMODE(v.ROOT.stat().st_mode),0o700)

if __name__=='__main__': unittest.main()
