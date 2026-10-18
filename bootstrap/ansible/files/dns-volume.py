#!/usr/bin/env python3
"""Prepare an owned 256 MiB DNS cache volume on a managed VPS, never a host device.

Interrupted formatting is never retried: the recorded UUID and a read-only fsck
must prove that it completed. An unrecorded file/directory requires inspection.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import uuid

ROOT = pathlib.Path('/var/lib/infra-dns')
IMAGE = ROOT / 'bind.ext4'
MOUNT = ROOT / 'bind'
DATA = MOUNT / 'data'
MARK = pathlib.Path('/etc/infra-flux/dns-volume.json')
LOCK = pathlib.Path('/etc/infra-flux/dns-volume.lock')
SCRIPT = pathlib.Path('/etc/infra-flux/dns-volume.py')
UNIT = pathlib.Path('/etc/systemd/system/var-lib-infra\\x2ddns-bind.mount')
GUARD = pathlib.Path('/etc/systemd/system/infra-dns-volume.service')
STATE = pathlib.Path('/etc/infra-flux/kubeadm-state.json')
MACHINE = pathlib.Path('/etc/machine-id')
CA = pathlib.Path('/etc/kubernetes/pki/ca.crt')
OWNER = 'infra-flux/dns-volume-v1'
BYTES = 256 * 1024**2
RESERVE = 20 * 1024**3
PHASES = ['intent', 'directories', 'image', 'allocated', 'formatting',
          'formatted', 'units', 'mounted', 'data', 'ready']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(argv, accepted=(0,)):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    require(p.returncode in accepted, 'Command failed: ' + argv[0])
    require(len(p.stdout) <= 1024**2, 'Command output exceeds bound')
    return p.stdout.strip()


def regular(path, mode=None):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and s.st_nlink == 1
            and not s.st_mode & 0o022, 'Untrusted file: ' + str(path))
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'Unexpected file mode: ' + str(path))
    return s


def directory(path, mode=None):
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0
            and not s.st_mode & 0o022, 'Untrusted directory: ' + str(path))
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'Unexpected directory mode: ' + str(path))
    return s


def identity(s):
    return {'device': s.st_dev, 'inode': s.st_ino}


def atomic(path, text, mode=0o600):
    if path.exists() or path.is_symlink():
        regular(path, mode)
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()


def save(record, phase):
    record['phase'] = phase
    atomic(MARK, json.dumps(record, indent=2) + '\n')


def check_cluster(expected_uid, expected_ca, expected_node):
    require(expected_node in ('msk', 'fin'), 'Only the two managed VPS nodes are allowed')
    regular(STATE, 0o600); regular(CA)
    state = json.loads(STATE.read_text())
    require(state.get('managed_by') == 'infra-flux/ansible/kubeadm'
            and state.get('cluster_name') == 'unified'
            and state.get('node_name') == expected_node, 'Not the expected managed VPS')
    ca = hashlib.sha256(CA.read_bytes()).hexdigest()
    require(ca == expected_ca == state.get('ca_sha256'), 'Kubernetes CA identity differs')
    live = json.loads(command(['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                              '--request-timeout=10s', 'get', 'namespace', 'kube-system', '-o', 'json']))
    require(live['metadata']['uid'] == expected_uid, 'Live cluster UID differs')


def load_record():
    regular(MARK, 0o600)
    require(MARK.stat().st_size <= 8192, 'Ownership record exceeds bound')
    record = json.loads(MARK.read_text())
    require(record.get('owner') == OWNER and record.get('image') == str(IMAGE)
            and record.get('mount') == str(MOUNT) and record.get('bytes') == BYTES
            and record.get('node') in ('msk', 'fin'), 'Foreign DNS volume ownership')
    require(record.get('machine_sha256') == hashlib.sha256(MACHINE.read_bytes()).hexdigest(),
            'Machine identity differs')
    require(record.get('ca_sha256') == hashlib.sha256(CA.read_bytes()).hexdigest(), 'CA identity differs')
    require(record.get('phase') in PHASES, 'Unknown preparation phase')
    require(str(uuid.UUID(record['filesystem_uuid'])) == record['filesystem_uuid'], 'Invalid filesystem UUID')
    return record


def image_shape(record, full=False):
    directory(ROOT, 0o711)
    s = regular(IMAGE, 0o600)
    require(identity(s) == record.get('image_identity'), 'Backing file identity changed')
    require(s.st_size == BYTES, 'Image must be exactly 256 MiB')
    if full:
        require(s.st_blocks * 512 >= BYTES, 'Image must be fully reserved before formatting')
    return s


def reserve(image=None):
    missing = 0 if image is None else max(0, BYTES - image.st_blocks * 512)
    fs = os.statvfs('/')
    available = fs.f_bavail * fs.f_frsize
    require(available >= RESERVE + missing, 'Keep 20 GiB root reserve plus unallocated image headroom')
    return available


def mount_unit():
    return f'''[Unit]
Description=Owned bounded authoritative DNS cache filesystem
Before=kubelet.service
[Mount]
What={IMAGE}
Where={MOUNT}
Type=ext4
Options=loop,nosuid,nodev,noexec
TimeoutSec=30
[Install]
WantedBy=local-fs.target
'''


def guard_unit():
    return f'''[Unit]
Description=Verify owned DNS filesystem before workload startup
RequiresMountsFor={MOUNT}
Before=kubelet.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {SCRIPT} verify
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''


def mounted():
    out = command(['findmnt', '--json', '--mountpoint', str(MOUNT), '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS'], (0, 1))
    return json.loads(out).get('filesystems', []) if out else []


def check_mount(record, initial=False):
    directory(ROOT, 0o711)
    directory(MOUNT, None if initial else 0o700)
    mounts = mounted()
    require(len(mounts) == 1, 'Expected the exact DNS mount')
    m = mounts[0]
    require(m['target'] == str(MOUNT) and m['fstype'] == 'ext4'
            and {'rw', 'nosuid', 'nodev', 'noexec'} <= set(m['options'].split(',')), 'Unexpected mount shape')
    source = m['source']
    require(re.fullmatch(r'/dev/loop[0-9]+', source), 'Only a simple loop device is permitted')
    require(stat.S_ISBLK(pathlib.Path(source).stat().st_mode), 'Not a block device')
    loops = json.loads(command(['losetup', '--json', '--list', '--output', 'NAME,BACK-FILE']))['loopdevices']
    matches = [x for x in loops if x['name'] == source]
    require(len(matches) == 1 and matches[0]['back-file'] == str(IMAGE), 'Loop backing file differs')
    require(command(['blkid', '-s', 'UUID', '-o', 'value', source]) == record['filesystem_uuid'],
            'Filesystem UUID differs')
    fs = os.statvfs(MOUNT)
    require(192 * 1024**2 < fs.f_blocks * fs.f_frsize <= BYTES, 'Unexpected filesystem hard capacity')
    require(MOUNT.stat().st_dev != ROOT.stat().st_dev, 'DNS data is on the root filesystem')


def verify(record):
    require(record['phase'] in ('data', 'ready'), 'Volume preparation is incomplete')
    require(identity(directory(ROOT, 0o711)) == record['root_identity'], 'Parent directory identity changed')
    image_shape(record)
    for unit, content in [(UNIT, mount_unit()), (GUARD, guard_unit())]:
        regular(unit, 0o644)
        require(unit.read_text() == content, 'Owned systemd unit changed')
    check_mount(record)
    s = DATA.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 53 and s.st_gid == 53
            and stat.S_IMODE(s.st_mode) == 0o700, 'Unexpected DNS data directory owner or mode')
    # Loop device numbers may change after boot; the filesystem UUID was checked above.
    require(s.st_ino == record['data_inode'], 'DNS data directory inode changed')
    reserve(image_shape(record))


def check_enabled():
    for unit in (UNIT, GUARD):
        require(command(['systemctl', 'is-enabled', unit.name]) == 'enabled', 'Persistent unit is not enabled')
        require(command(['systemctl', 'is-active', unit.name]) == 'active', 'Persistent unit is not active')


def prepare(uid, ca, node):
    check_cluster(uid, ca, node)
    if MARK.exists() or MARK.is_symlink():
        record = load_record()
        require((record['cluster_uid'], record['ca_sha256'], record['node']) == (uid, ca, node),
                'Cluster or node ownership differs')
        if record['phase'] == 'ready':
            verify(record); check_enabled()
            return False
    else:
        for path in (ROOT, IMAGE, MOUNT, DATA, UNIT, GUARD):
            require(not path.exists() and not path.is_symlink(), 'Refuse existing unowned path: ' + str(path))
        require(reserve() >= RESERVE + BYTES, 'New DNS volume would consume the root reserve')
        record = {'owner': OWNER, 'phase': 'intent', 'image': str(IMAGE), 'mount': str(MOUNT),
                  'bytes': BYTES, 'node': node, 'cluster_uid': uid, 'ca_sha256': ca,
                  'machine_sha256': hashlib.sha256(MACHINE.read_bytes()).hexdigest(),
                  'filesystem_uuid': str(uuid.uuid4())}
        save(record, 'intent')
    if record['phase'] == 'intent':
        require(not ROOT.exists() and not ROOT.is_symlink(), 'Unrecorded directory requires inspection')
        ROOT.mkdir(mode=0o711); ROOT.chmod(0o711); MOUNT.mkdir(mode=0o700)
        record['root_identity'] = identity(directory(ROOT, 0o711))
        record['mountpoint_identity'] = identity(directory(MOUNT, 0o700))
        save(record, 'directories')
    require(identity(directory(ROOT, 0o711)) == record['root_identity'], 'Parent directory identity changed')
    if record['phase'] == 'directories':
        require(not IMAGE.exists() and not IMAGE.is_symlink(), 'Unrecorded image requires inspection')
        fd = os.open(IMAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            record['image_identity'] = identity(os.fstat(fd))
        finally:
            os.close(fd)
        save(record, 'image')
    if record['phase'] == 'image':
        s = regular(IMAGE, 0o600)
        require(identity(s) == record['image_identity'] and s.st_size in (0, BYTES), 'Unexpected initial image')
        require(not command(['blkid', '-p', '-o', 'export', str(IMAGE)], (0, 2)), 'Initial image has a filesystem signature')
        reserve(s)
        command(['fallocate', '--length', str(BYTES), str(IMAGE)])
        image_shape(record, full=True); save(record, 'allocated')
    if record['phase'] == 'allocated':
        image_shape(record, full=True)
        require(not mounted(), 'Refuse formatting a mounted image')
        require(not command(['blkid', '-p', '-o', 'export', str(IMAGE)], (0, 2)), 'Refuse formatting an existing filesystem')
        save(record, 'formatting')
        # Only our O_EXCL-created, inode-bound regular file can reach this command.
        command(['mkfs.ext4', '-F', '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0',
                 '-m', '0', '-U', record['filesystem_uuid'], '-L', 'infra-dns', str(IMAGE)])
    if record['phase'] == 'formatting':
        # A crash during mkfs requires a complete, clean filesystem; never format it again.
        image_shape(record)
        require(not mounted(), 'Unexpected mount during formatting recovery')
        require(command(['blkid', '-s', 'UUID', '-o', 'value', str(IMAGE)]) == record['filesystem_uuid'],
                'Incomplete formatting requires inspection; UUID differs')
        command(['e2fsck', '-f', '-n', str(IMAGE)])
        save(record, 'formatted')
    image_shape(record)
    if record['phase'] == 'formatted':
        for unit, content in [(UNIT, mount_unit()), (GUARD, guard_unit())]:
            if unit.exists() or unit.is_symlink():
                regular(unit, 0o644)
                require(unit.read_text() == content, 'Unexpected unit during preparation resume')
            else:
                atomic(unit, content, 0o644)
        save(record, 'units')
    if record['phase'] == 'units':
        if mounted():
            check_mount(record, initial=True)
        else:
            require(identity(directory(MOUNT, 0o700)) == record['mountpoint_identity'],
                    'Underlying mountpoint identity changed')
            require(not list(MOUNT.iterdir()), 'Underlying mountpoint must be empty')
        for unit, content in [(UNIT, mount_unit()), (GUARD, guard_unit())]:
            regular(unit, 0o644)
            require(unit.read_text() == content, 'Owned systemd unit changed')
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'enable', '--now', UNIT.name])
        check_mount(record, initial=True); MOUNT.chmod(0o700); check_mount(record)
        save(record, 'mounted')
    if record['phase'] == 'mounted':
        check_mount(record)
        require(not DATA.exists() and not DATA.is_symlink(), 'Unrecorded data directory requires inspection')
        DATA.mkdir(mode=0o700); os.chown(DATA, 53, 53)
        record['data_inode'] = DATA.lstat().st_ino
        save(record, 'data')
    verify(record)
    command(['systemctl', 'enable', '--now', GUARD.name])
    check_enabled()
    save(record, 'ready')
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['prepare', 'verify'])
    p.add_argument('--expected-cluster-uid'); p.add_argument('--expected-ca-sha256')
    p.add_argument('--expected-node', choices=['msk', 'fin'])
    args = p.parse_args()
    require(os.geteuid() == 0, 'Root required')
    for path in ['/etc', '/etc/infra-flux', '/etc/systemd', '/etc/systemd/system', '/var', '/var/lib']:
        directory(pathlib.Path(path))
    if args.action == 'prepare':
        require(args.expected_cluster_uid and str(uuid.UUID(args.expected_cluster_uid)) == args.expected_cluster_uid,
                'Explicit canonical cluster UID required')
        require(re.fullmatch('[0-9a-f]{64}', args.expected_ca_sha256 or ''), 'Explicit CA SHA256 required')
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            regular(LOCK, 0o600); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            changed = prepare(args.expected_cluster_uid, args.expected_ca_sha256, args.expected_node)
        finally:
            os.close(fd)
    else:
        verify(load_record()); changed = False
    print(json.dumps({'ok': True, 'changed': changed, 'filesystem_hard_bytes': BYTES,
                      'data_path': str(DATA), 'existing_devices_formatted': False}))


if __name__ == '__main__':
    main()
