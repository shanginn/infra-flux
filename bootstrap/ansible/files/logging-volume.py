#!/usr/bin/env python3
"""Create only an owned 4 GiB loop-backed log filesystem; never format a host device."""
import argparse, fcntl, hashlib, json, os, pathlib, stat, subprocess, uuid

ROOT = pathlib.Path('/var/lib/infra-logging')
IMAGE = ROOT / 'loki.ext4'
MOUNT = ROOT / 'loki'
DATA = MOUNT / 'data'
MARK = pathlib.Path('/etc/infra-flux/logging-volume.json')
UNIT = pathlib.Path('/etc/systemd/system/var-lib-infra\\x2dlogging-loki.mount')
GUARD = pathlib.Path('/etc/systemd/system/infra-logging-volume.service')
SCRIPT = pathlib.Path('/etc/infra-flux/logging-volume.py')
BYTES = 4 * 1024**3
RESERVE = 110 * 1024**3
OWNER = 'infra-flux/logging-volume-v1'
LOCK = pathlib.Path('/etc/infra-flux/logging-volume.lock')
MACHINE = pathlib.Path('/etc/machine-id')
STATE = pathlib.Path('/etc/infra-flux/kubeadm-state.json')
CA = pathlib.Path('/etc/kubernetes/pki/ca.crt')

def require(value, message):
    if not value:
        raise RuntimeError(message)

def command(args):
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=90)
    require(len(result.stdout) <= 1024**2, 'Command output exceeded bound')
    return result.stdout.strip()

def regular(path, private=False):
    item = path.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_uid == 0 and item.st_nlink == 1 and
            not item.st_mode & (0o077 if private else 0o022), 'Untrusted file: ' + str(path))
    return item

def directory(path):
    item = path.lstat()
    require(stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022,
            'Untrusted directory: ' + str(path))

def atomic(path, data, mode=0o600):
    if path.exists() or path.is_symlink():
        regular(path)
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if temp.exists(): temp.unlink()

def image_shape(require_fully_allocated=False):
    directory(ROOT)
    item = regular(IMAGE, True)
    require(item.st_size == BYTES, 'Log image must remain exactly 4 GiB')
    if require_fully_allocated:
        require(item.st_blocks * 512 >= BYTES, 'Initial log image must be physically reserved before formatting')
    return {'device': item.st_dev, 'inode': item.st_ino}

def allocation_status():
    image_shape()
    allocated = regular(IMAGE, True).st_blocks * 512
    unallocated = max(0, BYTES - allocated)
    root = os.statvfs('/')
    return {'image_allocated_bytes': allocated, 'image_unallocated_bytes': unallocated,
            'root_available_bytes': root.f_bavail * root.f_frsize,
            'required_root_available_bytes': RESERVE + unallocated}

def check_root_reserve():
    state = allocation_status()
    require(state['root_available_bytes'] >= state['required_root_available_bytes'],
            'Keep 110 GiB root free plus the image unallocated-byte headroom')
    return state

def check_mount(record):
    directory(ROOT); directory(MOUNT)
    mounts = json.loads(command(['findmnt', '--json', '--mountpoint', str(MOUNT), '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS']))['filesystems']
    require(len(mounts) == 1, 'Expected exact log mount')
    mount = mounts[0]
    require(mount['target'] == str(MOUNT) and mount['fstype'] == 'ext4' and
            {'rw', 'nosuid', 'nodev', 'noexec'}.issubset(set(mount['options'].split(','))), 'Unexpected mount shape')
    source = mount['source']
    require(source.startswith('/dev/loop') and '[' not in source, 'Mount is not a simple loop device')
    require(stat.S_ISBLK(pathlib.Path(source).stat().st_mode), 'Not a block device')
    loops = json.loads(command(['losetup', '--json', '--list', '--output', 'NAME,BACK-FILE']))['loopdevices']
    matches = [x for x in loops if x['name'] == source]
    require(len(matches) == 1 and matches[0]['back-file'] == str(IMAGE), 'Loop backing file differs')
    require(command(['blkid', '-s', 'UUID', '-o', 'value', source]) == record['filesystem_uuid'], 'Filesystem UUID differs')
    fs = os.statvfs(MOUNT)
    require(fs.f_blocks * fs.f_frsize <= BYTES and fs.f_blocks * fs.f_frsize > 3 * 1024**3,
            'Filesystem is outside the declared hard capacity')
    require(os.stat(MOUNT).st_dev != os.stat(ROOT).st_dev, 'Data path is on root, not the log volume')

def load_record():
    regular(MARK, True)
    require(MARK.stat().st_size <= 8192, 'Ownership record exceeds bound')
    record = json.loads(MARK.read_text())
    require(record.get('owner') == OWNER and record.get('image') == str(IMAGE) and
            record.get('mount') == str(MOUNT) and record.get('bytes') == BYTES,
            'Foreign logging ownership')
    require(record['machine_sha256'] == hashlib.sha256(MACHINE.read_bytes()).hexdigest(),
            'Machine identity changed')
    require(record.get('ca_sha256') == hashlib.sha256(CA.read_bytes()).hexdigest(), 'Kubernetes CA ownership differs')
    require(record.get('phase') == 'ready', 'Incomplete preparation requires explicit inspection; no automatic retry')
    require(record['image_identity'] == image_shape(), 'Backing file identity changed')
    return record

def mount_unit():
    return f'''[Unit]
Description=Owned bounded Loki log filesystem
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
Description=Verify owned Loki filesystem before workload startup
RequiresMountsFor={MOUNT}
Before=kubelet.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {SCRIPT} verify
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''

def verify(record):
    for unit, expected in [(UNIT, mount_unit()), (GUARD, guard_unit())]:
        regular(unit)
        require(unit.read_text() == expected, 'Owned systemd unit changed')
    check_mount(record)
    check_root_reserve()
    item = DATA.lstat()
    require(stat.S_ISDIR(item.st_mode) and item.st_uid == 10001 and item.st_gid == 10001 and
            stat.S_IMODE(item.st_mode) == 0o700, 'Unexpected Loki data directory owner/mode')

def check_enabled():
    for unit in [UNIT, GUARD]:
        require(command(['systemctl', 'is-enabled', unit.name]) == 'enabled', 'Persistent unit is not enabled')
        require(command(['systemctl', 'is-active', unit.name]) == 'active', 'Persistent unit is not active')

def prepare(expected_uid):
    regular(STATE, True)
    marker = json.loads(STATE.read_text())
    require(marker.get('managed_by') == 'infra-flux/ansible/kubeadm' and marker.get('node_name') == 'home' and
            marker.get('cluster_name') == 'unified', 'Not the owned home Kubernetes host')
    ca_hash = hashlib.sha256(CA.read_bytes()).hexdigest()
    require(marker.get('ca_sha256') == ca_hash, 'Kubernetes CA ownership differs')
    cluster = json.loads(command(['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=10s',
                                  'get', 'namespace', 'kube-system', '-o', 'json']))
    require(cluster['metadata']['uid'] == expected_uid, 'Live cluster UID differs')
    available = os.statvfs('/').f_bavail * os.statvfs('/').f_frsize
    if MARK.exists():
        record = load_record()
        require(record['cluster_uid'] == expected_uid and record['ca_sha256'] == ca_hash, 'Cluster ownership changed')
        require(available >= RESERVE, 'Keep at least 110 GiB root free for PostgreSQL restore')
        verify(record); check_enabled()
        return False
    for path in [ROOT, IMAGE, MOUNT, UNIT, GUARD]:
        require(not path.exists() and not path.is_symlink(), 'Refuse existing unowned path: ' + str(path))
    require(available >= RESERVE + BYTES, '4 GiB logs must leave 110 GiB root reserve')
    directory(pathlib.Path('/var/lib')); directory(MARK.parent); directory(UNIT.parent)
    record = {'owner': OWNER, 'phase': 'intent', 'image': str(IMAGE), 'mount': str(MOUNT), 'bytes': BYTES,
              'machine_sha256': hashlib.sha256(MACHINE.read_bytes()).hexdigest(),
              'cluster_uid': expected_uid, 'ca_sha256': ca_hash, 'filesystem_uuid': str(uuid.uuid4())}
    atomic(MARK, json.dumps(record, indent=2) + '\n')
    ROOT.mkdir(mode=0o700); MOUNT.mkdir(mode=0o700)
    fd = os.open(IMAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
    command(['fallocate', '--length', str(BYTES), str(IMAGE)])
    record['image_identity'] = image_shape(require_fully_allocated=True)
    # Exactly the newly created regular file. Never /dev/*, never an existing unowned file.
    command(['mkfs.ext4', '-F', '-E', 'nodiscard', '-m', '0', '-U', record['filesystem_uuid'], '-L', 'infra-loki', str(IMAGE)])
    require(image_shape() == record['image_identity'], 'Image identity changed during formatting')
    atomic(UNIT, mount_unit(), 0o644); atomic(GUARD, guard_unit(), 0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', UNIT.name])
    check_mount(record)
    require(not DATA.exists() and not DATA.is_symlink(), 'Unexpected data in new filesystem')
    DATA.mkdir(mode=0o700); os.chown(DATA, 10001, 10001)
    record['phase'] = 'ready'; atomic(MARK, json.dumps(record, indent=2) + '\n')
    verify(record)
    command(['systemctl', 'enable', '--now', GUARD.name])
    check_enabled()
    check_root_reserve()
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'verify'])
    parser.add_argument('--expected-cluster-uid')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required')
    for path in ['/etc', '/etc/infra-flux', '/etc/systemd', '/etc/systemd/system', '/var', '/var/lib']:
        directory(pathlib.Path(path))
    if args.action == 'prepare':
        require(args.expected_cluster_uid and str(uuid.UUID(args.expected_cluster_uid)) == args.expected_cluster_uid,
                'Explicit canonical expected cluster UID required')
        # Only prepare takes the process lock: its synchronous systemd guard runs verify.
        directory(LOCK.parent)
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            regular(LOCK, True)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            changed = prepare(args.expected_cluster_uid)
        finally:
            os.close(fd)
    else:
        record = load_record(); verify(record); changed = False
    print(json.dumps({'ok': True, 'changed': changed, 'filesystem_hard_bytes': BYTES, 'existing_devices_formatted': False, **allocation_status()}))

if __name__ == '__main__': main()
