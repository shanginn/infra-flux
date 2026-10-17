#!/usr/bin/env python3
"""Persist an inspected GPT swap partition as noauto; never swapoff or reboot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

BEGIN = '# BEGIN infra-flux: swap noauto'
END = '# END infra-flux: swap noauto'
FSTAB = Path('/etc/fstab')
BOOTSTRAP = Path('/etc/infra-flux/kubeadm-state.json')
KUBELET = Path('/var/lib/kubelet/config.yaml')
BACKUPS = Path('/etc/infra-flux/swap-maintenance')
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Not a trusted regular file: ' + str(path))
    return path.read_bytes()


def run(argv):
    result = subprocess.run(argv, capture_output=True, timeout=15)
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024,
            'Bounded command failed: ' + argv[0])
    return result.stdout.decode()


def candidate(data, identifier):
    require(re.fullmatch(UUID, identifier), 'Expected a reviewed lowercase swap UUID')
    text = data.decode()
    require('\x00' not in text, 'Invalid fstab bytes')
    line = 'UUID=' + identifier + ' none swap noauto 0 0'
    block = BEGIN + '\n' + line + '\n' + END + '\n'
    active = [row.split() for row in text.splitlines() if row.strip() and not row.lstrip().startswith('#')]
    swaps = [row for row in active if len(row) >= 3 and row[2] == 'swap']
    if BEGIN in text or END in text:
        require(text.count(BEGIN) == 1 and text.count(END) == 1 and block in text,
                'Existing maintenance block differs')
        require(swaps == [line.split()], 'Unexpected additional swap entry')
        return data
    require(not swaps, 'Review existing noncommented swap entries first')
    # This transition is only for a partition already disabled by bootstrap.
    commented = [row[len('# infra-flux kubeadm disabled swap: '):].split()
                 for row in text.splitlines() if row.startswith('# infra-flux kubeadm disabled swap: ')]
    require(sum(len(row) >= 3 and row[0] == 'UUID=' + identifier and row[2] == 'swap'
                for row in commented) == 1, 'Expected exactly one bootstrap-disabled entry for this UUID')
    return data + (b'' if not data or data.endswith(b'\n') else b'\n') + block.encode()


def inspect(args):
    require(os.geteuid() == 0 and args.node == 'home', 'This reviewed transition targets the owned home node only')
    require(re.fullmatch(UUID, args.uuid) and re.fullmatch(UUID, args.partuuid), 'Invalid reviewed partition identity')
    require(re.fullmatch(r'/dev/(?:sd[a-z]+[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+|vd[a-z]+[0-9]+)', args.device), 'Use the reviewed kernel partition path')
    device = Path(args.device)
    require(stat.S_ISBLK(device.lstat().st_mode), 'Target is not a direct block device')
    marker_raw = trusted(BOOTSTRAP); marker = json.loads(marker_raw)
    require(marker.get('managed_by') == 'infra-flux/ansible/kubeadm' and marker.get('cluster_name') == 'unified'
            and marker.get('node_name') == args.node, 'Bootstrap owner/node mismatch')
    ca = sha(trusted(Path('/etc/kubernetes/pki/ca.crt')))
    require(ca == marker.get('ca_sha256') and (args.ca_sha256 is None or ca == args.ca_sha256), 'Cluster CA mismatch')
    version = run(['/usr/bin/systemctl', '--version']).splitlines()[0]
    require(re.match(r'^systemd 257(?:\s|$)', version), 'Review generator behavior for this systemd version')
    tags = dict(row.split('=', 1) for row in run(['/usr/sbin/blkid', '-p', '-o', 'export', args.device]).splitlines() if '=' in row)
    require(tags.get('TYPE') == 'swap' and tags.get('UUID') == args.uuid
            and tags.get('PART_ENTRY_UUID') == args.partuuid
            and tags.get('PART_ENTRY_TYPE') == '0657fd6d-a4ab-43c4-84e5-0933c84b4f4f', 'Swap/GPT partition identity mismatch')
    dev = device.stat().st_rdev; major_minor = str(os.major(dev)) + ':' + str(os.minor(dev))
    require(all(row.split()[2] != major_minor for row in Path('/proc/self/mountinfo').read_text().splitlines()), 'Target partition is mounted')
    data = trusted(FSTAB); desired = candidate(data, args.uuid)
    kubelet = trusted(KUBELET)
    require(re.search(rb'^failSwapOn: true\s*$', kubelet, re.M), 'The owned kubelet must retain failSwapOn: true')
    swaps = [row.split() for row in Path('/proc/swaps').read_text().splitlines()[1:]]
    root_mount = json.loads(run(['/usr/bin/findmnt', '--json', '--mountpoint', '/', '--output', 'SOURCE,FSTYPE,OPTIONS']))
    return {'node': args.node, 'ca_sha256': ca, 'systemd': version,
            'device': args.device, 'uuid': args.uuid, 'partuuid': args.partuuid,
            'fstab_sha256': sha(data), 'candidate_sha256': sha(desired),
            'bootstrap_sha256': sha(marker_raw), 'kubelet_sha256': sha(kubelet),
            'active_swap_count': len(swaps), 'root_mount': root_mount,
            'changed': data != desired}, data, desired


def atomic(path, data, mode, uid=0, gid=0):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        os.fchmod(fd, mode); os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def verify_generated():
    for directory in ('/run/systemd/generator', '/run/systemd/generator.early', '/run/systemd/generator.late'):
        for path in Path(directory).glob('*.swap'):
            text = path.read_text()
            require('systemd-gpt-auto-generator' not in text, 'GPT swap generation still present after reload')
    dependencies = run(['/usr/bin/systemctl', 'show', 'swap.target', '--property=Wants,Requires', '--value']).split()
    require(not any(value.endswith('.swap') for value in dependencies), 'A swap unit is still pulled in by swap.target')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'apply'))
    parser.add_argument('--node', required=True)
    parser.add_argument('--device', required=True)
    parser.add_argument('--uuid', required=True)
    parser.add_argument('--partuuid', required=True)
    parser.add_argument('--ca-sha256')
    parser.add_argument('--expected-fstab-sha256')
    args = parser.parse_args()
    before, original, desired = inspect(args)
    if args.action == 'inspect':
        print(json.dumps(before, sort_keys=True)); return
    require(args.ca_sha256 and re.fullmatch('[0-9a-f]{64}', args.ca_sha256), 'Apply requires the reviewed CA')
    require(args.expected_fstab_sha256 and re.fullmatch('[0-9a-f]{64}', args.expected_fstab_sha256), 'Apply requires the reviewed fstab preimage')
    require(before['fstab_sha256'] == args.expected_fstab_sha256, 'fstab differs from reviewed preimage')
    require(before['active_swap_count'] == 0, 'Disable active swap separately after resource review; this helper never swapoff')
    if before['changed']:
        BACKUPS.mkdir(mode=0o700, exist_ok=True)
        info = BACKUPS.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe preimage directory')
        backup = BACKUPS / ('fstab.before.' + before['fstab_sha256'])
        if backup.exists() or backup.is_symlink():
            require(trusted(backup) == original, 'Existing preimage differs')
        else:
            atomic(backup, original, 0o600)
        require(trusted(FSTAB) == original, 'fstab changed during maintenance')
        info = FSTAB.lstat()
        atomic(FSTAB, desired, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
    # A previous interrupted apply may have persisted the entry but not reloaded.
    run(['/usr/bin/systemctl', 'daemon-reload'])
    after, current, unused = inspect(args)
    require(current == desired and after['active_swap_count'] == 0, 'Swap or fstab readback differs')
    require(all(after[key] == before[key] for key in ('bootstrap_sha256', 'kubelet_sha256', 'root_mount')), 'An unrelated protected configuration or root mount changed')
    verify_generated()
    after.update(changed=before['changed'], generator_readback_verified=True, reboot_persistence_tested=False,
                 services_restarted=False, partition_modified=False)
    print(json.dumps(after, sort_keys=True))


if __name__ == '__main__':
    main()
