#!/usr/bin/env python3
"""SSH receiver: replace only the owned MacBook backup textfile, after identity checks."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

OWNER = '# managed-by: infra-flux/macos-backup-metrics-v1\n'
DIRECTORY = Path('/var/lib/node_exporter/textfile_collector')
TARGET = DIRECTORY / 'macbook-backup.prom'


def main():
    assert os.geteuid() == 0
    data = sys.stdin.buffer.read(65537)
    assert len(data) <= 65536
    request = json.loads(data)
    marker = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    monitor = json.loads(Path('/etc/infra-flux/monitoring.json').read_text())
    digest = hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest()
    assert marker['managed_by'] == 'infra-flux/ansible/kubeadm'
    assert marker['cluster_name'] == request['cluster_name'] and marker['ca_sha256'] == digest == request['ca_sha256']
    assert monitor['managed_by'] == 'infra-flux/ansible/monitoring' and monitor['node'] == marker['node_name']
    assert DIRECTORY.is_dir() and not DIRECTORY.is_symlink() and DIRECTORY.resolve() == DIRECTORY
    assert not TARGET.is_symlink()
    if TARGET.exists():
        assert TARGET.is_file() and TARGET.read_text().startswith(OWNER), 'Refuse unrelated metric file'
    assert isinstance(request['jobs'], list) and 0 < len(request['jobs']) <= 100
    rows, names = [OWNER], set()
    for job in request['jobs']:
        name = job['name']
        assert re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) and name not in names
        names.add(name)
        assert job['configured'] in (0, 1) and job['last_attempt_success'] in (0, 1)
        assert isinstance(job['last_success'], int) and 0 <= job['last_success'] <= time.time() + 600
        labels = '{component="' + name + '",destination="macbook"}'
        for metric, value in (
            ('configured', job['configured']), ('last_success_timestamp_seconds', job['last_success']),
            ('last_attempt_success', job['last_attempt_success']), ('max_age_seconds', 36 * 3600),
        ):
            rows.append('infra_backup_' + metric + labels + ' ' + str(value) + '\n')
    descriptor, temporary = tempfile.mkstemp(prefix='.macbook-backup-', dir=DIRECTORY)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(''.join(rows))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, TARGET)
        descriptor = os.open(DIRECTORY, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Backup metrics publication failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
