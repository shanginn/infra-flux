#!/usr/bin/env python3
"""Read-only Garage export and bounded streaming verification. No archive staging."""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

KUBE = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf']
MAX_JSON = 32 * 1024**2
NS = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def encoded(value, safe='-_.~'):
    return urllib.parse.quote(value, safe=safe, encoding='utf-8', errors='strict')


def json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def signed_headers(host, path, query, credentials, extra=None, now=None, method="GET", payload=b""):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stamp, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
    body_hash = hashlib.sha256(payload).hexdigest()
    headers = {'host': host, 'x-amz-date': stamp, 'x-amz-content-sha256': body_hash, **(extra or {})}
    canonical_headers = ''.join(key + ':' + ' '.join(headers[key].split()) + '\n' for key in sorted(headers))
    names = ';'.join(sorted(headers))
    canonical = '\n'.join((method, path, query, canonical_headers, names, body_hash))
    scope = f'{day}/garage/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = ('AWS4' + credentials['secretAccessKey']).encode()
    for part in (day, 'garage', 's3', 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    headers['authorization'] = f'AWS4-HMAC-SHA256 Credential={credentials["accessKeyId"]}/{scope}, SignedHeaders={names}, Signature={signature}'
    return headers


class S3:
    def __init__(self, port, credentials):
        self.port, self.credentials = port, credentials

    @contextmanager
    def get(self, bucket, key=None, query=None, headers=None):
        path = '/' + encoded(bucket) + ('/' + encoded(key, safe='/-_.~') if key is not None else '')
        query = '&'.join(encoded(k) + '=' + encoded(v) for k, v in sorted((query or {}).items()))
        host = f'127.0.0.1:{self.port}'
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        try:
            connection.request('GET', path + ('?' + query if query else ''),
                               headers=signed_headers(host, path, query, self.credentials, headers))
            response = connection.getresponse()
            require(response.status == 200, f'S3 read failed with HTTP {response.status}')
            yield response
        finally:
            connection.close()

    def put_validation_object(self, bucket, key, payload, headers):
        """Only the explicit isolated restore check uses writes; normal export is GET-only."""
        require(len(payload) <= 1024 * 1024, 'Validation object must fit the 1 MiB test bound')
        self._validation_write('PUT', bucket, key, payload, headers)

    def delete_validation_object(self, bucket, key):
        self._validation_write('DELETE', bucket, key, b'', {})

    def _validation_write(self, method, bucket, key, payload, headers):
        require(re.fullmatch(r'infra-backup-check-[a-f0-9]{24}', bucket), 'Writes are limited to isolated validation buckets')
        path = '/' + encoded(bucket) + '/' + encoded(key, safe='/-_.~')
        host = f'127.0.0.1:{self.port}'
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        try:
            signed = signed_headers(host, path, '', self.credentials, headers, method=method, payload=payload)
            connection.request(method, path, body=payload, headers=signed)
            response = connection.getresponse()
            require(response.status in (200, 204), 'Isolated restore-check write failed')
            response.read(MAX_JSON)
        finally:
            connection.close()

    def listing(self, bucket, maximum_objects, maximum_bytes):
        token, seen_tokens, objects, total = None, set(), {}, 0
        while True:
            query = {'list-type': '2', 'encoding-type': 'url', 'max-keys': '1000'}
            if token:
                query['continuation-token'] = token
            with self.get(bucket, query=query) as response:
                payload = response.read(MAX_JSON + 1)
            require(len(payload) <= MAX_JSON and b'<!DOCTYPE' not in payload.upper(), 'Oversized/unsafe S3 listing')
            tree = ET.fromstring(payload)
            require(tree.findtext('s3:EncodingType', namespaces=NS) == 'url', 'Listing must percent-encode object keys')
            for entry in tree.findall('s3:Contents', NS):
                key = urllib.parse.unquote(entry.findtext('s3:Key', namespaces=NS), encoding='utf-8', errors='strict')
                size = int(entry.findtext('s3:Size', namespaces=NS))
                require(key not in objects and len(key.encode()) <= 1024 and size >= 0, 'Invalid/duplicate object listing')
                objects[key] = {'key': key, 'size': size, 'etag': entry.findtext('s3:ETag', namespaces=NS),
                                'last_modified': entry.findtext('s3:LastModified', namespaces=NS)}
                total += size
                require(len(objects) <= maximum_objects and total <= maximum_bytes, 'Bucket exceeds backup bounds')
            if tree.findtext('s3:IsTruncated', namespaces=NS) != 'true':
                break
            token = tree.findtext('s3:NextContinuationToken', namespaces=NS)
            require(token and token not in seen_tokens, 'Invalid/repeated pagination token')
            seen_tokens.add(token)
        return [objects[key] for key in sorted(objects)]


class BoundedWriter:
    def __init__(self, stream, limit):
        self.stream, self.limit, self.count = stream, limit, 0

    def write(self, data):
        self.count += len(data)
        require(self.count <= self.limit, 'Archive exceeds configured byte limit')
        return self.stream.write(data)


class HashedReader:
    def __init__(self, stream, limit=None):
        self.stream, self.digest, self.count, self.limit = stream, hashlib.sha256(), 0, limit

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        self.count += len(data)
        require(self.limit is None or self.count <= self.limit, 'Encoded stream exceeds bound')
        return data


def add_bytes(archive, name, data):
    require(len(data) <= MAX_JSON, 'Metadata exceeds bound')
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), 0o600
    archive.addfile(info, io.BytesIO(data))


def export_stream(client, admin, cluster, stream, maximum_bytes, maximum_objects, final_admin=None):
    """Each GET is conditional; the second listing rejects detected concurrent changes."""
    started = int(time.time())
    header = {'format': 1, 'component': 'garage-objects', 'cluster': cluster,
              'versioning': False, 'consistency': 'two-pass-live-enumeration', 'created_at': started}
    inventory, count, total = {}, 0, 0
    for bucket in admin['buckets']:
        name = bucket['globalAliases'][0]
        items = client.listing(name, maximum_objects - count, maximum_bytes - total)
        inventory[name] = items
        count += len(items)
        total += sum(item['size'] for item in items)
    require(count <= maximum_objects and total <= maximum_bytes, 'Data exceeds global backup bound')
    chain = hashlib.sha256()
    writer = BoundedWriter(stream, maximum_bytes)
    with tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        header_data, admin_data = json_bytes(header), json_bytes(admin)
        add_bytes(archive, 'archive.json', header_data)
        add_bytes(archive, 'admin.json', admin_data)
        index = 0
        for bucket in sorted(inventory):
            for item in inventory[bucket]:
                prefix = f'objects/{index:08d}'
                with client.get(bucket, item['key'], headers={'if-match': item['etag']}) as response:
                    require(int(response.getheader('Content-Length', '-1')) == item['size'], 'Object size changed')
                    require(response.getheader('ETag') == item['etag'], 'Object changed since listing')
                    require(response.getheader('x-amz-version-id') in (None, 'null'), 'Versioned objects are unsupported')
                    headers = {key.lower(): value for key, value in response.getheaders()}
                    metadata = {key: value for key, value in headers.items() if key.startswith('x-amz-meta-') or key in
                                ('content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires')}
                    source = HashedReader(response)
                    info = tarfile.TarInfo(prefix + '.bin')
                    info.size, info.mode = item['size'], 0o600
                    archive.addfile(info, source)
                    require(source.count == item['size'] and response.read(1) == b'', 'Object body is incomplete or oversized')
                record = dict(item, bucket=bucket, sha256=source.digest.hexdigest(), headers=metadata)
                record_data = json_bytes(record)
                add_bytes(archive, prefix + '.json', record_data)
                chain.update(record_data)
                index += 1
        # Also compare bucket creation/removal and permissions/configuration if supplied.
        for bucket, original in inventory.items():
            require(client.listing(bucket, maximum_objects, maximum_bytes) == original, 'Bucket changed during backup; retry')
        if final_admin is not None:
            require(json_bytes(final_admin()) == admin_data, 'Bucket/key configuration changed during backup; retry')
        final = {'format': 1, 'component': 'garage-objects', 'completed': True, 'objects': count, 'object_bytes': total,
                 'completed_at': int(time.time()), 'records_sha256': chain.hexdigest(),
                 'archive_sha256': hashlib.sha256(header_data).hexdigest(), 'admin_sha256': hashlib.sha256(admin_data).hexdigest(),
                 'inventory_sha256': hashlib.sha256(json_bytes(inventory)).hexdigest()}
        add_bytes(archive, 'manifest.json', json_bytes(final))
    stream.flush()


def verify_stream(stream, maximum_bytes, maximum_objects, expected_cluster=None):
    """Hash every decrypted body without writing plaintext objects to disk."""
    require(maximum_bytes >= 1048576 and 0 <= maximum_objects <= 100000, 'Invalid verification bounds')
    count, total, chain, manifest, expected, body = 0, 0, hashlib.sha256(), None, 'archive.json', None
    metadata_hashes, header, inventory, admin = {}, None, {}, None
    bounded = HashedReader(stream, maximum_bytes)
    with tarfile.open(fileobj=bounded, mode='r|') as archive:
        for member in archive:
            require(bounded.count <= maximum_bytes, 'Encoded archive exceeds bound')
            if member.name == 'manifest.json' and body is None and header is not None and admin is not None:
                expected = 'manifest.json'
            require(manifest is None and member.isfile() and member.name == expected and member.size >= 0,
                    'Unexpected/duplicate/out-of-order archive entry')
            require(member.size <= maximum_bytes and total + member.size <= maximum_bytes, 'Archive exceeds bound')
            with archive.extractfile(member) as source:
                if member.name.endswith('.bin'):
                    digest, size = hashlib.sha256(), 0
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        size += len(block)
                    require(size == member.size, 'Truncated object')
                    body = (size, digest.hexdigest())
                    total += size
                    expected = f'objects/{count:08d}.json'
                    continue
                require(member.size <= MAX_JSON, 'Oversized metadata')
                payload = source.read(MAX_JSON + 1)
            value = json.loads(payload)
            if member.name == 'archive.json':
                header = value
                require(value.get('format') == 1 and value.get('component') == 'garage-objects' and value.get('versioning') is False,
                        'Unexpected archive identity')
                require(expected_cluster is None or value['cluster']['name'] == expected_cluster, 'Wrong source cluster')
                expected = 'admin.json'
            elif member.name == 'admin.json':
                admin = value
                require(isinstance(value.get('buckets'), list) and isinstance(value.get('keys'), list), 'Missing recovery metadata')
                inventory = {bucket['globalAliases'][0]: [] for bucket in value['buckets']}
                expected = 'objects/00000000.bin'
            elif member.name.startswith('objects/'):
                require(body == (value['size'], value['sha256']) and value['bucket'] in inventory and isinstance(value['key'], str),
                        'Object checksum or metadata differs')
                require(len(value['key'].encode()) <= 1024, 'Invalid object key')
                require(not inventory[value['bucket']] or inventory[value['bucket']][-1]['key'] < value['key'], 'Duplicate/unordered object key')
                inventory[value['bucket']].append({key: value[key] for key in ('key', 'size', 'etag', 'last_modified')})
                chain.update(payload)
                count += 1
                require(count <= maximum_objects, 'Object count exceeds bound')
                expected = f'objects/{count:08d}.bin'
                body = None
            elif member.name == 'manifest.json':
                manifest = value
                require(value.get('format') == 1 and value.get('component') == 'garage-objects' and value.get('completed') is True and value['objects'] == count and value['object_bytes'] == total and
                        value['records_sha256'] == chain.hexdigest(), 'Incomplete archive or object manifest differs')
            metadata_hashes[member.name] = hashlib.sha256(payload).hexdigest()
    while trailing := bounded.read(1024 * 1024):
        require(bounded.count <= maximum_bytes and not trailing.strip(b'\0'), 'Unexpected archive tail')
    require(manifest is not None and body is None, 'Missing completed manifest')
    require(manifest['archive_sha256'] == metadata_hashes['archive.json'] and manifest['admin_sha256'] == metadata_hashes['admin.json'] and
            manifest['inventory_sha256'] == hashlib.sha256(json_bytes(inventory)).hexdigest(), 'Recovery metadata differs')
    return {'objects': count, 'object_bytes': total, 'component': 'garage-objects', 'verified': True}


def command(args):
    result = subprocess.run(args, capture_output=True, timeout=90)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON, 'Garage/Kubernetes read failed')
    return result.stdout


def admin_api(pod, name, body=None):
    return json.loads(command(KUBE + ['exec', '-n', 'garage', pod, '-c', 'garage', '--', '/garage', 'json-api', name, json.dumps(body)]))


def inventory_admin(pod):
    buckets = admin_api(pod, 'ListBuckets')
    require(len(buckets) <= 1000 and all(len(b['globalAliases']) == 1 for b in buckets),
            'All buckets must have exactly one canonical global alias')
    require(len({b['id'] for b in buckets}) == len(buckets) and
            len({b['globalAliases'][0] for b in buckets}) == len(buckets), 'Duplicate bucket ID or global alias')
    details = [admin_api(pod, 'GetBucketInfo', {'id': b['id']}) for b in sorted(buckets, key=lambda b: b['id'])]
    for bucket in details:
        # Garage returns this permission set without a stable order. Normalize only
        # this set, retaining names/permissions/IDs so real configuration drift fails.
        entries = bucket.get('keys')
        require(isinstance(entries, list) and all(isinstance(entry, dict) and
                isinstance(entry.get('accessKeyId'), str) and entry['accessKeyId'] for entry in entries),
                'Invalid bucket key permission set')
        ids = [entry['accessKeyId'] for entry in entries]
        require(len(ids) == len(set(ids)), 'Duplicate bucket key IDs')
        bucket['keys'] = sorted(entries, key=lambda entry: entry['accessKeyId'])
        # These counters are intentionally excluded from configuration comparison.
        for key in ('objects', 'bytes', 'unfinishedUploads', 'unfinishedMultipartUploads', 'unfinishedMultipartUploadParts', 'unfinishedMultipartUploadBytes'):
            bucket.pop(key, None)
    keys = admin_api(pod, 'ListKeys')
    require(len(keys) <= 10000, 'Too many access keys')
    keys = [admin_api(pod, 'GetKeyInfo', {'id': key['id'], 'showSecretKey': True}) for key in sorted(keys, key=lambda key: key['id'])]
    require(all(key.get('secretAccessKey') for key in keys), 'Cannot export complete access-key recovery metadata')
    for key in keys:
        # This reverse permission set is also unordered in GetKeyInfo. Keep all
        # aliases and grants, changing only the order of distinct bucket IDs.
        entries = key.get('buckets')
        require(isinstance(entries, list) and all(isinstance(entry, dict) and
                isinstance(entry.get('id'), str) and entry['id'] for entry in entries),
                'Invalid key bucket permission set')
        ids = [entry['id'] for entry in entries]
        require(len(ids) == len(set(ids)), 'Duplicate key bucket IDs')
        key['buckets'] = sorted(entries, key=lambda entry: entry['id'])
    validate_local_aliases(buckets, details, keys)
    return {'buckets': details, 'keys': keys}


def validate_local_aliases(catalog, buckets, keys):
    """Preserve and cross-check (access key, alias) -> bucket in all native views."""
    expected = {}
    for bucket in catalog:
        entries = bucket.get('localAliases', [])
        require(isinstance(entries, list), 'Invalid local alias list')
        for entry in entries:
            require(isinstance(entry, dict) and set(entry) == {'accessKeyId', 'alias'} and
                    all(isinstance(v, str) and v for v in entry.values()), 'Invalid local alias entry')
            pair = (entry['accessKeyId'], entry['alias'])
            require(pair not in expected, 'Duplicate or ambiguous key-local alias')
            expected[pair] = bucket['id']
    def aliases(values):
        require(isinstance(values, list) and all(isinstance(v, str) and v for v in values) and
                len(values) == len(set(values)), 'Invalid or duplicate local alias names')
        return sorted(values)
    bucket_view = {}
    for bucket in buckets:
        for entry in bucket['keys']:
            names = aliases(entry.get('bucketLocalAliases', []))
            if 'bucketLocalAliases' in entry:
                entry['bucketLocalAliases'] = names
            for name in names:
                pair = (entry['accessKeyId'], name)
                require(pair not in bucket_view, 'Ambiguous bucket permission alias')
                bucket_view[pair] = bucket['id']
    key_view = {}
    for key in keys:
        for bucket in key['buckets']:
            names = aliases(bucket.get('localAliases', []))
            if 'localAliases' in bucket:
                bucket['localAliases'] = names
            for name in names:
                pair = (key['accessKeyId'], name)
                require(pair not in key_view, 'Ambiguous access-key alias')
                key_view[pair] = bucket['id']
    require(expected == bucket_view == key_view, 'Local alias metadata views disagree')


def validate_backup_aliases(admin, credentials):
    global_names = {b['globalAliases'][0]: b['id'] for b in admin['buckets']}
    for bucket in credentials['buckets']:
        for alias in bucket.get('localAliases', []):
            require(alias not in global_names or global_names[alias] == bucket['id'],
                    'Backup key local alias shadows a different canonical global bucket')


@contextmanager
def forward(pod):
    process = subprocess.Popen(KUBE + ['port-forward', '--address=127.0.0.1', '-n', 'garage', 'pod/' + pod, '0:3900'],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(30), 'Port-forward startup timed out')
        line = process.stdout.readline().decode()
        found = re.fullmatch(r'Forwarding from 127\.0\.0\.1:(\d+) -> 3900\n', line)
        require(found and process.poll() is None, 'Unexpected private port-forward state')
        selector.close()
        # kubectl logs every forwarded connection; drain it so a large bucket cannot fill the pipe.
        def drain():
            while process.stdout.read(65536):
                pass
        threading.Thread(target=drain, daemon=True).start()
        yield int(found.group(1))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def owned_cluster():
    require(os.geteuid() == 0, 'The protected exporter requires root via the existing SSH channel')
    marker = json.loads(Path('/etc/infra-flux/kubeadm-state.json').read_text())
    require(marker['managed_by'] == 'infra-flux/ansible/kubeadm' and
            marker['ca_sha256'] == hashlib.sha256(Path('/etc/kubernetes/pki/ca.crt').read_bytes()).hexdigest(), 'Cluster identity differs')
    require(json.loads(Path('/etc/infra-flux/garage.json').read_text())['managed_by'] == 'infra-flux/ansible/garage', 'Unowned Garage')
    return marker


def export(maximum_bytes, maximum_objects):
    marker = owned_cluster()
    key_file = Path('/etc/infra-garage/backup-key.json')
    require(key_file.is_file() and not key_file.is_symlink() and key_file.stat().st_mode & 0o077 == 0, 'Missing private backup key ID')
    key_state = json.loads(key_file.read_text())
    require(key_state.get('managed_by') == 'infra-flux/garage-macbook-backup', 'Unowned backup key')
    key_id = key_state['accessKeyId']
    pods = json.loads(command(KUBE + ['get', 'pods', '-n', 'garage', '-l',
        'app.kubernetes.io/name=garage,app.kubernetes.io/instance=garage', '-o', 'json']))['items']
    healthy = [p for p in pods if p['status']['phase'] == 'Running' and any(c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', []))]
    require(healthy, 'No healthy Garage endpoint')
    pod = sorted(healthy, key=lambda p: (p['spec']['nodeName'] != marker['node_name'], p['metadata']['name']))[0]['metadata']['name']
    admin = inventory_admin(pod)
    credentials = next(key for key in admin['keys'] if key['accessKeyId'] == key_id)
    require(not credentials['expired'] and not credentials['permissions']['createBucket'], 'Backup key must be active and unable to create buckets')
    validate_backup_aliases(admin, credentials)
    grants = {b['id']: b['permissions'] for b in credentials['buckets']}
    require(set(grants) == {b['id'] for b in admin['buckets']} and all(p['read'] and not p['write'] and not p['owner'] for p in grants.values()),
            'Backup key must have read-only access to every bucket')
    with forward(pod) as port:
        export_stream(S3(port, credentials), admin, {'name': marker['cluster_name'], 'ca_sha256': marker['ca_sha256']},
                      sys.stdout.buffer, maximum_bytes, maximum_objects, final_admin=lambda: inventory_admin(pod))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['export', 'verify'])
    parser.add_argument('--max-bytes', type=int, default=32 * 1024**3)
    parser.add_argument('--max-objects', type=int, default=100000)
    parser.add_argument('--cluster-name', default='unified')
    args = parser.parse_args()
    try:
        require(1048576 <= args.max_bytes <= 32 * 1024**3 and 0 <= args.max_objects <= 100000, 'Invalid export bounds')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Two-hour backup bound exceeded')))
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(TimeoutError('Backup interrupted')))
        signal.alarm(7200)
        if args.operation == 'export':
            require(not sys.stdout.isatty(), 'Binary secret-bearing export must be piped directly into encryption')
            export(args.max_bytes, args.max_objects)
        else:
            print(json.dumps(verify_stream(sys.stdin.buffer, args.max_bytes, args.max_objects, args.cluster_name), sort_keys=True))
    except Exception as error:
        print(f'Garage stream failed ({type(error).__name__})', file=sys.stderr)
        sys.exit(1)
