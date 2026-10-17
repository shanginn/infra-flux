#!/usr/bin/env python3
"""Offline stream failure tests; optional encrypted restic roundtrip via RESTIC_BINARY."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('garage_stream', Path(__file__).with_name('garage-stream.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
LIMIT = 2 * 1024**2
ADMIN = {'buckets': [{'id': 'test', 'globalAliases': ['example'], 'keys': []}], 'keys': [{'secretAccessKey': 'synthetic-secret'}]}


class Response(io.BytesIO):
    def __init__(self, data, etag):
        super().__init__(data)
        self.headers = {'content-length': str(len(data)), 'etag': etag, 'content-type': 'application/octet-stream', 'x-amz-meta-test': 'yes'}

    def getheader(self, key, default=None):
        return self.headers.get(key.lower(), default)

    def getheaders(self):
        return list(self.headers.items())


class Client:
    def __init__(self):
        self.objects = {'../unicode ключ %.bin': bytes(range(256)) * 500, 'empty': b''}
        self.calls, self.mutate, self.truncate = 0, False, False

    def listing(self, *args):
        self.calls += 1
        values = [{'key': key, 'size': len(data), 'etag': '"' + hashlib.md5(data).hexdigest() + '"', 'last_modified': '2026-10-17T00:00:00Z'} for key, data in sorted(self.objects.items())]
        if self.mutate and self.calls > 1:
            values.pop()
        return values

    @g.contextmanager
    def get(self, bucket, key, headers):
        data = self.objects[key]
        etag = '"' + hashlib.md5(data).hexdigest() + '"'
        assert headers['if-match'] == etag
        response = Response(data, etag)
        if self.truncate:
            response = Response(data[:-1], etag)
            response.headers['content-length'] = str(len(data))
        yield response


def produce(client=None, final_admin=None):
    stream = io.BytesIO()
    g.export_stream(client or Client(), ADMIN, {'name': 'test'}, stream, LIMIT, 10, final_admin)
    return stream.getvalue()


class StreamTests(unittest.TestCase):
    def test_roundtrip_binary_empty_unicode_and_metadata(self):
        encoded = produce()
        result = g.verify_stream(io.BytesIO(encoded), LIMIT, 10, 'test')
        self.assertEqual(result['objects'], 2)
        self.assertEqual(result['object_bytes'], 128000)
        with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
            metadata = json.load(archive.extractfile('objects/00000000.json'))
            self.assertEqual(metadata['key'], '../unicode ключ %.bin')
            self.assertEqual(metadata['headers']['x-amz-meta-test'], 'yes')
            self.assertEqual(json.load(archive.extractfile('admin.json')), ADMIN)

    def test_empty_bucket(self):
        client = Client()
        client.objects = {}
        result = g.verify_stream(io.BytesIO(produce(client)), LIMIT, 10)
        self.assertEqual(result['objects'], 0)

    def test_detects_concurrent_delete(self):
        client = Client()
        client.mutate = True
        with self.assertRaisesRegex(RuntimeError, 'changed during backup'):
            produce(client)

    def test_detects_configuration_change(self):
        with self.assertRaisesRegex(RuntimeError, 'configuration changed'):
            produce(final_admin=lambda: {'buckets': [], 'keys': []})

    def test_truncated_get_fails_without_final_manifest(self):
        client = Client()
        client.truncate = True
        with self.assertRaises((OSError, RuntimeError)):
            produce(client)

    def test_tampered_object_rejected(self):
        payload = bytearray(produce())
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            offset = archive.getmember('objects/00000000.bin').offset_data
        payload[offset] ^= 0x80
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            g.verify_stream(io.BytesIO(payload), LIMIT, 10)

    def test_missing_final_manifest_rejected(self):
        payload = produce()
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            offset = archive.getmember('manifest.json').offset
        with self.assertRaisesRegex(RuntimeError, 'Missing completed'):
            g.verify_stream(io.BytesIO(payload[:offset] + b'\0' * 10240), LIMIT, 10)

    def test_wrong_cluster_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Wrong source cluster'):
            g.verify_stream(io.BytesIO(produce()), LIMIT, 10, 'other')

    def test_object_count_bound(self):
        with self.assertRaisesRegex(RuntimeError, 'count exceeds'):
            g.verify_stream(io.BytesIO(produce()), LIMIT, 1)

    def test_small_archive_limit(self):
        client = Client()
        client.objects = {'large': b'x' * (2 * 1024**2)}
        with self.assertRaisesRegex(RuntimeError, 'byte limit'):
            produce(client)

    def test_explicit_write_scope_rejects_production_bucket(self):
        client = g.S3(1, {'accessKeyId': 'x', 'secretAccessKey': 'x'})
        with self.assertRaisesRegex(RuntimeError, 'isolated validation'):
            client.put_validation_object('production', 'key', b'x', {})

    @unittest.skipUnless(os.getenv('RESTIC_BINARY'), 'set RESTIC_BINARY for encrypted integration test')
    def test_real_encrypted_restic_dump_verifies_without_extracting_objects(self):
        binary = os.environ['RESTIC_BINARY']
        with tempfile.TemporaryDirectory(prefix='garage-restic-') as tmp:
            root = Path(tmp)
            password = root / 'password'
            password.write_text(os.urandom(32).hex())
            password.chmod(0o600)
            env = {key: value for key, value in os.environ.items() if not key.startswith('RESTIC_')}
            env.update(RESTIC_PASSWORD_FILE=str(password), RESTIC_REPOSITORY=str(root / 'repo'), RESTIC_CACHE_DIR=str(root / 'cache'))
            subprocess.run([binary, 'init'], env=env, capture_output=True, check=True, timeout=30)
            subprocess.run([binary, 'backup', '--stdin-filename', 'garage.tar', '--stdin-from-command', '--', sys.executable,
                            str(Path(__file__).resolve()), '--produce'], env=env, capture_output=True, check=True, timeout=60)
            with subprocess.Popen([binary, 'dump', 'latest', '/garage.tar'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                result = g.verify_stream(process.stdout, LIMIT, 10, 'test')
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertEqual(result['objects'], 2)
            subprocess.run([binary, 'check', '--read-data'], env=env, capture_output=True, check=True, timeout=60)
            # Repository files must not contain the source access-key test value in plaintext.
            self.assertTrue(all(b'synthetic-secret' not in file.read_bytes() for file in (root / 'repo').rglob('*') if file.is_file()))


if __name__ == '__main__':
    if sys.argv[1:] == ['--produce']:
        sys.stdout.buffer.write(produce())
    else:
        unittest.main()
