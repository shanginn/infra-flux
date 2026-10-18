#!/usr/bin/env python3
"""Verify the reviewed upstream schema bytes and the sole local policy addition."""
import hashlib
from pathlib import Path
import re
import unittest

SCHEMA = Path(__file__).with_name('powerdns-schema.sql').read_text()
UPSTREAM_SHA256 = '710fe153de6467ca76f6c6355fe32506c48f9e0eef1f6a6534ee413bfa7cb120'
BEGIN = '-- BEGIN UPSTREAM SCHEMA\n'
END = '-- END UPSTREAM SCHEMA\n'
TABLES = {'domains', 'records', 'supermasters', 'comments', 'domainmetadata', 'cryptokeys', 'tsigkeys'}


class UpstreamSchema(unittest.TestCase):
    def test_official_514_ddl_is_byte_for_byte_preserved(self):
        self.assertEqual(SCHEMA.count(BEGIN), 1)
        self.assertEqual(SCHEMA.count(END), 1)
        upstream = SCHEMA.split(BEGIN, 1)[1].split(END, 1)[0]
        self.assertEqual(hashlib.sha256(upstream.encode()).hexdigest(), UPSTREAM_SHA256)
        self.assertIn('https://raw.githubusercontent.com/PowerDNS/pdns/auth-5.1.4/modules/gpgsqlbackend/schema.pgsql.sql', SCHEMA)
        self.assertIn('-- Upstream SHA256: '+UPSTREAM_SHA256, SCHEMA)

    def test_only_local_statement_is_validated_native_only_constraint(self):
        before = SCHEMA.split(BEGIN, 1)[0]
        after = SCHEMA.split(END, 1)[1]
        strip_comments = lambda value: re.sub(r'--[^\n]*', '', value).strip()
        self.assertEqual(strip_comments(before), '')
        self.assertEqual(re.sub(r'\s+', ' ', strip_comments(after)),
                         "ALTER TABLE domains ADD CONSTRAINT domains_native_only CHECK (type = 'NATIVE');")

    def test_exact_seven_tables_and_six_standard_id_sequences(self):
        self.assertEqual(set(re.findall(r'CREATE TABLE (\w+)\s*\(', SCHEMA)), TABLES)
        declarations = re.findall(r'CREATE TABLE (\w+)\s*\(\s*id\s+(BIGSERIAL|SERIAL)\s+PRIMARY KEY', SCHEMA)
        self.assertEqual(dict(declarations), {
            'domains': 'SERIAL', 'records': 'BIGSERIAL', 'comments': 'SERIAL',
            'domainmetadata': 'SERIAL', 'cryptokeys': 'SERIAL', 'tsigkeys': 'SERIAL'})
        self.assertNotIn('IF NOT EXISTS', SCHEMA)


if __name__ == '__main__':
    unittest.main()
