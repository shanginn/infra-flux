#!/usr/bin/env python3
"""Read-only DNS parity verification through an existing SSH administration host.

Requires dnspython==2.9.0 locally; the SSH host needs only Python 3 and dig.
Results contain counts and query identities, never returned record contents.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

import dns.name
import dns.rdata
import dns.rdatatype
import dns.zone

REPO = Path(__file__).resolve().parents[2]
DYNAMIC = {'vibesites.ru.', 'xn--80aacc0bc7ayl4g.xn--p1ai.'}
REMOTE = r'''
import concurrent.futures, ipaddress, json, re, subprocess, sys
body=sys.stdin.buffer.read(2*1024*1024+1)
if len(body)>2*1024*1024: raise SystemExit('payload too large')
p=json.loads(body)
qs=p['queries']
if not 0<len(qs)<=5000 or not 1<=p['workers']<=8: raise SystemExit('invalid bounds')
def run(q):
    ipaddress.ip_address(q['address'])
    if not 1<=q['port']<=65535: raise ValueError('port')
    if not re.fullmatch(r'[A-Za-z0-9_.*-]+(?:\.[A-Za-z0-9_.*-]+)*\.',q['name']): raise ValueError('name')
    if not re.fullmatch(r'[A-Z0-9]+',q['type']): raise ValueError('type')
    if q['transport'] not in ('udp','tcp'): raise ValueError('transport')
    if q['type'] in ('ANY','IXFR'): raise ValueError('unsupported query type')
    args=['dig','@'+q['address'],'-p',str(q['port']),q['name'],q['type'],
          '+time=2','+tries=1','+bufsize=1232','+ignore','+noall','+comments','+answer',
          '+authority','+additional','+qr',
          '+recurse' if q.get('recurse') else '+norecurse',
          '+tcp' if q['transport']=='tcp' else '+notcp']
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=8)
        if len(r.stdout)>1024*1024: return {'id':q['id'],'error':'response_too_large'}
        return {'id':q['id'],'returncode':r.returncode,'stdout':r.stdout}
    except subprocess.TimeoutExpired:
        return {'id':q['id'],'error':'query_timeout'}
    except OSError:
        return {'id':q['id'],'error':'dig_unavailable'}
with concurrent.futures.ThreadPoolExecutor(max_workers=p['workers']) as pool:
    out=list(pool.map(run,qs))
print(json.dumps(out,separators=(',',':')))
'''


def require(value, message):
    if not value:
        raise RuntimeError(message)


def fqdn(value):
    name = dns.name.from_text(value, origin=dns.name.root).canonicalize()
    require(name.is_absolute() and len(name.to_wire()) <= 255, 'Invalid DNS name')
    return name.to_text()


def canonical(owner, ttl, rrtype, value, origin=dns.name.root):
    name = dns.name.from_text(owner, origin=origin).canonicalize()
    rdata = dns.rdata.from_text(1, rrtype, value, origin=origin, relativize=False)
    return (name.to_text(), dns.rdatatype.to_text(rdata.rdtype), int(ttl),
            rdata.to_wire(origin=origin, canonicalize=True).hex())


def zone_records(zone):
    result = []
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rd in rdataset:
                result.append((name.canonicalize().to_text(), dns.rdatatype.to_text(rd.rdtype),
                               rdataset.ttl, rd.to_wire(origin=zone.origin, canonicalize=True).hex()))
    return sorted(set(result))


def parse_dig(text):
    """Parse dig's response sections; ignore its +qr request and CNAME extras."""
    require(len(text) <= 1024 * 1024, 'Oversized DNS response')
    status = None
    flags = set()
    section = None
    parts = {'answer': [], 'authority': [], 'additional': []}
    all_records = []
    response_seen = False
    for line in text.splitlines():
        header = re.search(r'->>HEADER<<-.*status: ([A-Z0-9]+),', line)
        if header:
            status = header.group(1)
            flags = set()
            section = None
            continue
        f = re.search(r'^;; flags: ([^;]*);', line)
        if f:
            flags = set(f.group(1).split())
            response_seen = 'qr' in flags
            continue
        sec = re.match(r'^;; (ANSWER|AUTHORITY|ADDITIONAL) SECTION:', line)
        if sec:
            section = sec.group(1).lower()
            continue
        if not line or line.startswith(';'):
            continue
        cols = line.split(None, 4)
        if len(cols) != 5 or cols[2] != 'IN' or not cols[1].isdigit():
            continue
        try:
            record = canonical(cols[0], int(cols[1]), cols[3], cols[4])
        except Exception:
            raise RuntimeError('Unparseable DNS record') from None
        all_records.append(record)
        if section:
            parts[section].append(record)
    return {'status': status, 'flags': flags, 'sections': parts,
            'records': all_records, 'response_seen': response_seen,
            'transfer_failed': 'Transfer failed.' in text}


def remote_queries(via, queries, workers):
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', via), 'Use an existing simple SSH alias')
    command = 'python3 -c ' + shlex.quote(REMOTE)
    r = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                        '--', via, command], input=json.dumps({'workers': workers, 'queries': queries}),
                       capture_output=True, text=True,
                       timeout=max(45, ((len(queries) + workers - 1) // workers) * 9 + 30))
    require(r.returncode == 0, 'Remote read-only query runner failed')
    require(len(r.stdout) <= 64 * 1024**2, 'Remote output exceeds bound')
    try:
        results = json.loads(r.stdout)
    except Exception:
        raise RuntimeError('Remote query runner returned invalid JSON') from None
    require(isinstance(results, list) and len(results) == len(queries), 'Remote result count differs')
    require({x['id'] for x in results} == {q['id'] for q in queries}, 'Remote result IDs differ')
    return {x['id']: x for x in results}


def endpoint(value):
    require('=' in value, 'Endpoint must be LABEL=IP or LABEL=IP:PORT')
    label, address = value.split('=', 1)
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}', label), 'Invalid endpoint label')
    port = 53
    if address.startswith('['):
        match = re.fullmatch(r'\[([^]]+)\](?::([0-9]+))?', address)
        require(match is not None, 'Invalid IPv6 endpoint')
        address, p = match.groups()
        port = int(p) if p else 53
    elif address.count(':') == 1:
        address, p = address.rsplit(':', 1)
        port = int(p)
    ipaddress.ip_address(address)
    require(1 <= port <= 65535, 'Invalid DNS port')
    return {'label': label, 'address': address, 'port': port}


def load_static():
    config = REPO / 'components/bind9/base/configs/named.conf.local'
    source = config.read_text()
    entries = re.findall(r'zone "([^"]+)" IN \{\s*type master;\s*file "/etc/bind/zones/([^"]+)";', source)
    require(len(entries) == 22, 'Expected exactly the current twenty-two BIND zone declarations')
    zones = {}
    for name, filename in entries:
        origin = fqdn(name)
        require('/' not in filename and filename not in ('.', '..'), 'Unexpected zone filename')
        if origin in DYNAMIC:
            continue
        path = config.parent / 'zones' / filename
        zone = dns.zone.from_file(path, origin=origin, relativize=False, allow_include=False)
        zones[origin] = zone_records(zone)
    require(len(zones) == 20, 'Expected twenty static Git zones')
    return zones


def query(qid, target, name, rrtype, transport='udp', **extra):
    return {'id': qid, 'address': target['address'], 'port': target['port'],
            'name': fqdn(name), 'type': rrtype, 'transport': transport, **extra}


def load_dynamic(via, legacy, workers):
    requests = [query(i, legacy, name, 'AXFR', 'tcp') for i, name in enumerate(sorted(DYNAMIC))]
    results = remote_queries(via, requests, workers)
    zones = {}
    for q in requests:
        result = results[q['id']]
        require(not result.get('error') and result.get('returncode') == 0, 'Legacy dynamic AXFR failed')
        parsed = parse_dig(result['stdout'])
        records = parsed['records']
        require(not parsed['transfer_failed'], 'Legacy dynamic AXFR was refused')
        require(len(records) >= 3 and len(records) <= 25000, 'Invalid dynamic AXFR record count')
        soa = [r for r in records if r[0] == q['name'] and r[1] == 'SOA']
        require(len(soa) == 2 and soa[0] == soa[1], 'Dynamic AXFR lacks matching opening and closing SOA')
        require(all(dns.name.from_text(r[0]).is_subdomain(dns.name.from_text(q['name'])) for r in records),
                'Dynamic AXFR returned out-of-zone data')
        zones[q['name']] = sorted(set(records))
    return zones


def rrsets(records):
    groups = {}
    for owner, rrtype, ttl, content in records:
        groups.setdefault((owner, rrtype), set()).add((owner, rrtype, ttl, content))
    return groups


def beneath(name, origin):
    return dns.name.from_text(name).is_subdomain(dns.name.from_text(origin))


def cuts_for(origin, records):
    return {owner for owner, rrtype, _, _ in records if rrtype == 'NS' and owner != origin}


def existing_names(records, origin):
    result = {origin}
    for owner, _, _, _ in records:
        n = dns.name.from_text(owner)
        while n.is_subdomain(dns.name.from_text(origin)):
            result.add(n.to_text())
            if n.to_text() == origin:
                break
            n = n.parent()
    return result


def negative_name(origin, records, nonce):
    names = existing_names(records, origin)
    cuts = cuts_for(origin, records)
    dnames = {r[0] for r in records if r[1] == 'DNAME'}
    for owner in sorted(names, key=lambda n: ('*' in n, n != origin, n)):
        if any(beneath(owner, cut) for cut in cuts | dnames):
            continue
        candidate = nonce + '.' + owner
        if '*.' + owner not in names and candidate not in names:
            return candidate
    raise RuntimeError('No safe NXDOMAIN probe name found')


def build_checks(zones, public, backends, cohosted, nonce):
    checks = []
    known_cuts = set().union(*(cuts_for(z, r) for z, r in zones.items()))
    require(cohosted <= known_cuts, 'Cohosted zones must be declared child delegations')
    require(not cohosted or backends, 'Cohosted child zones require a direct backend to prove parent TTLs')
    def add(target, origin, kind, name, typ, proto, expected=(), **kwargs):
        checks.append({'query': query(len(checks), target, name, typ, proto, recurse=kwargs.pop('recurse', False)),
                       'target': target['label'], 'zone': origin, 'kind': kind,
                       'expected': set(expected), **kwargs})
    for target in public + backends:
        is_backend = target in backends
        for proto in ('udp', 'tcp'):
            for origin, records in sorted(zones.items()):
                groups = rrsets(records)
                cuts = cuts_for(origin, records)
                for (owner, typ), expected in sorted(groups.items()):
                    shadow = next((c for c in cohosted if beneath(owner, c)), None) if not is_backend else None
                    delegation = next((c for c in cuts if beneath(owner, c)), None)
                    add(target, origin, 'rrset', owner, typ, proto, expected,
                        require_aa=not bool(delegation) or bool(shadow), ignore_ttl=bool(shadow),
                        answer_only=not bool(delegation) or bool(shadow),
                        parent_ttl_via_backend=bool(shadow))
                    if typ == 'CNAME' and not delegation:
                        # An A lookup can include a CNAME chain. Validate the
                        # requested alias RRset without mistaking chased data.
                        add(target, origin, 'cname-chain', owner, 'A', proto, expected, require_aa=True)
                    if owner.startswith('*.'):
                        synthesized = nonce + '.' + owner[2:]
                        rewritten = {(synthesized, t, ttl, content) for _, t, ttl, content in expected}
                        add(target, origin, 'wildcard', synthesized, typ, proto, rewritten, require_aa=True)
                add(target, origin, 'nxdomain', negative_name(origin, records, nonce), 'A', proto,
                    groups[(origin, 'SOA')], require_aa=True)
                if (origin, 'DNSKEY') not in groups:
                    add(target, origin, 'nodata', origin, 'DNSKEY', proto, groups[(origin, 'SOA')], require_aa=True)
                for cut in cuts:
                    if (cut, 'DS') not in groups:
                        add(target, origin, 'nodata', cut, 'DS', proto, groups[(origin, 'SOA')], require_aa=True)
            add(target, '', 'refused', nonce+'.invalid.', 'A', proto, recurse=False)
            add(target, '', 'refused', nonce+'.invalid.', 'A', proto, recurse=True)
        for origin in sorted(zones):
            add(target, origin, 'axfr-refused', origin, 'AXFR', 'tcp')
    require(len(checks) <= 5000, 'Query plan exceeds safety bound')
    return checks


def strip_ttl(records):
    return {(owner, typ, content) for owner, typ, _, content in records}


def verify_check(check, raw):
    if raw.get('error'):
        return raw['error']
    if raw.get('returncode') != 0:
        return 'dig_failed'
    try:
        answer = parse_dig(raw['stdout'])
    except Exception:
        return 'unparseable_response'
    flags, status = answer['flags'], answer['status']
    if not answer['response_seen']:
        return 'missing_dns_response'
    if 'tc' in flags:
        return 'truncated_response'
    if 'ra' in flags:
        return 'recursion_available'
    if check['kind'] in ('refused', 'axfr-refused'):
        return None if status == 'REFUSED' and not answer['records'] else 'not_explicitly_refused'
    if check.get('require_aa') and 'aa' not in flags:
        return 'not_authoritative'
    expected = check['expected']
    if check['kind'] in ('nxdomain', 'nodata'):
        wanted = 'NXDOMAIN' if check['kind'] == 'nxdomain' else 'NOERROR'
        if status != wanted or answer['sections']['answer']:
            return 'incorrect_negative_answer'
        normalized = set()
        for owner, typ, ttl, content in expected:
            rd = dns.rdata.from_wire(1, 'SOA', bytes.fromhex(content), 0, len(bytes.fromhex(content)))
            normalized.add((owner, typ, min(ttl, rd.minimum), content))
        found = {r for r in answer['sections']['authority'] if r[0] == check['zone'] and r[1] == 'SOA'}
        return None if found == normalized else 'negative_soa_or_ttl_differs'
    if status != 'NOERROR':
        return 'unexpected_rcode'
    selectors = {(r[0], r[1]) for r in expected}
    pool = answer['sections']['answer'] if check.get('answer_only', True) else answer['records']
    found = {r for r in pool if (r[0], r[1]) in selectors}
    if check.get('ignore_ttl'):
        return None if strip_ttl(found) == strip_ttl(expected) else 'cohosted_child_rrset_differs'
    return None if found == expected else 'rrset_or_ttl_differs'


def save_report(path, report):
    path = path.expanduser().resolve()
    require(not path.is_relative_to(REPO), 'Keep DNS verification evidence outside the public Git repository')
    require(path.parent.is_dir(), 'Output parent directory must already exist')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())



def self_test():
    import unittest
    class Checks(unittest.TestCase):
        def response(self, body='', status='NOERROR', flags='qr aa', section='ANSWER'):
            return {'returncode': 0, 'stdout': (
                ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
                ';; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n'
                ';; ->>HEADER<<- opcode: QUERY, status: '+status+', id: 1\n'
                ';; flags: '+flags+'; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n'
                ';; '+section+' SECTION:\n'+body+'\n')}
        def check(self, expected, **kwargs):
            return {'kind':'rrset', 'zone':'example.', 'require_aa':True,
                    'expected':{expected}, **kwargs}
        def test_domain_name_rdata_canonicalization(self):
            a=canonical('WWW.Example.',300,'CNAME','Target.Example.')
            b=canonical('www.example.',300,'CNAME','target.example.')
            self.assertEqual(a,b)
        def test_cname_chased_records_are_not_alias_rrset(self):
            c=self.check(canonical('www.example.',300,'CNAME','target.example.'),kind='cname-chain')
            r=self.response('www.example. 300 IN CNAME target.example.\ntarget.example. 60 IN A 192.0.2.1')
            self.assertIsNone(verify_check(c,r))
        def test_ttl_difference_fails(self):
            c=self.check(canonical('www.example.',300,'A','192.0.2.1'))
            self.assertEqual(verify_check(c,self.response('www.example. 299 IN A 192.0.2.1')),'rrset_or_ttl_differs')
        def test_additional_data_does_not_mask_missing_answer(self):
            c=self.check(canonical('www.example.',300,'A','192.0.2.1'))
            self.assertEqual(verify_check(c,self.response('www.example. 300 IN A 192.0.2.1',section='ADDITIONAL')),'rrset_or_ttl_differs')
        def test_child_ttl_exception_preserves_record_validation(self):
            c=self.check(canonical('ns.child.example.',300,'A','192.0.2.1'),ignore_ttl=True)
            self.assertIsNone(verify_check(c,self.response('ns.child.example. 30 IN A 192.0.2.1')))
            self.assertEqual(verify_check(c,self.response('ns.child.example. 30 IN A 192.0.2.2')),'cohosted_child_rrset_differs')
        def test_negative_soa_ttl_is_capped(self):
            value='ns.example. hostmaster.example. 1 10 10 604800 300'
            c=self.check(canonical('example.',86400,'SOA',value),kind='nxdomain')
            self.assertIsNone(verify_check(c,self.response('example. 300 IN SOA '+value,status='NXDOMAIN',section='AUTHORITY')))
        def test_recursion_flag_fails(self):
            c=self.check(canonical('www.example.',300,'A','192.0.2.1'))
            self.assertEqual(verify_check(c,self.response('',flags='qr aa ra')),'recursion_available')
        def test_truncation_is_not_silently_successful_udp(self):
            c=self.check(canonical('www.example.',300,'A','192.0.2.1'))
            self.assertEqual(verify_check(c,self.response('',flags='qr aa tc')),'truncated_response')
        def test_refusal_must_be_explicit(self):
            c={'kind':'axfr-refused','expected':set()}
            self.assertIsNone(verify_check(c,self.response(status='REFUSED',flags='qr')))
            self.assertEqual(verify_check(c,self.response(status='SERVFAIL',flags='qr')),'not_explicitly_refused')
        def test_referral_uses_authority_without_aa(self):
            c=self.check(canonical('child.example.',300,'NS','ns.child.example.'),require_aa=False,answer_only=False)
            self.assertIsNone(verify_check(c,self.response('child.example. 300 IN NS ns.child.example.',flags='qr',section='AUTHORITY')))
        def test_nxdomain_anchor_for_wildcard_only_zone(self):
            records=[canonical('example.',300,'A','192.0.2.1'),canonical('*.example.',300,'A','192.0.2.1')]
            self.assertEqual(negative_name('example.',records,'_probe'),'_probe.*.example.')
        def test_invalid_endpoint_rejected(self):
            with self.assertRaises((RuntimeError,ValueError)):
                endpoint('x=127.0.0.1;echo bad')
        def test_remote_runner_rejects_udp_fallback(self):
            self.assertIn("'+ignore'",REMOTE)
            self.assertNotIn('shell=True',REMOTE)
        def test_static_inventory_and_cohosting_guard(self):
            zones=load_static()
            self.assertEqual(len(zones),20)
            with self.assertRaises(RuntimeError):
                build_checks(zones,[endpoint('test=192.0.2.1')],[],{'apps.shanginn.io.'},'_probe')
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--via', required=True, help='Existing SSH alias used as DNS query vantage point')
    p.add_argument('--server', action='append', required=True, type=endpoint, help='Public LABEL=IP[:PORT]')
    p.add_argument('--backend-server', action='append', default=[], type=endpoint, help='Internal LABEL=IP[:PORT]')
    p.add_argument('--backend-via', help='Optional separate SSH alias that can reach the internal backend')
    p.add_argument('--legacy-primary', required=True, type=endpoint, help='Read-only dynamic AXFR source LABEL=IP[:PORT]')
    p.add_argument('--cohosted-zone', action='append', default=[], type=fqdn)
    p.add_argument('--workers', type=int, default=4, choices=range(1, 9))
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    targets = args.server + args.backend_server
    require(len(targets) <= 6 and len({t['label'] for t in targets}) == len(targets), 'Use at most six distinctly labelled endpoints')
    started = time.time()
    zones = load_static()
    dynamic_before = load_dynamic(args.via, args.legacy_primary, args.workers)
    zones.update(dynamic_before)
    nonce = '_infra-dns-check-' + uuid.uuid4().hex[:16]
    checks = build_checks(zones, args.server, args.backend_server, set(args.cohosted_zone), nonce)
    backend_labels = {t['label'] for t in args.backend_server}
    public_queries = [c['query'] for c in checks if c['target'] not in backend_labels]
    backend_queries = [c['query'] for c in checks if c['target'] in backend_labels]
    results = remote_queries(args.via, public_queries, args.workers)
    if backend_queries:
        results.update(remote_queries(args.backend_via or args.via, backend_queries, args.workers))
    failures = []
    counts = {}
    for check in checks:
        kind = check['kind']
        counts[kind] = counts.get(kind, 0) + 1
        reason = verify_check(check, results[check['query']['id']])
        if reason:
            failures.append({'server': check['target'], 'zone': check['zone'], 'kind': kind,
                             'name': check['query']['name'], 'type': check['query']['type'],
                             'transport': check['query']['transport'], 'reason': reason})
    static_after = load_static()
    static_changed = sorted(z for z in static_after if static_after[z] != zones[z])
    if static_changed:
        failures.append({'kind': 'git_source_changed_during_verification', 'zones': static_changed,
                         'reason': 'rerun_after_static_source_stabilizes'})
    dynamic_after = load_dynamic(args.via, args.legacy_primary, args.workers)
    changed = sorted(z for z in DYNAMIC if dynamic_before[z] != dynamic_after[z])
    if changed:
        failures.append({'kind': 'source_changed_during_verification', 'zones': changed,
                         'reason': 'rerun_after_dynamic_source_stabilizes'})
    report = {'ok': not failures, 'vantage': args.via, 'started_unix': started,
              'finished_unix': time.time(), 'static_zones': 20, 'dynamic_zones': 2,
              'rrsets': sum(len(rrsets(r)) for r in zones.values()),
              'records': sum(len(r) for r in zones.values()), 'queries': len(checks),
              'query_kinds': counts, 'passed': len(checks) - sum(1 for f in failures if 'server' in f),
              'failed': len(failures), 'failures': failures,
              'parent_ttl_public_exceptions': sum(bool(c.get('parent_ttl_via_backend')) for c in checks),
              'parent_ttl_checked_by': [t['label'] for t in args.backend_server],
              'backend_vantage': args.backend_via or args.via,
              'record_fingerprint': hashlib.sha256(json.dumps(zones, sort_keys=True).encode()).hexdigest(),
              'dynamic_source_stable': not changed, 'static_source_stable': not static_changed, 'mutations': False}
    save_report(args.output, report)
    print(json.dumps({k: v for k, v in report.items() if k not in ('failures', 'record_fingerprint')}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(self_test() if sys.argv[1:] == ['--self-test'] else main())
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'ok': False, 'error': str(error)}), file=sys.stderr)
        sys.exit(2)
