#!/usr/bin/env python3
"""Bounded kubelet serving TLS maintenance; no wildcard CSR approver or restart retry."""
import argparse
import base64
import copy
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import time
import types
import uuid

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID

OWNER = 'infra-flux/kubelet-serving-tls-v1'
ROOT = Path('/etc/infra-flux/kubelet-serving-tls')
CONFIG = Path('/var/lib/kubelet/config.yaml')
SERVER_CERT = Path('/var/lib/kubelet/pki/kubelet-server-current.pem')
BASE_SHA = '93bcb56f662d4b8e56b76235543c62f1465bbc9d5b1350417aa1867f7f6fd7f3'
base = common = None


def require(value, message):
    if not value: raise RuntimeError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def load_helpers(endpoint_source, shared_source):
    global base, common
    require(sha(endpoint_source.encode()) == BASE_SHA, 'Review changed endpoint helper before reuse')
    base = types.ModuleType('reviewed_endpoint')
    exec(compile(endpoint_source, '<reviewed-endpoint>', 'exec'), base.__dict__)
    base.load_common(shared_source); common = base.common
    # Leave base.ROOT unchanged: its inspect requires the previous HA endpoint proof.
    common.ROOT = ROOT; common.OWNER = OWNER


class StrictLoader(yaml.SafeLoader): pass


def mapping(loader, node, deep=False):
    pairs = loader.construct_pairs(node, deep=deep); result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate kubelet configuration key')
        result[key] = value
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def patch_config(raw):
    obj = yaml.load(raw, Loader=StrictLoader)
    require(isinstance(obj, dict) and obj.get('apiVersion') == 'kubelet.config.k8s.io/v1beta1' and
            obj.get('kind') == 'KubeletConfiguration', 'Unexpected kubelet configuration type')
    require(obj.get('serverTLSBootstrap') in (None, False, True) and
            not obj.get('tlsCertFile') and not obj.get('tlsPrivateKeyFile') and
            obj.get('featureGates', {}).get('RotateKubeletServerCertificate', True) is True,
            'Explicit serving certificates or disabled rotation require separate review')
    require(obj.get('authentication', {}).get('anonymous', {}).get('enabled') is False and
            obj.get('authentication', {}).get('webhook', {}).get('enabled') is True and
            obj.get('authorization', {}).get('mode') == 'Webhook', 'Kubelet authentication/authorization changed')
    lines = list(re.finditer(rb'^serverTLSBootstrap:[^\r\n]*(?:\r?\n|$)', raw, re.M))
    require(len(lines) <= 1 and ('serverTLSBootstrap' not in obj or len(lines) == 1), 'Unexpected serving bootstrap scalar syntax')
    candidate = (raw[:lines[0].start()] + b'serverTLSBootstrap: true\n' + raw[lines[0].end():]) if lines else raw + (b'' if raw.endswith(b'\n') else b'\n') + b'serverTLSBootstrap: true\n'
    expected = copy.deepcopy(obj); expected['serverTLSBootstrap'] = True
    require(yaml.load(candidate, Loader=StrictLoader) == expected, 'Changes outside serverTLSBootstrap are forbidden')
    return candidate


def argv_guard(process):
    args = Path('/proc', str(process['pid']), 'cmdline').read_bytes().split(b'\0')
    require(args.count(b'--config=/var/lib/kubelet/config.yaml') == 1 and
            not any(a == b'--config' or (a.startswith(b'--config=') and a != b'--config=/var/lib/kubelet/config.yaml') or
                    a.startswith((b'--tls-cert-file', b'--tls-private-key-file', b'--rotate-server-certificates', b'--feature-gates')) for a in args),
            'Unexpected kubelet config/TLS/feature-gate overrides')


def read_record():
    if not ROOT.exists():
        require(not ROOT.is_symlink(), 'Symlink maintenance directory'); return None
    st = ROOT.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Untrusted maintenance directory')
    record = json.loads(common.trusted(ROOT / 'record.json', True))
    require(record.get('owner') == OWNER and re.fullmatch('[0-9a-f]{32}', record.get('token', '')), 'Unknown maintenance owner')
    require(record.get('phase') in ('prepared', 'config-written', 'restart-intent', 'verified'), 'Unknown maintenance phase')
    require(sha(common.trusted(ROOT / 'config.before.yaml', True)) == record['before_sha256'] and
            sha(common.trusted(ROOT / 'bootstrap.before.json', True)) == record['bootstrap_sha256'], 'Maintenance preimage changed')
    return record


def inspect(node, ca=None):
    prior, _, _, marker, endpoint_record = base.inspect(node, ca)
    require(endpoint_record and endpoint_record['phase'] == 'verified' and prior['server'] == base.ENDPOINT,
            'Complete the owned HA kubelet endpoint maintenance first')
    raw = common.trusted(CONFIG); mode = stat.S_IMODE(CONFIG.lstat().st_mode)
    require(CONFIG.lstat().st_gid == 0 and mode in (0o600, 0o644), 'Unexpected root kubelet config permissions')
    candidate = patch_config(raw); process = base.kubelet_process(); argv_guard(process)
    host = base.get('node', node, node_credentials=True); record = read_record()
    proof = {k: prior[k] for k in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')}
    proof.update(config_sha256=sha(raw), candidate_sha256=sha(candidate), changed=raw != candidate, mode=mode)
    require(record is not None or raw != candidate, 'Unowned enabled serving bootstrap requires explicit adoption review')
    if record:
        for key in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256'):
            require(proof[key] == record[key], 'Maintenance identity changed: ' + key)
        require(record['after_sha256'] == sha(candidate) and sha(raw) in (record['before_sha256'], record['after_sha256']), 'Config changed outside maintenance')
    return proof, raw, candidate, marker, record, host


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def expected_sans(node):
    addresses = node['status'].get('addresses', [])
    dns = {a['address'] for a in addresses if a['type'] == 'Hostname'}
    ips = {str(ipaddress.ip_address(a['address'])) for a in addresses if a['type'] == 'InternalIP'}
    require(dns == {node['metadata']['name']} and len(ips) == 1, 'Review changed node hostname/IP topology')
    require({a['type'] for a in addresses} <= {'Hostname', 'InternalIP'}, 'Review additional Node address types before signing')
    return dns, ips


def san_sets(san):
    require(all(isinstance(x, (x509.DNSName, x509.IPAddress)) for x in san), 'URI/email/other SAN types forbidden')
    dns = san.get_values_for_type(x509.DNSName); ips = [str(x) for x in san.get_values_for_type(x509.IPAddress)]
    require(len(dns) == len(set(dns)) and len(ips) == len(set(ips)), 'Duplicate SANs forbidden')
    return set(dns), set(ips)


def validate_csr(obj, node, earliest, now, client_cert_sha256):
    spec = obj['spec']; name = node['metadata']['name']
    require(obj.get('apiVersion') == 'certificates.k8s.io/v1' and obj.get('kind') == 'CertificateSigningRequest', 'Unexpected CSR kind')
    require(re.fullmatch(r'csr-[a-z0-9]+', obj['metadata']['name']) and obj['metadata'].get('uid') and obj['metadata'].get('resourceVersion'), 'Unexpected CSR identity')
    created = base.lease_time(obj['metadata']['creationTimestamp'])
    require(earliest <= created <= now + 5 and now - created <= 900, 'CSR is not within the reviewed 15-minute issuance window')
    require(spec['signerName'] == 'kubernetes.io/kubelet-serving' and spec['username'] == 'system:node:' + name and
            sorted(spec.get('groups', [])) == ['system:authenticated', 'system:nodes'], 'Unexpected CSR authenticated requester')
    require(re.fullmatch('[0-9a-f]{64}', client_cert_sha256 or '') and spec.get('extra') ==
            {'authentication.kubernetes.io/credential-id': ['X509SHA256=' + client_cert_sha256]},
            'CSR authenticated client certificate fingerprint differs')
    require(spec.get('expirationSeconds') is None, 'Review non-default requested lifetime')
    raw = base64.b64decode(spec['request'], validate=True)
    csr = x509.load_pem_x509_csr(raw)
    require(csr.is_signature_valid, 'Invalid CSR signature')
    expected_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'system:node:' + name), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'system:nodes')])
    require(sorted((a.oid.dotted_string, a.value) for a in csr.subject) == sorted((a.oid.dotted_string, a.value) for a in expected_subject), 'Unexpected CSR subject')
    require(len(csr.extensions) == 1 and csr.extensions[0].oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME and not csr.extensions[0].critical,
            'Unexpected CSR extensions')
    dns, ips = san_sets(csr.extensions[0].value)
    require((dns, ips) == expected_sans(node), 'CSR must match exactly the fresh Node hostname and private IP')
    key = csr.public_key(); usages = ['digital signature', 'server auth']
    if isinstance(key, rsa.RSAPublicKey):
        require(key.key_size >= 2048, 'Weak RSA CSR'); usages.append('key encipherment')
    else:
        require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1), 'Review changed kubelet key algorithm')
    require(sorted(spec['usages']) == sorted(usages), 'Unexpected serving usages for key algorithm')
    conditions = obj.get('status', {}).get('conditions', [])
    require(all(c['type'] == 'Approved' and c.get('status') == 'True' for c in conditions) and len(conditions) <= 1, 'Denied/Failed/unknown CSR condition')
    return {'name': obj['metadata']['name'], 'uid': obj['metadata']['uid'], 'request_sha256': sha(raw),
            'spki_sha256': sha(spki(key)), 'client_certificate_sha256': client_cert_sha256, 'dns': sorted(dns), 'ips': sorted(ips)}, csr


def csr_list(node):
    return [x for x in json.loads(base.kube(['get', 'csr', '-o', 'json']))['items']
            if x['spec'].get('signerName') == 'kubernetes.io/kubelet-serving' and x['spec'].get('username') == 'system:node:' + node]


def current_client_fingerprint():
    path = Path(base.CERT); target = path.resolve(strict=True)
    require(path.is_symlink() and target.parent == path.parent and target.name.startswith('kubelet-client-'), 'Unexpected current client certificate target')
    cert = x509.load_pem_x509_certificate(common.trusted(target, True))
    return sha(cert.public_bytes(serialization.Encoding.DER))


def approve_once(record, node):
    if not record.get('csr'):
        fresh = [x for x in csr_list(record['node']) if base.lease_time(x['metadata']['creationTimestamp']) >= record['dispatch_unix'] - 3]
        require(len(fresh) == 1, 'Waiting for exactly one fresh serving CSR; ambiguous requests require manual review')
        obj = fresh[0]; proof, _ = validate_csr(obj, node, record['dispatch_unix'] - 3, time.time(), current_client_fingerprint())
        require(not obj.get('status', {}).get('conditions') and not obj.get('status', {}).get('certificate'), 'CSR was approved outside this maintenance')
        record['csr'] = proof; record['approval'] = 'prepared'; common.save_record(record)
    obj = base.get('csr', record['csr']['name']); proof, csr = validate_csr(obj, node, record['dispatch_unix'] - 3, time.time(), current_client_fingerprint())
    require(proof == record['csr'], 'CSR identity/request changed')
    if record['approval'] == 'prepared':
        require(not obj.get('status', {}).get('conditions') and not obj.get('status', {}).get('certificate'), 'Unexpected external CSR approval')
        record['approval'] = 'dispatched'; common.save_record(record)
        obj.setdefault('status', {})['conditions'] = [{'type': 'Approved', 'status': 'True', 'reason': 'InfraOwnedNodeServingTLS',
              'message': 'Exact node identity, fresh CSR, subject, SAN and key usages verified by bounded maintenance',
              'lastUpdateTime': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')}]
        # PUT carries UID/resourceVersion. Unknown dispatch is only observed, never retried.
        try:
            base.kube(['replace', '--raw=/apis/certificates.k8s.io/v1/certificatesigningrequests/' + proof['name'] + '/approval', '-f', '-'], obj)
        except (RuntimeError, subprocess.TimeoutExpired): pass
        obj = base.get('csr', proof['name'])
    require(obj['metadata']['uid'] == proof['uid'] and sha(base64.b64decode(obj['spec']['request'], validate=True)) == proof['request_sha256'], 'Issued CSR identity differs')
    require(obj.get('status', {}).get('certificate'), 'Waiting for signed serving certificate; unknown approval must not be retried')
    return csr, base64.b64decode(obj['status']['certificate'], validate=True)


def verify_endpoint(csr, issued, node):
    cert = x509.load_pem_x509_certificate(issued)
    require(spki(cert.public_key()) == spki(csr.public_key()) and cert.subject == csr.subject, 'Issued key/subject differs from approved CSR')
    require(san_sets(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == expected_sans(node), 'Issued SAN differs')
    require(set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == {ExtendedKeyUsageOID.SERVER_AUTH}, 'Unexpected issued EKU')
    ca_raw = common.trusted(Path('/etc/kubernetes/pki/ca.crt')); ca = x509.load_pem_x509_certificate(ca_raw)
    cert.verify_directly_issued_by(ca)
    require(SERVER_CERT.is_symlink(), 'Expected kubelet-managed serving certificate symlink')
    target = SERVER_CERT.resolve(strict=True)
    require(target.parent == SERVER_CERT.parent and re.fullmatch(r'kubelet-server-.*\.pem', target.name), 'Unexpected serving keypair location')
    pair = common.trusted(target, True); disk = x509.load_pem_x509_certificate(pair)
    private = serialization.load_pem_private_key(pair, password=None)
    require(disk.public_bytes(serialization.Encoding.DER) == cert.public_bytes(serialization.Encoding.DER) and spki(private.public_key()) == spki(csr.public_key()), 'Persisted serving keypair differs from CSR/issued certificate')
    ip = next(iter(expected_sans(node)[1])); ctx = ssl.create_default_context(cafile='/etc/kubernetes/pki/ca.crt')
    with socket.create_connection((ip, 10250), timeout=5) as tcp:
        with ctx.wrap_socket(tcp, server_hostname=ip) as tls:
            require(tls.getpeercert(binary_form=True) == cert.public_bytes(serialization.Encoding.DER), 'Real kubelet TLS endpoint presents another certificate')
    return {'certificate_sha256': sha(cert.public_bytes(serialization.Encoding.DER)), 'expires': cert.not_valid_after_utc.isoformat(), 'verified_private_ip': True}


def apply(args):
    proof, before, candidate, marker, record, node = inspect(args.node, args.ca_sha256)
    base.validate_review(proof, args.review_json)
    require(re.fullmatch('[0-9a-f]{64}', args.expected_sha256 or '') and (args.expected_sha256 == proof['config_sha256'] or
            (record and args.expected_sha256 == record['before_sha256'])), 'Reviewed kubelet config preimage differs')
    common.lock_available(record)
    prior = base.health(args.node) if record is None or record['phase'] in ('prepared', 'config-written', 'verified') else None
    if record is None:
        require(not SERVER_CERT.exists() and not SERVER_CERT.is_symlink(), 'Pre-existing serving keypair requires explicit adoption review')
        require(not [x for x in csr_list(args.node) if not x.get('status', {}).get('certificate') and not x.get('status', {}).get('conditions')], 'Pre-existing pending serving CSR requires review')
        process = base.kubelet_process(); running = base.workloads(); old_lease = base.lease(args.node)
        ROOT.mkdir(mode=0o700); common.atomic(ROOT / 'config.before.yaml', before); common.atomic(ROOT / 'bootstrap.before.json', marker)
        record = {**{k: proof[k] for k in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')},
                  'owner': OWNER, 'token': uuid.uuid4().hex, 'phase': 'prepared', 'before_sha256': sha(before), 'after_sha256': sha(candidate),
                  'mode': proof['mode'], 'member_ids': prior['member_ids'], 'kubelet_before': process, 'workloads_before': running,
                  'lease_before': old_lease, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        common.save_record(record)
    if prior: require(prior['member_ids'] == record['member_ids'], 'etcd membership changed')
    if record['phase'] == 'verified':
        require(before == candidate, 'Verified serving config was reverted')
        held = common.fault_lock()
        if held and held['data'].get('phase') == 'active': common.release(record)
        return {**proof, 'changed': False, 'already_verified': True, 'health': prior}
    require(record['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'Reboot during unfinished maintenance requires manual review')
    common.acquire(record)
    require(common.trusted(CONFIG) == before and common.trusted(base.BOOTSTRAP, True) == marker, 'Preimage changed')
    if record['phase'] == 'prepared':
        if before != candidate:
            common.atomic(CONFIG, candidate)
            os.chmod(CONFIG, record['mode'])  # Preserve original root-only/readable mode; YAML contains no private key.
        record['phase'] = 'config-written'; common.save_record(record)
    base.restart_once(record)
    deadline = time.monotonic() + 360; stable_since = None; last_error = None
    while time.monotonic() < deadline:
        try:
            fresh, raw, wanted, current_marker, _, host = inspect(args.node, args.ca_sha256)
            require(raw == wanted and current_marker == marker and fresh['node_uid'] == record['node_uid'], 'Identity/config changed during recovery')
            process = base.kubelet_process(); current_lease = base.lease(args.node)
            base.validate_recovery(record, process, current_lease, base.workloads())
            if not record.get('observed_new_process'):
                record['observed_new_process'] = process; record['observed_new_lease'] = current_lease; common.save_record(record); continue
            csr, issued = approve_once(record, host); tls_proof = verify_endpoint(csr, issued, host)
            after = base.health(args.node); require(after['member_ids'] == record['member_ids'], 'etcd membership changed')
            if stable_since is None: stable_since = time.monotonic()
            if time.monotonic() - stable_since >= 30:
                record.update(phase='verified', verified_unix=time.time(), certificate=tls_proof, kubelet_after=process)
                common.save_record(record); common.release(record)
                return {**proof, 'changed': True, 'health': after, 'certificate': tls_proof, 'workload_pids_preserved': True, 'stable_seconds': 30}
        except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as error:
            last_error = type(error).__name__ + ': ' + str(error); stable_since = None
        time.sleep(3)
    raise RuntimeError('TLS recovery unverified; lock retained. No restart/approval retry: ' + str(last_error))


def renewal(args):
    proof, _, _, _, initial, node = inspect(args.node, args.ca_sha256)
    require(initial and initial['phase'] == 'verified', 'Complete initial serving TLS maintenance before renewal')
    require(re.fullmatch(r'csr-[a-z0-9]+', args.csr_name or ''), 'One explicit CSR name is required')
    obj = base.get('csr', args.csr_name)
    csr_proof, _ = validate_csr(obj, node, time.time() - 900, time.time(), current_client_fingerprint())
    if args.action == 'inspect-renewal':
        common.lock_available(); proof['csr'] = csr_proof; proof['health'] = base.health(args.node)
        return proof
    base.validate_review(proof, args.review_json)
    require(args.csr_uid == csr_proof['uid'] and args.csr_sha256 == csr_proof['request_sha256'], 'Reviewed exact CSR UID/request SHA differs')
    parent = ROOT / 'renewals'; directory = parent / args.csr_name
    if parent.exists():
        st = parent.lstat(); require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Untrusted renewal directory')
    common.ROOT = directory
    if directory.exists():
        st = directory.lstat(); require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'Untrusted CSR record directory')
        record = json.loads(common.trusted(directory / 'record.json', True))
        require(record.get('owner') == OWNER and record.get('csr') == csr_proof and record.get('phase') in ('prepared', 'verified') and
                re.fullmatch('[0-9a-f]{32}', record.get('token', '')), 'Unexpected renewal record')
        for k in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256'):
            require(record[k] == proof[k], 'Renewal node identity changed')
    else:
        common.lock_available(); health = base.health(args.node)
        require(not obj.get('status', {}).get('conditions') and not obj.get('status', {}).get('certificate'), 'Only an unapproved reviewed CSR may begin renewal')
        if not parent.exists(): parent.mkdir(mode=0o700)
        directory.mkdir(mode=0o700)
        record = {**{k: proof[k] for k in ('node', 'node_uid', 'machine_id', 'ca_sha256', 'bootstrap_sha256')},
                  'owner': OWNER, 'token': uuid.uuid4().hex, 'phase': 'prepared', 'csr': csr_proof, 'approval': 'prepared',
                  'dispatch_unix': base.lease_time(obj['metadata']['creationTimestamp']) + 3, 'member_ids': health['member_ids']}
        common.save_record(record)
    common.lock_available(record); health = base.health(args.node)
    require(record['member_ids'] == health['member_ids'], 'Renewal etcd membership changed')
    if record['phase'] == 'verified':
        held = common.fault_lock()
        if held and held['data'].get('phase') == 'active': common.release(record)
        return {**proof, 'changed': False, 'renewal_verified': True}
    common.acquire(record); deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        # Fresh CA/machine/NodeUID/client-authentication checks before each approval/observation.
        fresh, *_, host = inspect(args.node, args.ca_sha256)
        base.validate_review(fresh, args.review_json)
        try:
            csr, issued = approve_once(record, host); cert = verify_endpoint(csr, issued, host)
            health = base.health(args.node); require(health['member_ids'] == record['member_ids'], 'Renewal membership changed')
            record.update(phase='verified', verified_unix=time.time(), certificate=cert)
            common.save_record(record); common.release(record)
            return {**proof, 'changed': True, 'renewal_verified': True, 'certificate': cert}
        except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError): time.sleep(3)
    raise RuntimeError('Renewal unverified; exact CSR record/lock retained. Approval is not retried after unknown dispatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'apply', 'inspect-renewal', 'approve-renewal']); parser.add_argument('--node', choices=['home', 'msk', 'fin'], required=True)
    parser.add_argument('--endpoint-source', required=True); parser.add_argument('--shared-source', required=True)
    parser.add_argument('--ca-sha256'); parser.add_argument('--expected-sha256'); parser.add_argument('--review-json')
    parser.add_argument('--csr-name'); parser.add_argument('--csr-uid'); parser.add_argument('--csr-sha256')
    args = parser.parse_args(); require(os.geteuid() == 0, 'Run on the owned node as root')
    load_helpers(args.endpoint_source, args.shared_source)
    if args.action == 'inspect':
        proof, *_, record, node = inspect(args.node, args.ca_sha256); common.lock_available(record)
        proof['health'] = base.health(args.node); proof['expected_sans'] = [sorted(x) for x in expected_sans(node)]
        print(json.dumps(proof, sort_keys=True)); return
    require(args.ca_sha256 or args.action == 'inspect-renewal', 'Reviewed CA required')
    common.trusted(base.BOOTSTRAP, True)
    with base.BOOTSTRAP.open('rb') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(renewal(args) if 'renewal' in args.action else apply(args), sort_keys=True))


if __name__ == '__main__': main()
