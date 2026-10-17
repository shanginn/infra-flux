#!/usr/bin/env python3
"""Offline safety cases: real CSRs, narrow config patch and single approval dispatch."""
import base64
import copy
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

spec=importlib.util.spec_from_file_location('serving',Path(__file__).with_name('kubelet-serving-tls.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NOW=1792260000
CLIENT_SHA="a"*64
NODE={'metadata':{'name':'fin','uid':'node-uid'},'status':{'addresses':[{'type':'Hostname','address':'fin'},{'type':'InternalIP','address':'192.0.2.10'}]}}
RAW=b'''apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous: {enabled: false}
  webhook: {enabled: true}
authorization: {mode: Webhook}
rotateCertificates: true
'''

def csr_obj(key=None, subject=None, sans=None, extension=None):
    import ipaddress
    key=key or ec.generate_private_key(ec.SECP256R1())
    subject=subject or x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,'system:nodes'),x509.NameAttribute(NameOID.COMMON_NAME,'system:node:fin')])
    sans=sans or [x509.DNSName('fin'),x509.IPAddress(ipaddress.ip_address('192.0.2.10'))]
    builder=x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(x509.SubjectAlternativeName(sans),False)
    if extension: builder=builder.add_extension(extension,True)
    raw=builder.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    usages=['digital signature','server auth']+(['key encipherment'] if isinstance(key,rsa.RSAPrivateKey) else [])
    return {'apiVersion':'certificates.k8s.io/v1','kind':'CertificateSigningRequest',
            'metadata':{'name':'csr-fixture','uid':'csr-uid','resourceVersion':'12','creationTimestamp':datetime.datetime.fromtimestamp(NOW-5,datetime.timezone.utc).isoformat()},
            'spec':{'request':base64.b64encode(raw).decode(),'signerName':'kubernetes.io/kubelet-serving','username':'system:node:fin','groups':['system:nodes','system:authenticated'],'extra':{'authentication.kubernetes.io/credential-id':['X509SHA256='+CLIENT_SHA]},'usages':usages}}

class Safety(unittest.TestCase):
    def setUp(self):
        m.base=types.SimpleNamespace(lease_time=lambda x:datetime.datetime.fromisoformat(x.replace('Z','+00:00')).timestamp())
        self.fp=patch.object(m,'current_client_fingerprint',return_value=CLIENT_SHA);self.fp.start();self.addCleanup(self.fp.stop)
    def valid(self,obj=None):return m.validate_csr(obj or csr_obj(),NODE,NOW-10,NOW,CLIENT_SHA)
    def test_exact_field_patch(self):
        self.assertEqual(m.patch_config(RAW),RAW+b'serverTLSBootstrap: true\n')
        self.assertEqual(m.patch_config(RAW+b'serverTLSBootstrap: false\n'),RAW+b'serverTLSBootstrap: true\n')
        self.assertEqual(m.patch_config(m.patch_config(RAW)),m.patch_config(RAW))
    def test_duplicate_config_rejected(self):
        with self.assertRaises(RuntimeError):m.patch_config(RAW+b'serverTLSBootstrap: false\nserverTLSBootstrap: true\n')
    def test_unknown_config_type_rejected(self):
        with self.assertRaises(RuntimeError):m.patch_config(RAW.replace(b'KubeletConfiguration',b'Config'))
    def test_explicit_key_rejected(self):
        with self.assertRaises(RuntimeError):m.patch_config(RAW+b'tlsPrivateKeyFile: /secret\n')
    def test_rotation_disabled_rejected(self):
        with self.assertRaises(RuntimeError):m.patch_config(RAW+b'featureGates: {RotateKubeletServerCertificate: false}\n')
    def test_anonymous_rejected(self):
        with self.assertRaises(RuntimeError):m.patch_config(RAW.replace(b'anonymous: {enabled: false}',b'anonymous: {enabled: true}'))
    def test_real_ecdsa_valid(self):self.assertEqual(self.valid()[0]['ips'],['192.0.2.10'])
    def test_real_rsa_valid(self):self.valid(csr_obj(key=rsa.generate_private_key(public_exponent=65537,key_size=2048)))
    def test_wrong_requester(self):
        x=csr_obj();x['spec']['username']='system:node:msk'
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_wrong_credential_fingerprint(self):
        x=csr_obj();x['spec']['extra']['authentication.kubernetes.io/credential-id']=['X509SHA256='+'b'*64]
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_unknown_extra_field(self):
        x=csr_obj();x['spec']['extra']['unreviewed']=['value']
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_missing_credential_fingerprint(self):
        x=csr_obj();del x['spec']['extra']
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_duplicate_credential_fingerprint(self):
        x=csr_obj();x['spec']['extra']['authentication.kubernetes.io/credential-id']*=2
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_extra_group(self):
        x=csr_obj();x['spec']['groups'].append('system:masters')
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_wrong_signer(self):
        x=csr_obj();x['spec']['signerName']='kubernetes.io/kube-apiserver-client'
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_extra_usage(self):
        x=csr_obj();x['spec']['usages'].append('client auth')
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_wrong_subject(self):
        x=csr_obj(subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'system:node:msk')]))
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_wildcard_san(self):
        with self.assertRaises(RuntimeError):self.valid(csr_obj(sans=[x509.DNSName('*.internal')]))
    def test_uri_san(self):
        with self.assertRaises(RuntimeError):self.valid(csr_obj(sans=[x509.UniformResourceIdentifier('spiffe://node/fin')]))
    def test_external_ip_rejected(self):
        import ipaddress
        with self.assertRaises(RuntimeError):self.valid(csr_obj(sans=[x509.DNSName('fin'),x509.IPAddress(ipaddress.ip_address('203.0.113.4'))]))
    def test_extra_extension_rejected(self):
        with self.assertRaises(RuntimeError):self.valid(csr_obj(extension=x509.BasicConstraints(ca=True,path_length=None)))
    def test_denied_rejected(self):
        x=csr_obj();x['status']={'conditions':[{'type':'Denied','status':'True'}]}
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_stale_rejected(self):
        x=csr_obj();x['metadata']['creationTimestamp']='2020-01-01T00:00:00Z'
        with self.assertRaises(RuntimeError):self.valid(x)
    def test_changed_node_sans_rejected(self):
        host=copy.deepcopy(NODE);host['status']['addresses'].append({'type':'ExternalIP','address':'203.0.113.1'})
        with self.assertRaises(RuntimeError):m.validate_csr(csr_obj(),host,NOW-10,NOW,CLIENT_SHA)
    def test_ambiguous_fresh_requests_rejected(self):
        x=csr_obj();m.base.kube=lambda *a:json.dumps({'items':[x,x]}).encode()
        with patch.object(m.time,'time',return_value=NOW),self.assertRaises(RuntimeError):m.approve_once({'node':'fin','dispatch_unix':NOW-8},NODE)
    def test_unknown_approval_is_never_retried(self):
        x=csr_obj();saved=[];calls=[]
        m.base.kube=lambda *a:json.dumps({'items':[x]}).encode();m.base.get=lambda *a:copy.deepcopy(x)
        m.common=types.SimpleNamespace(save_record=lambda r:saved.append(copy.deepcopy(r)))
        r={'node':'fin','dispatch_unix':NOW-8}
        def dispatch(argv,payload=None):
            calls.append((argv,copy.deepcopy(payload)));raise subprocess.TimeoutExpired('kubectl',5)
        with patch.object(m.time,'time',return_value=NOW):
            # First obtain and persist exact identity; then simulate one uncertain PUT.
            proof,_=self.valid(x);r.update(csr=proof,approval='prepared');m.base.kube=dispatch
            for _ in range(2):
                with self.assertRaises(RuntimeError):m.approve_once(r,NODE)
        self.assertEqual(len(calls),1);self.assertEqual(saved[0]['approval'],'dispatched')
        self.assertEqual(calls[0][1]['metadata']['resourceVersion'],'12');self.assertEqual(calls[0][1]['metadata']['uid'],'csr-uid')
    def test_identity_change_before_put_rejected(self):
        x=csr_obj();proof,_=self.valid(x);x['metadata']['uid']='foreign';calls=[]
        m.base.get=lambda *a:x;m.base.kube=lambda *a:calls.append(a)
        with patch.object(m.time,'time',return_value=NOW),self.assertRaises(RuntimeError):m.approve_once({'node':'fin','dispatch_unix':NOW-8,'csr':proof,'approval':'prepared'},NODE)
        self.assertFalse(calls)

if __name__=='__main__':unittest.main()
