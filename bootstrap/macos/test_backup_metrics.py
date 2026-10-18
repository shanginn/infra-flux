#!/usr/bin/env python3
"""Check identity guards, atomic textfile output, and independent delivery status."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import types
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('metrics',Path(__file__).with_name('publish-backup-metrics.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
backup_spec=importlib.util.spec_from_file_location('backup',Path(__file__).with_name('backup.py'))
b=importlib.util.module_from_spec(backup_spec);backup_spec.loader.exec_module(b)


class ReceiverTests(unittest.TestCase):
    def setup_files(self, root):
        ca=b'test-public-ca';digest=hashlib.sha256(ca).hexdigest()
        files={
            '/etc/infra-flux/kubeadm-state.json':json.dumps({'managed_by':'infra-flux/ansible/kubeadm','cluster_name':'test','node_name':'msk','ca_sha256':digest}).encode(),
            '/etc/infra-flux/monitoring.json':json.dumps({'managed_by':'infra-flux/ansible/monitoring','node':'msk'}).encode(),
            '/etc/kubernetes/pki/ca.crt':ca,
        }
        mapping={}
        for name,data in files.items():
            path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);mapping[name]=path
        directory=(root/'collector').resolve();directory.mkdir()
        (directory/'other-producer.prom').write_text('other_metric 1\n')
        payload={'cluster_name':'test','ca_sha256':digest,'jobs':[{'name':'garage','configured':1,'last_success':123,'last_attempt_success':1}]}
        return mapping,directory,payload

    def run_receiver(self,mapping,directory,payload):
        real_path=Path
        def path(value):return mapping.get(str(value),real_path(value))
        with patch.object(m,'Path',side_effect=path),patch.object(m,'DIRECTORY',directory),patch.object(m,'TARGET',directory/'macbook-backup.prom'),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'stdin',io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))):
            m.main()

    def test_owned_atomic_file_and_other_producer_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping,directory,payload=self.setup_files(Path(tmp))
            self.run_receiver(mapping,directory,payload)
            text=(directory/'macbook-backup.prom').read_text()
            self.assertIn('infra_backup_last_success_timestamp_seconds{component="garage",destination="macbook"} 123',text)
            self.assertIn('129600',text)
            self.assertEqual((directory/'other-producer.prom').read_text(),'other_metric 1\n')
            self.assertEqual(list(directory.glob('.macbook-backup-*')),[])
            self.run_receiver(mapping,directory,payload)

    def test_wrong_ca_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping,directory,payload=self.setup_files(Path(tmp));payload['ca_sha256']='wrong'
            with self.assertRaises(AssertionError):self.run_receiver(mapping,directory,payload)
            self.assertFalse((directory/'macbook-backup.prom').exists())

    def test_unrelated_existing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping,directory,payload=self.setup_files(Path(tmp));target=directory/'macbook-backup.prom';target.write_text('foreign 1\n')
            with self.assertRaises(AssertionError):self.run_receiver(mapping,directory,payload)
            self.assertEqual(target.read_text(),'foreign 1\n')

    def test_label_injection_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping,directory,payload=self.setup_files(Path(tmp));payload['jobs'][0]['name']='x"}\ninjected_metric 1'
            with self.assertRaises(AssertionError):self.run_receiver(mapping,directory,payload)


class DeliveryTests(unittest.TestCase):
    def test_per_destination_jump_keeps_identity_payload_and_default_route(self):
        for chains in (None, {}, {'secondary': ['gateway', 'relay']}, {'secondary': []}):
            with self.subTest(chains=chains), tempfile.TemporaryDirectory() as tmp:
                status=Path(tmp)/'status.json'
                config={'jobs':[{'name':'garage','enabled':True,'ssh_jump_chain':['export-only']}],
                    'metrics_publication':{'enabled':True,'cluster_name':'test','ca_sha256':'a'*64,
                                           'ssh_aliases':['primary','secondary']}}
                if chains is not None:
                    config['metrics_publication']['ssh_jump_chains']=chains
                with patch.object(b,'STATUS',status),patch.object(b.subprocess,'run') as send:
                    b.publish_metrics(config)
                self.assertEqual(send.call_count,2)
                for call,alias in zip(send.call_args_list,['primary','secondary']):
                    argv=call.args[0]
                    self.assertEqual(argv[-2],alias)
                    self.assertIn('StrictHostKeyChecking=yes',argv)
                    self.assertIn('BatchMode=yes',argv)
                    self.assertNotIn('export-only',argv)
                    self.assertNotIn('HostKeyAlias=', ' '.join(argv[:-1]))
                    payload=json.loads(call.kwargs['input'])
                    self.assertEqual(payload['ca_sha256'],'a'*64)
                    self.assertEqual(payload['cluster_name'],'test')
                    expected=(chains or {}).get(alias,[])
                    if expected:
                        self.assertEqual(argv[argv.index('-J')+1],','.join(expected))
                    else:
                        self.assertNotIn('-J',argv)
                self.assertTrue(json.loads(status.read_text())['metrics_publication']['ok'])

    def test_invalid_mapping_fails_before_any_delivery_or_status_write(self):
        invalid=(None, [], 'secondary=gateway', {'unknown': []}, {'secondary': None},
                 {'secondary': 'gateway'}, {'secondary': ['secondary']},
                 {'secondary': ['gateway','gateway']}, {'secondary': ['-F']},
                 {'secondary': ['user@host']}, {'secondary': ['a','b','c','d']})
        for chains in invalid:
            with self.subTest(chains=chains),patch.object(b.subprocess,'run') as send, \
                    patch.object(b,'atomic_json') as write:
                config={'metrics_publication':{'enabled':True,'ssh_aliases':['secondary'],
                                                'ssh_jump_chains':chains}}
                with self.assertRaises(RuntimeError):
                    b.publish_metrics(config)
                send.assert_not_called()
                write.assert_not_called()

    def test_settings_rejects_unconfigured_metrics_jump_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            password=root/'password';password.write_text('fixture');password.chmod(0o600)
            config=root/'config.json'
            data={'owner':b.OWNER,'repository':str(root.parent/'unused-repository'),
                  'jobs':[{'name':'node','component':'node-config','ssh_aliases':['source'],'max_bytes':1048576}],
                  'metrics_publication':{'enabled':True,'cluster_name':'test','ca_sha256':'a'*64,
                                         'ssh_aliases':['secondary']}}
            config.write_text(json.dumps(data))
            with patch.object(b,'STATE',root),patch.object(b,'PASSWORD',password):
                b.settings(config)
                data['metrics_publication']['ssh_jump_chains']={'unknown': []}
                config.write_text(json.dumps(data))
                with self.assertRaises(RuntimeError):
                    b.settings(config)

    def test_installer_rejects_invalid_metrics_route_before_writing(self):
        with patch.dict(sys.modules,{'backup':b}):
            spec=importlib.util.spec_from_file_location('metrics_installer',Path(__file__).with_name('install.py'))
            installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as tmp:
            config=Path(tmp)/'config.json'
            config.write_text(json.dumps({'jobs':[{'component':'node-config','ssh_aliases':['source']}],
                'metrics_publication':{'ssh_aliases':['secondary'],'ssh_jump_chains':{'secondary':['secondary']}}}))
            responses=[types.SimpleNamespace(stdout='restic 0.19.1 test'),
                       types.SimpleNamespace(stdout='--stdin-from-command')]
            with patch.object(sys,'argv',['install.py','--config',str(config)]), \
                    patch.object(installer.sys,'platform','darwin'),patch.object(installer.os,'geteuid',return_value=501), \
                    patch.object(installer.shutil,'which',return_value='/fixture/restic'), \
                    patch.object(installer.subprocess,'run',side_effect=responses),patch.object(installer,'atomic_json') as write:
                with self.assertRaises(RuntimeError):
                    installer.main()
                write.assert_not_called()

    def test_one_unreachable_destination_preserves_actual_backup_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            status=Path(tmp)/'status.json'
            status.write_text(json.dumps({'ok':True,'last_success':123,
                'jobs':{'garage':{'ok':True,'last_success':123,'snapshot_id':'verified-id'}}}))
            config={'jobs':[{'name':'garage','enabled':True},{'name':'postgres','enabled':False}],
                'metrics_publication':{'enabled':True,'cluster_name':'test','ca_sha256':'a'*64,
                                       'ssh_aliases':['reachable','unreachable']}}
            seen=[]
            def send(argv,**kwargs):
                seen.append((argv[-2],json.loads(kwargs['input'])))
                if argv[-2]=='unreachable':raise subprocess.TimeoutExpired(argv,60)
            with patch.object(b,'STATUS',status),patch.object(b.subprocess,'run',side_effect=send),patch.object(b,'notify_failure') as notify:
                b.publish_metrics(config)
            result=json.loads(status.read_text())
            self.assertTrue(result['ok'])
            self.assertEqual(result['jobs']['garage']['snapshot_id'],'verified-id')
            self.assertFalse(result['metrics_publication']['ok'])
            self.assertTrue(result['metrics_publication']['targets']['reachable']['ok'])
            self.assertFalse(result['metrics_publication']['targets']['unreachable']['ok'])
            self.assertEqual([alias for alias,_ in seen],['reachable','unreachable'])
            self.assertEqual(seen[0][1]['jobs'][1]['configured'],0)
            notify.assert_called_once_with(metrics=True)


if __name__=='__main__':unittest.main()
