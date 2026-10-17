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
