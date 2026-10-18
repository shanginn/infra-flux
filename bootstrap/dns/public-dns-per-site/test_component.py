#!/usr/bin/env python3
"""Render-scope guards for the inactive per-site DNS bootstrap."""
import copy,json,pathlib,subprocess,tempfile,unittest
import yaml
ROOT=pathlib.Path(__file__).resolve().parents[3];HERE=pathlib.Path(__file__).resolve().parent
BASE=ROOT/'clusters/unified/public-dns'
def render(path):return {x['kind']+'/'+x['metadata']['name']:x for x in yaml.safe_load_all(subprocess.check_output(['kubectl','kustomize',str(path)]))if x}
class Component(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.before=render(BASE)
  # Place the disposable overlay within the repository so the same relative
  # resources/component paths and default load restrictions are exercised.
  cls.temp=tempfile.TemporaryDirectory(prefix='.per-site-render-',dir=ROOT/'bootstrap/dns');p=pathlib.Path(cls.temp.name)
  (p/'kustomization.yaml').write_text('apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [../../../clusters/unified/public-dns]\ncomponents: [../public-dns-per-site]\n');cls.after=render(p)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_only_exact_two_objects_change(self):
  self.assertEqual(set(self.before),set(self.after));changed={k for k in self.before if self.before[k]!=self.after[k]};self.assertEqual(changed,{'DaemonSet/public-dns','ConfigMap/public-dns-config-8kb7hccgc2'})
 def test_initial_files_are_identical(self):
  k='ConfigMap/public-dns-config-8kb7hccgc2';old=self.before[k];expected=copy.deepcopy(old);core=old['data']['Corefile'];self.assertEqual((HERE/'msk.Corefile').read_text(),core);self.assertEqual((HERE/'fin.Corefile').read_text(),core);expected['data'].update({'msk.Corefile':core,'fin.Corefile':core});self.assertEqual(self.after[k],expected)
 def test_ondelete_args_only_core_process(self):
  k='DaemonSet/public-dns';expected=copy.deepcopy(self.before[k]);expected['spec']['updateStrategy']={'type':'OnDelete'};containers=expected['spec']['template']['spec']['containers'];core=next(c for c in containers if c['name']=='coredns');self.assertNotIn('env',core);core['env']=[{'name':'NODE_NAME','valueFrom':{'fieldRef':{'fieldPath':'spec.nodeName'}}}];core['args']=['-conf','/config/$(NODE_NAME).Corefile'];self.assertEqual(self.after[k],expected)
 def test_parent_inactive(self):
  for path in (ROOT/'clusters').rglob('*.yaml'):self.assertNotIn('public-dns-per-site',path.read_text())
 def test_no_dynamic_route_or_readers(self):
  for name in('msk.Corefile','fin.Corefile'):
   text=(HERE/name).read_text();self.assertIn('reload ',text);self.assertNotIn('10.120.53.54',text)
if __name__=='__main__':unittest.main()
