#!/usr/bin/env python3
"""Render-scope guards for the per-site DNS bootstrap."""
import copy,json,os,pathlib,shutil,subprocess,tempfile,unittest
import yaml
ROOT=pathlib.Path(__file__).resolve().parents[3];HERE=pathlib.Path(__file__).resolve().parent
BASE=ROOT/'clusters/unified/public-dns'
def render(path):return {x['kind']+'/'+x['metadata']['name']:x for x in yaml.safe_load_all(subprocess.check_output(['kubectl','kustomize',str(path)]))if x}
class Component(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # Compare the configured base with the same base without this one component.
  # Copy its files so normal Kustomize load restrictions remain in effect.
  cls.temp=tempfile.TemporaryDirectory(prefix='.per-site-render-',dir=ROOT/'bootstrap/dns');p=pathlib.Path(cls.temp.name)/'base';shutil.copytree(BASE,p)
  path=p/'kustomization.yaml';base=yaml.safe_load(path.read_text());refs=base['components'];target='../../../bootstrap/dns/public-dns-per-site';assert refs.count(target)==1;refs.remove(target);base['components']=[os.path.relpath((BASE/ref).resolve(),p)for ref in refs];path.write_text(yaml.safe_dump(base))
  cls.before=render(p);cls.after=render(BASE)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def test_only_exact_two_objects_change(self):
  self.assertEqual(set(self.before),set(self.after));changed={k for k in self.before if self.before[k]!=self.after[k]};self.assertEqual(changed,{'DaemonSet/public-dns','ConfigMap/public-dns-config-8kb7hccgc2'})
 def test_initial_files_are_identical(self):
  k='ConfigMap/public-dns-config-8kb7hccgc2';old=self.before[k];expected=copy.deepcopy(old);core=old['data']['Corefile'];self.assertEqual((HERE/'msk.Corefile').read_text(),core);self.assertEqual((HERE/'fin.Corefile').read_text(),core);expected['data'].update({'msk.Corefile':core,'fin.Corefile':core});self.assertEqual(self.after[k],expected)
 def test_ondelete_args_only_core_process(self):
  k='DaemonSet/public-dns';expected=copy.deepcopy(self.before[k]);expected['spec']['updateStrategy']={'type':'OnDelete'};containers=expected['spec']['template']['spec']['containers'];core=next(c for c in containers if c['name']=='coredns');self.assertNotIn('env',core);core['env']=[{'name':'NODE_NAME','valueFrom':{'fieldRef':{'fieldPath':'spec.nodeName'}}}];core['args']=['-conf','/config/$(NODE_NAME).Corefile'];self.assertEqual(self.after[k],expected)
 def test_exact_parent_activation(self):
  refs=[path for path in (ROOT/'clusters').rglob('*.yaml')if 'public-dns-per-site'in path.read_text()];self.assertEqual(refs,[BASE/'kustomization.yaml'])
 def test_no_dynamic_route_or_readers(self):
  for name in('msk.Corefile','fin.Corefile'):
   text=(HERE/name).read_text();self.assertIn('reload ',text);self.assertNotIn('10.120.53.54',text)
if __name__=='__main__':unittest.main()
