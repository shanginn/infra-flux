"""Offline exact two-Service alias/8081 removal tests. No cluster access."""
import copy,json,os,pathlib,subprocess,tempfile,unittest,yaml
HERE=pathlib.Path(__file__).resolve().parent
ROOT=pathlib.Path(os.environ.get('INFRA_REPO',str(HERE.parents[2])))
COMPONENT=HERE/'contabo-aliases'
def render(component=True,modified=None):
 with tempfile.TemporaryDirectory()as td:
  p=pathlib.Path(td).resolve();base=ROOT/'clusters/contabo/vibesites-dns'
  if modified is not None:
   (p/'service.yaml').write_text(yaml.safe_dump_all(modified));base=p/'base';base.mkdir();(base/'kustomization.yaml').write_text(yaml.safe_dump({'apiVersion':'kustomize.config.k8s.io/v1beta1','kind':'Kustomization','resources':['../service.yaml']}))
  k={'apiVersion':'kustomize.config.k8s.io/v1beta1','kind':'Kustomization','resources':[os.path.relpath(base,p)]}
  if component:k['components']=[os.path.relpath(COMPONENT,p)]
  (p/'kustomization.yaml').write_text(yaml.safe_dump(k));r=subprocess.run(['kubectl','kustomize',str(p),'--load-restrictor','LoadRestrictionsNone'],capture_output=True,text=True)
  if r.returncode:raise ValueError('Render rejected exact preimage: '+r.stderr[:2000])
  return {(x['kind'],x['metadata'].get('namespace'),x['metadata']['name']):x for x in yaml.safe_load_all(r.stdout)if x}
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.before=render(False);cls.after=render()
 def test_exactly_two_services_change(self):
  self.assertEqual(set(self.before),set(self.after));self.assertEqual({k for k in self.before if self.before[k]!=self.after[k]},{('Service','vibesites-dns',n)for n in('powerdns-authoritative','vibesites-powerdns')})
 def test_only_selector_and_api_port_change(self):
  for n in('powerdns-authoritative','vibesites-powerdns'):
   key=('Service','vibesites-dns',n);expected=copy.deepcopy(self.before[key]);expected['spec']['selector']={'app.kubernetes.io/name':'legacy-pdns-read-forwarder'};expected['spec']['ports']=expected['spec']['ports'][:2];self.assertEqual(expected,self.after[key]);self.assertEqual({(x['port'],x['protocol'])for x in expected['spec']['ports']},{(53,'TCP'),(53,'UDP')})
 def test_runtime_vips_uid_and_other_fields_preserved(self):
  rows=[copy.deepcopy(v)for k,v in self.before.items()if k[0]=='Service'and k[2]in('powerdns-authoritative','vibesites-powerdns')]
  for i,row in enumerate(rows):row['metadata']['uid']='synthetic-'+str(i);row['spec'].update(clusterIP='192.0.2.'+str(i+1),clusterIPs=['192.0.2.'+str(i+1)])
  got=render(modified=rows)
  for old in rows:
   new=got[('Service','vibesites-dns',old['metadata']['name'])];self.assertEqual(old['metadata'],new['metadata']);self.assertEqual(old['spec']['clusterIP'],new['spec']['clusterIP']);self.assertEqual(old['spec']['clusterIPs'],new['spec']['clusterIPs'])
 def test_wrong_selector_refused(self):
  old=copy.deepcopy(self.before[('Service','vibesites-dns','powerdns-authoritative')]);old['spec']['selector']={'app':'other'}
  with self.assertRaises(ValueError):render(modified=[old])
 def test_wrong_api_port_refused(self):
  old=copy.deepcopy(self.before[('Service','vibesites-dns','powerdns-authoritative')]);old['spec']['ports'][-1]['port']=8082
  with self.assertRaises(ValueError):render(modified=[old])
 def test_component_has_no_parent_activation(self):
  for folder in('clusters','components'):
   for path in(ROOT/folder).rglob('kustomization.yaml'):self.assertNotIn('read-route/contabo-aliases',path.read_text())
if __name__=='__main__':unittest.main()
