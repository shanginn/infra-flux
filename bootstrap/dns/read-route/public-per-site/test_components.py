"""Actual-base render scope; no cluster access."""
import copy,importlib.util,re,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('route_tests',HERE.parent/'test_routes.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.base=m.render('clusters/unified/public-dns');cls.egress=m.render('clusters/unified/public-dns','public-reader-egress');cls.sites={x:m.render('clusters/unified/public-dns','public-per-site/'+x)for x in('msk','fin')};cls.cm=('ConfigMap','public-dns-config-8kb7hccgc2');cls.zones=set((m.ROOT/'clusters/unified/dns-authority/zones.txt').read_text().splitlines())
 def test_additive_egress_only(self):
  key=('NetworkPolicy','public-dns-powerdns-readers');self.assertEqual(set(self.egress)-set(self.base),{key});self.assertTrue(all(self.egress[k]==v for k,v in self.base.items()));self.assertEqual(self.egress[key]['spec'],m.yaml.safe_load((HERE.parent/'unified-public/reader-egress.yaml').read_text())['spec'])
 def test_each_site_changes_only_selected_file(self):
  for site,after in self.sites.items():
   self.assertEqual(set(after),set(self.base));expected=copy.deepcopy(self.base);expected[self.cm]['data'][site+'.Corefile']=(HERE/site/(site+'.Corefile')).read_text();self.assertEqual(after,expected)
 def test_preserves_app_authority_and_all_bind_suffixes(self):
  for site,after in self.sites.items():
   text=after[self.cm]['data'][site+'.Corefile'];old=self.base[self.cm]['data'][site+'.Corefile'];self.assertEqual(text.split('\n\n',1)[0],old.split('\n\n',1)[0]);self.assertEqual(set(re.search(r'^\s*except (.+)$',text,re.M).group(1).split()),self.zones);self.assertEqual(text,(HERE.parent/'unified-public/Corefile').read_text());self.assertNotIn('import ',text)
 def test_health_refusal_and_parent_dispatch_kept(self):
  for site,after in self.sites.items():
   text=after[self.cm]['data'][site+'.Corefile'];self.assertIn('health.test:53 vibesites-dns-health.test:53',text);self.assertIn('template ANY ANY health.test vibesites-dns-health.test',text);self.assertEqual(text.count('rcode REFUSED'),2);self.assertIn('shanginn.io:53 .:53 {',text);self.assertNotIn('next NXDOMAIN',text)
 def test_components_inactive(self):
  for p in (m.ROOT/'clusters').rglob('kustomization.yaml'):
   self.assertNotIn('public-per-site',p.read_text());self.assertNotIn('public-reader-egress',p.read_text())
 def test_daemonset_and_other_site_unchanged(self):
  for site,after in self.sites.items():
   self.assertEqual(after[('DaemonSet','public-dns')],self.base[('DaemonSet','public-dns')]);other='fin'if site=='msk'else'msk';self.assertEqual(after[self.cm]['data'][other+'.Corefile'],self.base[self.cm]['data'][other+'.Corefile']);self.assertEqual(after[self.cm]['data']['Corefile'],self.base[self.cm]['data']['Corefile'])
if __name__=='__main__':unittest.main()
