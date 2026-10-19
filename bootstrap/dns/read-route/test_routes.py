"""Offline Kustomize and routing-isolation tests. No cluster access."""
import copy
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import unittest
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

def render(base, component=None, omit_components=()):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve()
        source = ROOT / base
        if omit_components:
            original = source
            source = path / 'base'
            shutil.copytree(original, source)
            file = source / 'kustomization.yaml'
            value = yaml.safe_load(file.read_text())
            refs = value.get('components', [])
            for ref in omit_components:
                assert refs.count(ref) == 1
                refs.remove(ref)
            value['components'] = [os.path.relpath((original / ref).resolve(), source) for ref in refs]
            file.write_text(yaml.safe_dump(value))
        config = {'apiVersion':'kustomize.config.k8s.io/v1beta1','kind':'Kustomization',
                  'resources':[os.path.relpath(source,path)]}
        if component:
            config['components']=[os.path.relpath(HERE / component,path)]
        (path/'kustomization.yaml').write_text(yaml.safe_dump(config))
        raw = subprocess.check_output(['kubectl','kustomize',str(path),'--load-restrictor','LoadRestrictionsNone'], text=True)
        return {(x['kind'],x['metadata']['name']):x for x in yaml.safe_load_all(raw) if x}

def one(objects,kind,name):return objects[(kind,name)]

def config(objects,prefix,key):
    matches=[x['data'][key] for (kind,name),x in objects.items() if kind=='ConfigMap' and name.startswith(prefix) and key in x['data']]
    assert len(matches)==1
    return matches[0]

class RouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = {site:render('clusters/'+site+'/vibesites-dns') for site in ['rubase','contabo']}
        cls.legacy = {site:render('clusters/'+site+'/vibesites-dns','legacy-dnsdist') for site in cls.old}
        cls.proxyold=render('clusters/rubase/vibesites-dns/legacy-api-proxy')
        cls.proxy=cls.proxyold
        omit=('../../../bootstrap/dns/read-route/public-reader-egress',)
        cls.publicold=render('clusters/unified/public-dns',omit_components=omit)
        cls.public=render('clusters/unified/public-dns','unified-public',omit_components=omit)
        cls.contabo=render('bootstrap/dns/read-route/contabo-forwarder')
        cls.zones=set((ROOT/'clusters/unified/dns-authority/zones.txt').read_text().splitlines())

    def test_only_separate_rubase_preview_references_routes(self):
        allowed=ROOT/'clusters/rubase/vibesites-dns/legacy-api-proxy/kustomization.yaml'
        for folder in ['clusters','components']:
            for path in (ROOT/folder).rglob('*.yaml'):
                if path==allowed:
                    self.assertEqual(yaml.safe_load(path.read_text())['components'],
                                     ['../../../../bootstrap/dns/read-route/rubase-proxy'])
                    continue
                if path==ROOT/'clusters/unified/public-dns/kustomization.yaml':
                    self.assertEqual(yaml.safe_load(path.read_text())['components'],
                                     ['../../../bootstrap/dns/public-dns-per-site',
                                      '../../../bootstrap/dns/read-route/public-reader-egress'])
                    continue
                self.assertNotIn('bootstrap/dns/read-route',path.read_text(),str(path))

    def test_legacy_changes_only_dnsdist_and_one_config_key(self):
        for site,after in self.legacy.items():
            before=self.old[site]
            self.assertEqual(set(before),set(after))
            for key in before:
                if key==('Deployment','vibesites-dnsdist'):continue
                if key==('ConfigMap','vibesites-dns-config'):
                    a,b=copy.deepcopy(before[key]),copy.deepcopy(after[key])
                    del a['data']['dnsdist.conf'];del b['data']['dnsdist.conf']
                    self.assertEqual(a,b)
                else:self.assertEqual(before[key],after[key],key)

    def test_legacy_has_exact_bind_routes_and_two_strict_health_backends(self):
        text=config(self.legacy['rubase'],'vibesites-dns-config','dnsdist.conf')
        self.assertEqual(set(re.findall(r"bind_zones:add\(newDNSName\('([^']+)\.'\)\)",text)),self.zones)
        self.assertEqual(text.count('mustResolve=true'),2)
        self.assertEqual(text.count("checkName='health.test.'"),2)
        self.assertEqual(text.count(':5354'),2)
        self.assertIn('setServFailWhenNoServer(true)',text)
        self.assertNotIn('__POWERDNS_ADDRESS__',text)
        self.assertLess(text.index('SuffixMatchNodeRule(health_zones)'),text.index('AllRule()'))

    def test_legacy_rollout_preserves_listener_and_avoids_old_api_dependency(self):
        for site,after in self.legacy.items():
            dep=one(after,'Deployment','vibesites-dnsdist')
            self.assertEqual(dep['spec']['strategy']['rollingUpdate'],{'maxSurge':1,'maxUnavailable':0})
            command=dep['spec']['template']['spec']['containers'][0]['args'][0]
            self.assertNotIn('vibesites-powerdns',command)
            self.assertNotIn('${bind9_ip}',command)
            self.assertIn('test -n "$1"',command)
            self.assertEqual(dep['spec']['template']['spec']['containers'][0]['ports'],one(self.old[site],'Deployment','vibesites-dnsdist')['spec']['template']['spec']['containers'][0]['ports'])

    def test_proxy_has_no_dns_dependency_on_legacy_vip(self):
        text=config(self.proxy,'legacy-pdns-api-proxy-config','Corefile')
        self.assertNotIn('LEGACY_POWERDNS_DNS_SERVICE_ADDRESS',text)
        self.assertIn('${MSK_VPN_ADDRESS}:5354 ${FIN_VPN_ADDRESS}:5354',text)
        leaf=ROOT/'clusters/rubase/vibesites-dns/legacy-api-proxy'
        self.assertEqual(config(self.proxy,'legacy-pdns-api-proxy-config','haproxy.cfg'),(leaf/'haproxy.cfg').read_text())
        policy=one(self.proxy,'NetworkPolicy','legacy-pdns-api-proxy')['spec']
        original=yaml.safe_load((leaf/'network-policy.yaml').read_text())['spec']
        self.assertEqual(policy['ingress'],original['ingress'])
        self.assertEqual(policy['egress'][0],original['egress'][0])
        self.assertEqual(policy['egress'][1]['ports'],[{'port':5354,'protocol':'UDP'},{'port':5354,'protocol':'TCP'}])
        self.assertNotIn('podSelector',str(policy['egress']))

    def test_public_routes_every_bind_zone_and_retains_apps(self):
        text=config(self.public,'public-dns-config','Corefile')
        block=next(line.strip() for line in text.splitlines() if line.strip().startswith('except '))
        self.assertEqual(set(block.split()[1:]),self.zones)
        self.assertLess(text.index('forward . 10.120.53.54:53'),text.index('forward . 10.120.53.53:53'))
        self.assertNotRegex(text,r'(?m)^\s*next\s')
        self.assertIn('apps.shanginn.io:53 {',text)
        self.assertIn('file /zones/apps.db apps.shanginn.io',text)
        self.assertEqual(text.count('forward . 10.120.53.53:53'),1)
        self.assertEqual(text.count('forward . 10.120.53.54:53'),1)
        self.assertIn('health.test:53 vibesites-dns-health.test:53',text)
        self.assertIn('rcode REFUSED',text)

    def test_public_reload_does_not_change_pods_or_other_config(self):
        a,b=self.publicold,self.public
        for key in a:
            if key==('ConfigMap','public-dns-config-8kb7hccgc2'):
                ca,cb=copy.deepcopy(a[key]),copy.deepcopy(b[key]);del ca['data']['Corefile'];del cb['data']['Corefile'];self.assertEqual(ca,cb)
            else:self.assertEqual(a[key],b[key],key)
        extra=set(b)-set(a)
        self.assertEqual(extra,{('NetworkPolicy','public-dns-powerdns-readers')})
        p=b[next(iter(extra))]['spec'];self.assertEqual(p['policyTypes'],['Egress'])
        self.assertEqual(p['egress'][0]['ports'],[{'port':5353,'protocol':'UDP'},{'port':5353,'protocol':'TCP'}])

    def test_public_health_apex_ds_is_also_refused_by_root_chain(self):
        # CoreDNS handles a DS query at an exact child apex in its parent chain.
        # Therefore a child-only refusal must not be our only health-zone guard.
        text=config(self.public,'public-dns-config','Corefile')
        root=text.split('\nshanginn.io:53 .:53 {',1)[1]
        template='template ANY ANY health.test vibesites-dns-health.test {\n        rcode REFUSED\n    }'
        self.assertIn(template,root)
        self.assertLess(root.index(template),root.index('forward .'))

    def test_contabo_forwarder_has_no_writer_or_old_service(self):
        self.assertEqual({kind for kind,_ in self.contabo},{'Deployment','ConfigMap','Service','NetworkPolicy'})
        self.assertEqual(len(self.contabo),4)
        self.assertEqual([name for kind,name in self.contabo if kind=='Service'],['legacy-pdns-read-forwarder-preview'])
        pod=one(self.contabo,'Deployment','legacy-pdns-read-forwarder')['spec']['template']
        self.assertEqual(pod['metadata']['labels'],{'app.kubernetes.io/name':'legacy-pdns-read-forwarder'})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertEqual(len(pod['spec']['containers']),1)
        self.assertNotIn('secret',str(pod).lower())
        self.assertNotIn('8081',str(self.contabo))
        self.assertNotIn('18081',str(self.contabo))
        for c in pod['spec']['containers']:
            self.assertIn('@sha256:',c['image'])
            self.assertEqual(c['securityContext']['capabilities'],{'drop':['ALL'],'add':['NET_BIND_SERVICE']})

    def test_contabo_egress_only_two_dns_entries(self):
        p=one(self.contabo,'NetworkPolicy','legacy-pdns-read-forwarder')['spec']
        self.assertEqual(p['policyTypes'],['Ingress','Egress'])
        self.assertEqual(p['egress'],[{'to':[{'ipBlock':{'cidr':'${MSK_VPN_ADDRESS}/32'}},{'ipBlock':{'cidr':'${FIN_VPN_ADDRESS}/32'}}],'ports':[{'port':5354,'protocol':'UDP'},{'port':5354,'protocol':'TCP'}]}])

    def test_contabo_owner_is_detached_suspended_and_requires_private_map(self):
        owner=yaml.safe_load((HERE/'contabo-forwarder-flux.example.yaml').read_text())
        self.assertEqual(owner['metadata'],{'name':'legacy-powerdns-read-forwarder','namespace':'flux-system'})
        spec=owner['spec']
        self.assertIs(spec['suspend'],True)
        self.assertIs(spec['wait'],True)
        self.assertEqual(spec['path'],'./bootstrap/dns/read-route/contabo-forwarder')
        self.assertEqual(spec['dependsOn'],[{'name':'vibesites-dns'}])
        self.assertEqual(spec['postBuild']['substituteFrom'],[{'kind':'ConfigMap','name':'legacy-dns-read-forwarder','optional':False}])
        for folder in ['clusters','components']:
            for path in (ROOT/folder).rglob('*.yaml'):
                self.assertNotIn('legacy-powerdns-read-forwarder',path.read_text(),str(path))

if __name__=='__main__':unittest.main()
