import ast
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('monitor',Path(__file__).with_name('monitor-alerts.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def payload(*alerts):
    return json.dumps({'status':'success','data':{'alerts':list(alerts)}}).encode()


def alert(name='DiskLow',severity='critical',state='firing',summary='Low space',replica='one'):
    return {'state':state,'labels':{'alertname':name,'severity':severity,'node':'msk','replica':replica},'annotations':{'summary':summary,'description':'changing 42'},'activeAt':'old','value':'42'}


class MonitorTests(unittest.TestCase):
    def test_remote_endpoint_binding(self):
        tree=ast.parse(m.REMOTE)
        selected=ast.Module(body=[v for v in tree.body if isinstance(v,(ast.FunctionDef,ast.ClassDef)) and v.name in ('validate_endpoint','NoRedirect')],type_ignores=[])
        namespace={'ipaddress':ipaddress,'urllib':__import__('urllib')}
        exec(compile(selected,'remote-fixture','exec'),namespace)
        validate=namespace['validate_endpoint']
        pod={'metadata':{'namespace':'monitoring','labels':{'app':'prometheus'},'ownerReferences':[{'kind':'StatefulSet','name':'prometheus','controller':True}]},'spec':{'nodeName':'msk'},'status':{'phase':'Running','podIP':'10.1.2.3','conditions':[{'type':'Ready','status':'True'}]}}
        self.assertEqual(validate({'items':[pod]},'msk','10.1.0.0/16'),'10.1.2.3')
        for section,key,value in [('metadata','namespace','other'),('metadata','labels',{'app':'other'}),('spec','nodeName','fin'),('status','podIP','192.0.2.10'),('status','conditions',[{'type':'Ready','status':'False'}])]:
            bad=copy.deepcopy(pod);bad[section][key]=value
            with self.assertRaises(ValueError):validate({'items':[bad]},'msk','10.1.0.0/16')
        with self.assertRaises(ValueError):validate({'items':[pod,pod]},'msk','10.1.0.0/16')
        self.assertIsNone(namespace['NoRedirect']().redirect_request(None,None,302,'',{},'https://example.invalid'))

    def test_only_firing_warning_critical(self):
        observed=m.alerts_from_payload(payload(alert(),alert('Waiting',state='pending'),alert('Info',severity='info')))
        self.assertEqual(len(observed),1)

    def test_replica_and_values_do_not_repeat(self):
        a=m.alerts_from_payload(payload(alert()))
        b=alert(replica='two');b['value']='55';b['activeAt']='new';b['annotations']['description']='changing 55'
        self.assertEqual(m.transition({'alerts':a},m.alerts_from_payload(payload(b))),[])

    def test_new_changed_resolved_once(self):
        a=m.alerts_from_payload(payload(alert()))
        self.assertEqual([e['kind'] for e in m.transition({},a)],['firing'])
        b=m.alerts_from_payload(payload(alert(summary='Different summary')))
        self.assertEqual([e['kind'] for e in m.transition({'alerts':a},b)],['changed'])
        self.assertEqual([e['kind'] for e in m.transition({'alerts':b},{})],['resolved'])
        self.assertEqual(m.transition({'alerts':{}},{}),[])

    def test_outage_threshold_and_recovery(self):
        self.assertEqual(m.failure_transition({})[1],[])
        self.assertEqual(m.failure_transition({'consecutive_failures':1})[1],[])
        self.assertEqual(m.failure_transition({'consecutive_failures':2})[1],[{'kind':'monitor_unavailable'}])
        self.assertEqual(m.failure_transition({'consecutive_failures':3,'unavailable_notified':True})[1],[])
        self.assertEqual(m.transition({'alerts':{},'unavailable_notified':True},{}),[{'kind':'monitor_recovered','active_count':0}])

    def test_bad_api_and_size(self):
        for bad in [b'{}',b'{"status":"success","data":{}}',b'x'*(m.LIMIT+1),b'not json']:
            with self.assertRaises((ValueError,TypeError)):
                m.alerts_from_payload(bad)

    def test_identity_validation(self):
        cfg={'ssh_aliases':['k8s-msk','k8s-fin'],'cluster_uid':'00000000-0000-0000-0000-000000000000','ca_sha256':'0'*64}
        self.assertEqual(m.validate_config(cfg),cfg)
        cfg['ssh_aliases']=['-oProxyCommand=unsafe']
        with self.assertRaises(ValueError):m.validate_config(cfg)

    def test_bounded_subprocess(self):
        self.assertEqual(m.bounded_run([sys.executable,'-c','print("ok")'],2,100),b'ok\n')
        with self.assertRaises(ValueError):m.bounded_run([sys.executable,'-c','print("x"*1000)'],2,100)
        with self.assertRaises(TimeoutError):m.bounded_run([sys.executable,'-c','import time;time.sleep(3)'],.1,100)

    def test_fallback(self):
        cfg={'ssh_aliases':['a','b'],'cluster_uid':'00000000-0000-0000-0000-000000000000','ca_sha256':'0'*64}
        with patch.object(m,'bounded_run',side_effect=[TimeoutError(),payload(alert())]):
            observed,source,errors=m.poll(cfg)
        self.assertEqual(source,'b');self.assertEqual(len(observed),1);self.assertEqual(errors,{'a':'TimeoutError'})

    def test_partial_notification_does_not_repeat_accepted_group(self):
        before=m.alerts_from_payload(payload(alert('Resolved')))
        after=m.alerts_from_payload(payload(alert('New')))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m.atomic_json(root/'status.json',{'owner':m.OWNER,'alerts':before})
            with patch.object(m,'poll',return_value=(after,'msk',{})),patch.object(m,'notify',side_effect=[None,RuntimeError()]):
                self.assertEqual(m.run_once({},root),1)
            state=json.loads((root/'status.json').read_text())
            self.assertEqual([e['kind'] for e in m.transition(state,after)],['resolved'])
            self.assertEqual((root/'status.json').stat().st_mode & 0o777,0o600)

    def test_outage_does_not_resolve_previous_alert(self):
        before=m.alerts_from_payload(payload(alert()))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m.atomic_json(root/'status.json',{'owner':m.OWNER,'alerts':before,'consecutive_failures':2})
            with patch.object(m,'poll',side_effect=m.PollUnavailable({'a':'TimeoutError'})),patch.object(m,'notify') as notify:
                self.assertEqual(m.run_once({},root),1)
                self.assertEqual(notify.call_count,1)
            state=json.loads((root/'status.json').read_text());self.assertEqual(state['alerts'],before);self.assertTrue(state['unavailable_notified']);self.assertFalse(state['ok'])


if __name__=='__main__':unittest.main()
