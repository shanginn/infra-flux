"""Offline readiness and graceful-reload safety checks; no cluster access."""
import json, os, pathlib, re, signal, subprocess, sys, tempfile, time, unittest
ROOT=pathlib.Path(__file__).resolve().parent
class DNSRuntime(unittest.TestCase):
    def test_all_zone_modes(self):
        s=(ROOT/'named.conf.zones').read_text()
        blocks=dict(re.findall(r'zone "([^"]+)" IN \{(.*?)\n\};',s,re.S))
        self.assertEqual(set(blocks),set((ROOT/'zones.txt').read_text().splitlines()))
        self.assertEqual(len(blocks),22)
        secondaries={z for z,b in blocks.items() if 'type secondary;' in b}
        self.assertEqual(secondaries,{'vibesites.ru','xn--80aacc0bc7ayl4g.xn--p1ai'})
        self.assertEqual(sum('type primary;' in b for b in blocks.values()),20)
        for z in secondaries:
            self.assertNotIn('/zones/',blocks[z])
            self.assertIn('primaries { legacy-bind; };',blocks[z])
    def readiness(self, mode):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            script=(ROOT/'readiness.sh').read_text().replace('/config/zones.txt',str(ROOT/'zones.txt'))
            (p/'readiness').write_text(script)
            (p/'dig').write_text('#!'+sys.executable+'\nimport os,sys\nm=os.environ["MODE"]\nzone=sys.argv[4]\nbad=zone=="vibesites.ru"\nstatus="SERVFAIL" if m=="servfail" and bad else "NOERROR"\nflags="qr" if m=="noaa" and bad else "qr aa"\nprint(";; ->>HEADER<<- opcode: QUERY, status: "+status+", id: 1")\nprint(";; flags: "+flags+"; QUERY: 1, ANSWER: 1")\nif not (m=="empty" and bad): print(zone+". 300 IN SOA ns.example. hostmaster.example. 1 10 10 604800 300")\n')
            (p/'dig').chmod(0o755)
            return subprocess.run(['/bin/sh',str(p/'readiness')],env={**os.environ,'PATH':str(p)+':'+os.environ['PATH'],'MODE':mode},capture_output=True).returncode
    def test_all_ready(self): self.assertEqual(self.readiness('valid'),0)
    def test_one_servfail_blocks_ready(self): self.assertNotEqual(self.readiness('servfail'),0)
    def test_non_authoritative_blocks_ready(self): self.assertNotEqual(self.readiness('noaa'),0)
    def test_empty_answer_blocks_ready(self): self.assertNotEqual(self.readiness('empty'),0)
    def test_supervisor_preserves_named_and_rejects_invalid_generation(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            for folder in ('config','zones','transfer','bin'): (p/folder).mkdir()
            for name in ('named.conf','named.conf.zones'): (p/'config'/name).write_text('valid')
            (p/'zones'/'example').write_text('serial 1')
            (p/'transfer'/'named.conf.transfers').write_text('runtime source')
            (p/'bin'/'named-checkconf').write_text('#!'+sys.executable+'\nimport pathlib,sys\nsys.exit(1 if "INVALID" in pathlib.Path('+repr(str(p/'config'/'named.conf'))+').read_text() else 0)\n')
            named='''import os,signal,time,pathlib,sys
p=pathlib.Path(%r)
(p/'named.pid').write_text(str(os.getpid()))
def hup(*a):
    with (p/'hups').open('a') as f: f.write(str(os.getpid())+'\\n')
signal.signal(signal.SIGHUP,hup)
signal.signal(signal.SIGTERM,lambda *a:sys.exit(0))
while True: time.sleep(.02)
''' % str(p)
            (p/'bin'/'named').write_text('#!'+sys.executable+'\n'+named)
            for f in (p/'bin').iterdir(): f.chmod(0o755)
            script=(ROOT/'run.sh').read_text().replace('/usr/sbin/named-checkconf',str(p/'bin'/'named-checkconf')).replace('/usr/sbin/named',str(p/'bin'/'named')).replace('/config/',str(p/'config')+'/').replace('/zones/',str(p/'zones')+'/').replace('/run/transfer/',str(p/'transfer')+'/').replace('sleep 5','sleep 0.1')
            (p/'run.sh').write_text(script)
            proc=subprocess.Popen(['/bin/sh',str(p/'run.sh')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            def wait_until(fn):
                end=time.monotonic()+3
                while time.monotonic()<end:
                    if fn(): return
                    time.sleep(.02)
                self.fail('timed out')
            try:
                wait_until(lambda:(p/'named.pid').exists())
                pid=(p/'named.pid').read_text()
                time.sleep(.3)
                self.assertFalse((p/'hups').exists())
                (p/'config'/'named.conf').write_text('INVALID')
                time.sleep(.3)
                self.assertFalse((p/'hups').exists())
                (p/'config'/'named.conf').write_text('valid new config')
                wait_until(lambda:(p/'hups').exists())
                time.sleep(.2)
                self.assertEqual((p/'hups').read_text().splitlines(),[pid])
                (p/'zones'/'example').write_text('serial 2')
                wait_until(lambda:len((p/'hups').read_text().splitlines())==2)
                self.assertEqual((p/'named.pid').read_text(),pid)
                self.assertEqual((p/'hups').read_text().splitlines(),[pid,pid])
                proc.terminate()
                out,err=proc.communicate(timeout=3)
                self.assertEqual(proc.returncode,0)
                self.assertEqual(err.count(b'failed validation'),1)
                self.assertEqual(err.count(b'reload requested'),2)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGKILL)
                    proc.communicate()
if __name__=='__main__': unittest.main()
