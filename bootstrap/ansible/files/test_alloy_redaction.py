#!/usr/bin/env python3
"""Synthetic local Alloy fixture. Set ALLOY_BINARY to a verified release binary.
Replaces only discovery root and output with a local echo; no cluster or network destination.
"""
import datetime
import os
import pathlib
import subprocess
import socket
import tempfile
import time
import unittest

CONFIG = pathlib.Path(__file__).resolve().parents[3] / 'clusters/unified/observability/logging/config.alloy'

@unittest.skipUnless(os.environ.get('ALLOY_BINARY'), 'ALLOY_BINARY not set')
class Redaction(unittest.TestCase):
    def test_real_pipeline_drops_sensitive_sources_and_redacts_values(self):
        with tempfile.TemporaryDirectory(prefix='infra-alloy-fixture-') as root:
            root=pathlib.Path(root); pods=root/'pods'
            config=CONFIG.read_text().split('loki.write "home" {',1)[0]
            config=config.replace('level = "warn"','level = "info"').replace('/var/log/pods',str(pods)).replace('tail_from_end = true','tail_from_end = false')
            config=config.replace('loki.write.home.receiver','loki.echo.fixture.receiver')+'\nloki.echo "fixture" {}\n'
            cfg=root/'config.alloy'; cfg.write_text(config)
            now=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
            def lines(ns,pod,values):
                file=pods/(ns+'_'+pod+'_11111111-1111-4111-8111-111111111111')/'app'/'0.log'
                file.parent.mkdir(parents=True)
                file.write_text(''.join(now+' stdout F '+x+'\n' for x in values))
            lines('demo','web', ['SAFE_HEALTHY_LINE', 'password=CANARY_PASSWORD','Authorization: Bearer CANARY_BEARER',
                                'Cookie: session=CANARY_COOKIE','url=https://user:CANARY_URL_PASSWORD@invalid.example/path?key=CANARY_QUERY',
                                'dsn=postgresql://user:CANARY_PG_PASSWORD@invalid.example/db',
                                'dsn=postgres://user:CANARY_PG_SHORT_PASSWORD@invalid.example/db',
                                'token=CANARY_TOKEN','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.CANARY_SIGNATURE',
                                '-----BEGIN PRIVATE KEY----- CANARY_PEM', 'CANARY_LONG_'+'x'*9000])
            lines('infra-ha-test','observer',['CANARY_TEST_NAMESPACE'])
            lines('database','postgres-restore-fixture',['CANARY_RESTORE_POD'])
            lines('logging','loki',['CANARY_FEEDBACK'])
            lines('demo-audit','web',['CANARY_AUDIT'])
            log=root/'output.log'
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
            with log.open('w') as out:
                proc=subprocess.Popen([os.environ['ALLOY_BINARY'],'run','--disable-reporting','--server.http.listen-addr=127.0.0.1:'+str(port),
                    '--storage.path='+str(root/'state'),str(cfg)],stdout=out,stderr=subprocess.STDOUT,env={**os.environ,'NODE_NAME':'fixture'})
                try:
                    deadline=time.monotonic()+15
                    while time.monotonic()<deadline:
                        if proc.poll() is not None: break
                        output=log.read_text()
                        if 'SAFE_HEALTHY_LINE' in output and '[REDACTED-JWT]' in output: break
                        time.sleep(.2)
                    time.sleep(.5)
                finally:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
            output=log.read_text()
            self.assertIn('SAFE_HEALTHY_LINE',output,output[-2000:])
            self.assertIn('[REDACTED]',output)
            self.assertIn('[REDACTED-JWT]',output)
            self.assertIn('[REDACTED-QUERY]',output)
            self.assertIn('postgresql://[REDACTED]@invalid.example/db',output)
            self.assertIn('postgres://[REDACTED]@invalid.example/db',output)
            self.assertNotIn('CANARY_',output,output[-3000:])
            self.assertIn('namespace="demo"',output.replace(chr(92),''))
            self.assertNotIn('filename=',output)

if __name__=='__main__':unittest.main()
