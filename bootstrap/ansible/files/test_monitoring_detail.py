import importlib.util
from pathlib import Path
import unittest
import stat
import types
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('detail',Path(__file__).with_name('monitoring-detail.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MetricsSafety(unittest.TestCase):
    def test_identity_labels_removed_and_summed(self):
        raw=b'headscale_mapresponse_sent_total{node="secret-node",user="private"} 3\nheadscale_mapresponse_sent_total{node="other"} 4\n'
        result=m.parse_metrics(raw,'headscale');self.assertEqual(result,{'infra_headscale_mapresponse_sent_total':7})
        self.assertNotIn('secret',str(result));self.assertNotIn('private',str(result))
    def test_unknown_families_not_forwarded(self):
        raw=b'derp_bytes_sent 12\nprivate_key_info{value="hidden"} 1\n'
        self.assertEqual(m.parse_metrics(raw,'derp'),{'infra_derp_bytes_sent':12})
    def test_only_bucket_boundary_survives(self):
        raw=b'http_request_duration_seconds_bucket{path="/node/private",le="1"} 8\nhttp_request_duration_seconds_bucket{le="1",path="/other"} 3\n'
        self.assertEqual(m.parse_metrics(raw,'headscale'),{'infra_headscale_http_request_duration_seconds_bucket{le="1"}':11})
    def test_oversize_rejected(self):
        with self.assertRaises(RuntimeError):m.parse_metrics(b'#'*(1048577),'derp')
    def test_nonfinite_rejected(self):
        for value in ('NaN','+Inf','-1'):
            with self.subTest(value=value),self.assertRaises(RuntimeError):m.parse_metrics(('derp_bytes_sent '+value+'\n').encode(),'derp')
    def test_malformed_rejected(self):
        with self.assertRaises(RuntimeError):m.parse_metrics(b'derp_bytes_sent{broken\n','derp')
    def test_empty_allowlist_is_failure(self):
        with self.assertRaises(RuntimeError):m.parse_metrics(b'go_goroutines 3\n','derp')
    def test_gpu_units_and_no_serial(self):
        r=m.gpu_metrics(b'0, 25, 1024, 8192, 50\n');self.assertEqual(r['infra_gpu_memory_used_bytes{gpu="0"}'],1073741824)
        self.assertEqual(r['infra_gpu_temperature_celsius{gpu="0"}'],50)
    def test_gpu_unavailable_fails_not_zero(self):
        with self.assertRaises(ValueError):m.gpu_metrics(b'0, N/A, 0, 8192, 45\n')
    def test_duplicate_gpu_rejected(self):
        with self.assertRaises(RuntimeError):m.gpu_metrics(b'0, 1, 2, 3, 4\n0, 1, 2, 3, 4\n')
    def gpu_files(self,foreign=False,writable=False,cycle=False):
        link='/usr/bin/nvidia-smi';target='/usr/lib/nvidia/nvidia-smi'
        def info(path):
            name=str(path)
            mode=stat.S_IFLNK|0o777 if name==link else ((stat.S_IFREG|(0o777 if writable else 0o755)) if name==target else stat.S_IFDIR|0o755)
            return types.SimpleNamespace(st_uid=1000 if foreign and name==target else 0,st_mode=mode)
        return patch.object(m.Path,'lstat',info),patch.object(m.Path,'resolve',lambda self,strict=False:self),patch.object(m.os,'readlink',lambda p:link if cycle else target)
    def test_gpu_root_alternative_allowed(self):
        a,b,c=self.gpu_files()
        with a,b,c:self.assertEqual(m.gpu_executable(),'/usr/lib/nvidia/nvidia-smi')
    def test_gpu_foreign_target_rejected(self):
        a,b,c=self.gpu_files(foreign=True)
        with a,b,c,self.assertRaises(RuntimeError):m.gpu_executable()
    def test_gpu_writable_target_rejected(self):
        a,b,c=self.gpu_files(writable=True)
        with a,b,c,self.assertRaises(RuntimeError):m.gpu_executable()
    def test_gpu_cycle_rejected(self):
        a,b,c=self.gpu_files(cycle=True)
        with a,b,c,self.assertRaises(RuntimeError):m.gpu_executable()
    def test_unowned_loaded_unit_rejected(self):
        result=types.SimpleNamespace(returncode=0,stdout=b'LoadState=loaded\nActiveState=active\nMainPID=23\nFragmentPath=/run/systemd/transient/infra-monitoring-detail.service\nDropInPaths=\n')
        with patch.object(m.subprocess,'run',return_value=result),self.assertRaises(RuntimeError):m.unit_guard(False)
    def test_dropin_rejected(self):
        result=types.SimpleNamespace(returncode=0,stdout=b'LoadState=loaded\nActiveState=inactive\nMainPID=0\nFragmentPath=/etc/systemd/system/infra-monitoring-detail.service\nDropInPaths=/etc/systemd/system/infra-monitoring-detail.service.d/override.conf\n')
        with patch.object(m.subprocess,'run',return_value=result),self.assertRaises(RuntimeError):m.unit_guard(True)
if __name__=='__main__':unittest.main()
