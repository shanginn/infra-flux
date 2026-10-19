"""Render the real base and optional component without cluster access."""
import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
ZONES = {
    "xn--80aaa0aef8ckd2c.xn--p1ai",
    "xn--80agrjfkbaugg.xn--p1ai",
    "xn--90aoavb.xn--p1ai",
}


def render(component=False):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory).resolve()
        value = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": [os.path.relpath(BASE, path)],
        }
        if component:
            value["components"] = [os.path.relpath(HERE, path)]
        (path / "kustomization.yaml").write_text(yaml.safe_dump(value))
        raw = subprocess.check_output(
            ["kubectl", "kustomize", str(path),
             "--load-restrictor", "LoadRestrictionsNone"], text=True,
        )
        return {
            (x["kind"], x["metadata"]["name"]): x
            for x in yaml.safe_load_all(raw) if x
        }


def zones(text):
    return dict(re.findall(
        r'^zone "([^"]+)" IN \{\n(.*?)^\};', text, re.MULTILINE | re.DOTALL
    ))


class ComponentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before, cls.after = render(), render(True)
        cls.cm = ("ConfigMap", "bind-authority-config")
        cls.policy = ("NetworkPolicy", "bind-authority-legacy-powerdns")

    def test_render_changes_one_config_key_and_adds_one_policy(self):
        expected = copy.deepcopy(self.before)
        expected[self.cm]["data"]["named.conf.zones"] = (
            HERE / "named.conf.zones"
        ).read_text()
        expected[self.policy] = self.after[self.policy]
        self.assertEqual(self.after, expected)
        self.assertEqual(set(self.after) - set(self.before), {self.policy})

    def test_existing_zone_declarations_are_exact(self):
        old = (BASE / "named.conf.zones").read_text()
        new = self.after[self.cm]["data"]["named.conf.zones"]
        self.assertTrue(new.startswith(old))
        before, after = zones(old), zones(new)
        self.assertEqual(len(before), 22)
        self.assertEqual(set(after) - set(before), ZONES)
        self.assertEqual({k: after[k] for k in before}, before)
        self.assertEqual(len(re.findall(r'^zone ', new, re.MULTILINE)), 25)

    def test_new_zones_are_persistent_read_only_secondaries(self):
        all_zones = zones(self.after[self.cm]["data"]["named.conf.zones"])
        files = []
        for zone in ZONES:
            text = all_zones[zone]
            self.assertIn("type secondary;", text)
            self.assertIn("primaries { legacy-powerdns; };", text)
            self.assertIn("request-ixfr no;", text)
            self.assertIn("allow-notify { none; };", text)
            self.assertIn("allow-update-forwarding { none; };", text)
            file = re.search(r'file "([^"]+)";', text).group(1)
            self.assertEqual(file, "/var/lib/bind/pdns-" + zone)
            self.assertNotIn("/zones/", text)
            self.assertNotIn("type primary", text)
            files.append(file)
        self.assertEqual(len(set(files)), 3)
        named = self.after[self.cm]["data"]["named.conf"]
        for rule in ("allow-update { none; };", "allow-transfer { none; };"):
            self.assertIn(rule, named)

    def test_original_readiness_and_runtime_contract_unchanged(self):
        for key in ("zones.txt", "readiness.sh", "run.sh", "named.conf"):
            self.assertEqual(self.after[self.cm]["data"][key],
                             self.before[self.cm]["data"][key])
        self.assertEqual(len(self.after[self.cm]["data"]["zones.txt"].splitlines()), 22)
        for kind in ("StatefulSet", "Service", "PersistentVolumeClaim"):
            self.assertEqual(
                {k: v for k, v in self.after.items() if k[0] == kind},
                {k: v for k, v in self.before.items() if k[0] == kind},
            )
        self.assertIn('include "/run/transfer/named.conf.transfers";',
                      self.after[self.cm]["data"]["named.conf"])

    def test_additive_egress_is_one_private_address_dns_only(self):
        self.assertEqual(self.after[self.policy]["metadata"]["namespace"], "dns-authority")
        self.assertEqual(self.after[self.policy]["spec"], {
            "podSelector": {"matchLabels": {"app": "bind-authority"}},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{"ipBlock": {"cidr": "${RUBASE_VPN_ADDRESS}/32"}}],
                "ports": [{"port": 5355, "protocol": "UDP"},
                          {"port": 5355, "protocol": "TCP"}],
            }],
        })
        self.assertEqual(self.after[("NetworkPolicy", "bind-authority")],
                         self.before[("NetworkPolicy", "bind-authority")])
        self.assertFalse(any(k[0] == "Secret" for k in self.after))

    def test_component_is_not_activated_by_a_parent(self):
        for folder in (ROOT / "clusters", ROOT / "bootstrap", ROOT / "components"):
            for path in folder.rglob("kustomization.yaml"):
                if path.parent == HERE:
                    continue
                self.assertNotIn("legacy-powerdns-secondary", path.read_text(), str(path))

    def test_private_address_substitutes_to_one_host_cidr(self):
        raw = yaml.safe_dump(self.after[self.policy])
        result = subprocess.check_output(
            ["flux", "envsubst", "--strict"], input=raw, text=True,
            env={"PATH": os.environ["PATH"], "RUBASE_VPN_ADDRESS": "192.0.2.42"},
        )
        expected = copy.deepcopy(self.after[self.policy])
        expected["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"] = "192.0.2.42/32"
        self.assertEqual(yaml.safe_load(result), expected)
        self.assertNotIn("${", result)

    def test_missing_private_address_is_rejected(self):
        result = subprocess.run(
            ["flux", "envsubst", "--strict"],
            input=yaml.safe_dump(self.after[self.policy]), text=True,
            capture_output=True, env={"PATH": os.environ["PATH"]},
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
