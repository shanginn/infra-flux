"""Render and isolation guards for the static-site workload owner."""
import pathlib
import subprocess
import unittest

import yaml


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
IMAGE = "ghcr.io/shanginn/itaisolutions.ru@sha256:c87b669a9eb1e1d291fd5f7993a581068e4c17952a091703dd8969ad88946c4f"


class StaticSiteConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rendered = subprocess.run(
            ["kubectl", "kustomize", str(HERE)], check=True,
            capture_output=True, text=True, timeout=15,
        ).stdout
        cls.objects = list(yaml.safe_load_all(rendered))
        cls.deployments = [x for x in cls.objects if x["kind"] == "Deployment"]

    def test_base_contains_workload_and_route_without_credentials(self):
        self.assertCountEqual([x["kind"] for x in self.objects], [
            "Namespace", "ServiceAccount", "Service", "Deployment",
            "Deployment", "NetworkPolicy", "Middleware", "Ingress", "Ingress",
        ])
        for obj in self.objects:
            self.assertNotIn(obj["kind"], {"Secret", "Certificate"})

    def test_both_sites_use_same_pinned_stateless_image(self):
        self.assertEqual(len(self.deployments), 2)
        self.assertEqual({x["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"] for x in self.deployments}, {"home", "fin"})
        for obj in self.deployments:
            self.assertEqual(obj["spec"]["replicas"], 1)
            pod = obj["spec"]["template"]["spec"]
            self.assertIs(pod["automountServiceAccountToken"], False)
            self.assertEqual(pod["imagePullSecrets"], [{"name": "dockerconfigjson-github-com"}])
            self.assertNotIn("volumes", pod)
            self.assertEqual(len(pod["containers"]), 1)
            container = pod["containers"][0]
            self.assertEqual(container["image"], IMAGE)
            self.assertNotIn("env", container)
            self.assertNotIn("envFrom", container)
            self.assertEqual(container["resources"]["requests"]["memory"], "32Mi")
            self.assertEqual(container["resources"]["limits"]["memory"], "128Mi")
            for key in ("livenessProbe", "readinessProbe"):
                self.assertEqual(container[key]["httpGet"], {"path": "/", "port": "http", "scheme": "HTTP"})

    def test_deployment_selectors_disjoint_and_service_selects_both(self):
        service = next(x for x in self.objects if x["kind"] == "Service")
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"], [{"name": "http", "port": 80, "targetPort": "http", "protocol": "TCP"}])
        selectors = [x["spec"]["selector"]["matchLabels"] for x in self.deployments]
        self.assertNotEqual(selectors[0], selectors[1])
        for obj, selector in zip(self.deployments, selectors):
            labels = obj["spec"]["template"]["metadata"]["labels"]
            self.assertEqual(selector, labels)
            self.assertTrue(all(labels.get(k) == v for k, v in service["spec"]["selector"].items()))

    def test_ingress_is_only_traefik_on_application_port(self):
        policy = next(x for x in self.objects if x["kind"] == "NetworkPolicy")["spec"]
        self.assertEqual(policy["policyTypes"], ["Ingress"])
        self.assertEqual(policy["ingress"], [{"from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}},
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}},
        }], "ports": [{"protocol": "TCP", "port": 80}]}])
        for obj in self.deployments:
            self.assertTrue(all(obj["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in policy["podSelector"]["matchLabels"].items()))

    def test_owner_is_scoped_and_renewal_excluded_until_dns_cutover(self):
        base = yaml.safe_load((HERE / "kustomization.yaml").read_text())
        self.assertEqual(base["resources"], ["workload.yaml", "network-policy.yaml", "public-route.yaml"])
        parent = yaml.safe_load((HERE.parent / "kustomization.yaml").read_text())
        self.assertEqual(parent["resources"], ["flux.yaml"])
        owner = yaml.safe_load((HERE.parent / "flux.yaml").read_text())
        self.assertEqual(owner["metadata"], {"name": "applications-itaisolutions", "namespace": "flux-system"})
        self.assertIs(owner["spec"].get("suspend", False), False)
        self.assertEqual(owner["spec"]["path"], "./clusters/unified/applications/itaisolutions")
        self.assertEqual(owner["spec"]["sourceRef"], {"kind": "GitRepository", "name": "infra-flux"})
        unified = yaml.safe_load((ROOT / "clusters/unified/kustomization.yaml").read_text())
        self.assertEqual(unified.get("resources", []).count("applications"), 1)
        self.assertNotIn("applications/itaisolutions", unified.get("resources", []))

    def test_optional_route_preserves_host_path_and_tls_identity(self):
        objects = list(yaml.safe_load_all((HERE / "public-route.yaml").read_text()))
        for obj in objects:
            if obj["kind"] != "Ingress":
                continue
            self.assertEqual(obj["spec"]["ingressClassName"], "traefik")
            self.assertEqual(obj["spec"]["rules"], [{"host": "itaisolutions.ru", "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "itaisolutions-static-app", "port": {"name": "http"}}}}]}}])
        certificate = yaml.safe_load((HERE / "certificate.yaml").read_text())
        self.assertEqual(certificate["spec"]["dnsNames"], ["itaisolutions.ru"])
        self.assertEqual(certificate["spec"]["issuerRef"]["name"], "letsencrypt-production")


if __name__ == "__main__":
    unittest.main()
