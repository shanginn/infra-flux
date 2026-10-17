#!/usr/bin/env python3
"""Check phase1 components without collecting addresses or unrelated services."""
import json
import subprocess
import sys


PACKAGES = ("containerd.io", "cri-tools", "kubeadm", "kubelet", "kubectl", "tailscale")


def run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def read_json(argv):
    code, output = run(argv)
    try:
        data = json.loads(output)
        return code, data if isinstance(data, dict) else {}
    except ValueError:
        return code, {}


def main():
    package_code, package_output = run([
        "dpkg-query", "-W", "-f=${Package} ${Version}\n", *PACKAGES,
    ])
    versions = dict(line.split(maxsplit=1) for line in package_output.splitlines()
                    if len(line.split()) == 2)
    hold_code, hold_output = run(["apt-mark", "showhold"])
    held = sorted(set(hold_output.splitlines()).intersection(PACKAGES))
    cri_code, cri = read_json([
        "crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock", "info",
    ])
    runtime_ready = any(
        item.get("type") == "RuntimeReady" and item.get("status") is True
        for item in cri.get("status", {}).get("conditions", [])
    )
    systemd_cgroup = (cri.get("config", {}).get("containerd", {})
                     .get("runtimes", {}).get("runc", {}).get("options", {})
                     .get("SystemdCgroup"))
    tailscale_code, tailscale = read_json(["tailscale", "status", "--json"])
    backend_state = tailscale.get("BackendState")
    services = {}
    for service in ("containerd", "tailscaled", "kubelet"):
        code, output = run([
            "systemctl", "show", service, "-p", "LoadState",
            "-p", "ActiveState", "-p", "UnitFileState",
        ])
        services[service] = {"exit_code": code, **dict(
            line.split("=", 1) for line in output.splitlines() if "=" in line
        )}
    ready = (
        package_code == 0 and set(versions) == set(PACKAGES)
        and hold_code == 0 and set(held) == set(PACKAGES)
        and cri_code == 0 and runtime_ready and systemd_cgroup is True
        and tailscale_code == 0 and backend_state in ("NeedsLogin", "NoState")
        and all(services[name].get("exit_code") == 0
                and services[name].get("LoadState") == "loaded"
                for name in services)
        and all(services[name].get("ActiveState") == "active"
                and services[name].get("UnitFileState") == "enabled"
                for name in ("containerd", "tailscaled"))
        and services["kubelet"].get("ActiveState") == "inactive"
        and services["kubelet"].get("UnitFileState") == "disabled"
    )
    print(json.dumps({
        "ready": ready,
        "packages": {"exit_code": package_code, "versions": versions},
        "held_packages": {"exit_code": hold_code, "names": held},
        "cri": {"exit_code": cri_code, "runtime_ready": runtime_ready,
                "systemd_cgroup": systemd_cgroup},
        "tailscale": {"exit_code": tailscale_code, "backend_state": backend_state},
        "services": services,
    }, indent=2))
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
