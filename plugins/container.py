"""
plugins/container.py — Container & Cloud Escape Detection Module

Checks:
  1.  Docker container detection (cgroup, .dockerenv)
  2.  Docker socket exposure (RCE)
  3.  Privileged container check
  4.  Kubernetes pod detection & service account token
  5.  LXC/LXD container detection
  6.  Cloud metadata API (AWS/GCP/Azure/DO) — credential theft
  7.  Mounted sensitive host paths
  8.  Writable hostfs paths
  9.  Namespace analysis (PID/net/user ns)
  10. Container capabilities audit
"""

import os
import re
import socket

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, file_exists, is_readable, is_writable

# Cloud metadata endpoints
METADATA_ENDPOINTS = {
    "AWS":        ("169.254.169.254", 80,  "/latest/meta-data/iam/security-credentials/"),
    "GCP":        ("169.254.169.254", 80,  "/computeMetadata/v1/instance/service-accounts/"),
    "Azure":      ("169.254.169.254", 80,  "/metadata/instance?api-version=2021-02-01"),
    "DigitalOcean":("169.254.169.254",80,  "/metadata/v1/"),
    "Oracle":     ("169.254.169.254", 80,  "/opc/v1/instance/"),
}


def run(args, verbose=False):
    results = {}

    in_container = _detect_container(results, verbose)
    _docker_socket(results, verbose)
    _privileged_check(results, verbose)
    _kubernetes_check(results, verbose)
    _cloud_metadata(results, verbose)
    _mounted_host_paths(results, verbose)
    _namespace_analysis(results, verbose)
    _container_capabilities(results, verbose)

    return results


# ── Checks ────────────────────────────────────────────────────────────────────

def _detect_container(results, verbose):
    print_status("Detecting container / virtualisation environment…", "info")
    indicators = []

    # .dockerenv
    if file_exists("/.dockerenv"):
        indicators.append(("Docker", "/.dockerenv present"))

    # cgroup v1
    cgroup = read_file("/proc/1/cgroup") or ""
    if "docker" in cgroup:
        m = re.search(r'docker/([a-f0-9]{12,})', cgroup)
        cid = m.group(1)[:12] if m else "unknown"
        indicators.append(("Docker", f"cgroup entry (container ID: {cid})"))
    if "lxc" in cgroup:
        indicators.append(("LXC/LXD", "cgroup entry"))
    if "kubepods" in cgroup:
        indicators.append(("Kubernetes", "kubepods cgroup entry"))

    # /proc/1/environ check for container runtime
    environ = read_file("/proc/1/environ") or ""
    if "container=lxc" in environ:
        indicators.append(("LXC", "container=lxc in PID 1 environ"))
    if "KUBERNETES_SERVICE" in environ:
        indicators.append(("Kubernetes", "KUBERNETES_SERVICE in environ"))

    # systemd-detect-virt
    _, virt = run_cmd("systemd-detect-virt 2>/dev/null")
    if virt.strip() not in ("none", ""):
        indicators.append(("Virtualisation", virt.strip()))

    results["container_indicators"] = indicators
    in_container = bool(indicators)

    if indicators:
        print_finding(
            f"Container/VM Environment Detected ({len(indicators)} indicator(s))",
            "\n".join(f"  [{i[0]}] {i[1]}" for i in indicators),
            "info"
        )
    else:
        print_status("No container indicators found (bare-metal or undetected VM).", "miss")

    return in_container


def _docker_socket(results, verbose):
    print_status("Checking for exposed Docker socket…", "info")
    docker_sockets = ["/var/run/docker.sock", "/run/docker.sock"]
    exposed = []

    for sock in docker_sockets:
        if os.path.exists(sock):
            readable = os.access(sock, os.R_OK)
            writable = os.access(sock, os.W_OK)
            exposed.append((sock, readable, writable))

    results["docker_socket"] = exposed

    if exposed:
        for sock, r, w in exposed:
            if w:
                print_finding(
                    f"Docker Socket WRITABLE: {sock}",
                    "Full container escape possible:\n"
                    "  docker -H unix://" + sock + " run -v /:/host --rm -it alpine chroot /host sh",
                    "critical"
                )
            elif r:
                print_finding(
                    f"Docker Socket readable: {sock}",
                    "Can enumerate containers and potentially escalate.",
                    "high"
                )
    else:
        print_status("No Docker socket found.", "miss")


def _privileged_check(results, verbose):
    print_status("Checking for privileged container flags…", "info")
    issues = []

    # Check capabilities — privileged containers have all caps
    _, caps = run_cmd("cat /proc/self/status 2>/dev/null | grep CapEff")
    if caps:
        m = re.search(r'CapEff:\s+([0-9a-f]+)', caps)
        if m:
            cap_val = int(m.group(1), 16)
            # 0x3fffffffff = full capabilities
            if cap_val >= 0x3fffffffff:
                issues.append(("CapEff", hex(cap_val), "ALL capabilities — running PRIVILEGED"))
            else:
                # Check for dangerous specific caps
                dangerous_caps = {
                    0: "CAP_CHOWN",
                    1: "CAP_DAC_OVERRIDE",
                    2: "CAP_DAC_READ_SEARCH",
                    6: "CAP_SETUID",
                    7: "CAP_SETGID",
                    12: "CAP_NET_ADMIN",
                    21: "CAP_SYS_ADMIN",
                    25: "CAP_SYS_PTRACE",
                }
                has_dangerous = [name for bit, name in dangerous_caps.items()
                                 if cap_val & (1 << bit)]
                if has_dangerous:
                    issues.append(("Capabilities", ", ".join(has_dangerous), "Dangerous caps present"))

    # Check if /proc/sysrq-trigger is writable (privileged)
    if os.access("/proc/sysrq-trigger", os.W_OK):
        issues.append(("sysrq-trigger", "writable", "Privileged — can crash/reboot host"))

    # Mounted host devices
    _, mounts = run_cmd("cat /proc/mounts 2>/dev/null")
    host_devs = [l for l in mounts.splitlines() if re.match(r'/dev/[sv]d[a-z]', l.split()[0] if l.split() else "")]
    if host_devs:
        issues.append(("Host Block Devices", str(len(host_devs)) + " mounted",
                       "May be able to access host filesystem via debugfs"))

    results["privileged"] = issues

    if issues:
        sev = "critical" if any("PRIVILEGED" in str(i) or "sysrq" in str(i) for i in issues) else "high"
        print_finding(
            f"Privileged Container Indicators ({len(issues)})",
            "\n".join(f"  {i[0]}: {i[1]}" for i in issues),
            sev
        )
    else:
        print_status("Container does not appear to be privileged.", "miss")


def _kubernetes_check(results, verbose):
    print_status("Checking Kubernetes service account & API access…", "info")
    k8s_token_path  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    k8s_ca_path     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    k8s_ns_path     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    findings = []

    if file_exists(k8s_token_path) and is_readable(k8s_token_path):
        token    = (read_file(k8s_token_path) or "")[:60] + "…"
        ns       = (read_file(k8s_ns_path) or "unknown").strip()
        findings.append(("Service Account Token", f"Namespace: {ns} | Token: {token}"))

        # Try to reach the k8s API
        api_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if api_host:
            rc, api_resp = run_cmd(
                f"curl -sk -m5 --cacert {k8s_ca_path} "
                f"-H 'Authorization: Bearer $(cat {k8s_token_path})' "
                f"https://{api_host}:{api_port}/api/v1/namespaces/{ns}/pods 2>/dev/null | head -5",
                timeout=8
            )
            if '"kind"' in api_resp or '"items"' in api_resp:
                findings.append(("K8s API Access", f"Pod list readable in namespace {ns}"))

    env_k8s = {k: v for k, v in os.environ.items() if "KUBERNETES" in k or "K8S" in k}
    if env_k8s:
        for k, v in env_k8s.items():
            findings.append((f"Env: {k}", v[:80]))

    results["kubernetes"] = findings

    if findings:
        print_finding(
            f"Kubernetes Environment ({len(findings)} finding(s))",
            "\n".join(f"  [{f[0]}] {f[1]}" for f in findings),
            "high"
        )
    else:
        print_status("No Kubernetes service account artifacts found.", "miss")


def _cloud_metadata(results, verbose):
    print_status("Probing cloud instance metadata APIs…", "info")
    found = []

    for provider, (host, port, path) in METADATA_ENDPOINTS.items():
        try:
            s = socket.socket()
            s.settimeout(1.5)
            rc = s.connect_ex((host, port))
            s.close()
            if rc != 0:
                continue
        except Exception:
            continue

        # Reachable — grab data
        headers = ""
        if provider == "GCP":
            headers = '-H "Metadata-Flavor: Google"'
        elif provider == "Azure":
            headers = '-H "Metadata: true"'

        rc2, resp = run_cmd(
            f"curl -sf -m3 {headers} http://{host}{path} 2>/dev/null | head -20",
            timeout=6
        )
        if resp.strip():
            found.append((provider, host + path, resp.strip()[:200]))

    results["cloud_metadata"] = found

    if found:
        for f in found:
            print_finding(
                f"Cloud Metadata API Accessible: {f[0]}",
                f"  Endpoint: http://{f[1]}\n  Response: {f[2]}",
                "critical"
            )
    else:
        print_status("No cloud metadata APIs reachable.", "miss")


def _mounted_host_paths(results, verbose):
    print_status("Checking for sensitive host paths mounted into container…", "info")
    _, mounts = run_cmd("cat /proc/mounts 2>/dev/null || mount 2>/dev/null")
    sensitive = []

    sensitive_paths = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/root", "/home", "/var/run/docker.sock",
        "/proc", "/sys", "/dev", "/boot",
    ]

    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mountpoint = parts[1]
        for sp in sensitive_paths:
            if mountpoint == sp or mountpoint.startswith(sp + "/"):
                writable = "rw" in (parts[3] if len(parts) > 3 else "")
                sensitive.append((mountpoint, "rw" if writable else "ro",
                                  "WRITABLE — escape risk" if writable else "read-only"))
                break

    results["host_mounts"] = sensitive

    if sensitive:
        print_finding(
            f"Sensitive Host Paths Mounted ({len(sensitive)})",
            "\n".join(f"  {m[0]} [{m[1]}] {m[2]}" for m in sensitive),
            "critical" if any(m[1] == "rw" for m in sensitive) else "high"
        )
    else:
        print_status("No obviously sensitive host paths mounted.", "miss")


def _namespace_analysis(results, verbose):
    print_status("Analysing Linux namespaces…", "info")
    _, ns_out = run_cmd("ls -la /proc/self/ns/ 2>/dev/null")
    ns_links = {}

    # Check if we share namespaces with PID 1 (host ns indicator)
    for ns_type in ["pid", "net", "mnt", "uts", "ipc", "user"]:
        _, self_ns  = run_cmd(f"readlink /proc/self/ns/{ns_type} 2>/dev/null")
        _, init_ns  = run_cmd(f"readlink /proc/1/ns/{ns_type} 2>/dev/null")
        shared = (self_ns.strip() == init_ns.strip() and self_ns.strip())
        ns_links[ns_type] = {"self": self_ns.strip(), "shared_with_host": shared}

    results["namespaces"] = ns_links
    shared = [k for k, v in ns_links.items() if v["shared_with_host"]]

    if shared:
        print_finding(
            f"Shared Namespaces with Host: {', '.join(shared)}",
            "Sharing namespaces with PID 1 suggests partial or full host access.",
            "high" if len(shared) > 2 else "medium"
        )
    else:
        print_status("Namespaces appear isolated from host.", "miss")


def _container_capabilities(results, verbose):
    print_status("Auditing effective container capabilities…", "info")
    _, cap_out = run_cmd("capsh --print 2>/dev/null || cat /proc/self/status | grep Cap")
    results["capabilities_raw"] = cap_out

    if verbose:
        print(f"{C.DIM}{cap_out[:500]}{C.RESET}")
    else:
        print_status("Capabilities enumerated (use --verbose to display).", "miss")
