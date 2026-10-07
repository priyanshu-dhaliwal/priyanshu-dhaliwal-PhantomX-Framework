"""
plugins/privesc.py — Privilege Escalation Discovery Module

Checks:
  1.  SUID/SGID binaries (GTFOBins cross-reference)
  2.  Sudo misconfigurations (NOPASSWD, ALL, wildcards)
  3.  Writable cron jobs
  4.  Linux capabilities
  5.  Kernel version → CVE suggestions
  6.  Writable /etc/passwd or /etc/shadow
  7.  Docker / LXD group membership
  8.  Weak PATH entries
  9.  NFS no_root_squash
  10. World-writable scripts run by root
"""

import os
import re

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, is_writable, read_file, get_uid, is_root, cmd_exists

# ── GTFOBins SUID quick-reference (abbreviated list) ─────────────────────────
GTFOBINS_SUID = {
    "bash","sh","dash","zsh","python","python2","python3",
    "perl","ruby","node","lua","awk","gawk","nawk","mawk",
    "find","vim","vi","nano","more","less","man","env",
    "cp","mv","tee","dd","cat","head","tail","sort","cut",
    "tar","gzip","zip","unzip","7z","rsync","curl","wget",
    "nmap","tcpdump","openssl","base64","xxd","hexdump",
    "nc","netcat","socat","strace","ltrace","gdb","ftp",
    "php","ruby","pkexec","sudo","su","passwd","chsh","chfn",
    "ping","traceroute","mail","sendmail","crontab","at","batch",
    "docker","lxc","lxd","runc","nsenter",
}

# Kernel CVE suggestions (simplified mapping: version prefix → CVEs)
KERNEL_CVES = {
    "2.6": ["CVE-2016-5195 (DirtyCow)", "CVE-2012-0056 (Mempodipper)"],
    "3.":  ["CVE-2016-5195 (DirtyCow)", "CVE-2015-1328 (overlayfs)"],
    "4.":  ["CVE-2021-4034 (PwnKit)", "CVE-2021-3493 (overlayfs Ubuntu)"],
    "5.":  ["CVE-2021-4034 (PwnKit)", "CVE-2022-0847 (DirtyPipe)"],
}


def run(args, verbose=False):
    results = {}

    _check_suid(results, verbose)
    _check_sudo(results, verbose)
    _check_cron(results, verbose)
    _check_capabilities(results, verbose)
    _check_kernel(results, verbose)
    _check_passwd_shadow(results, verbose)
    _check_group_escape(results, verbose)
    _check_path_hijack(results, verbose)
    _check_nfs(results, verbose)
    _check_writable_root_scripts(results, verbose)

    _print_summary(results)
    return results


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_suid(results, verbose):
    print_status("Scanning SUID/SGID binaries…", "info")
    rc, out = run_cmd("find / -perm -4000 -o -perm -2000 2>/dev/null", timeout=30)
    binaries = [l.strip() for l in out.splitlines() if l.strip()]

    interesting = []
    for b in binaries:
        name = os.path.basename(b).lower()
        if name in GTFOBINS_SUID:
            interesting.append((b, name, "GTFOBins match"))
        elif verbose:
            interesting.append((b, name, ""))

    results["suid_binaries"] = binaries
    results["suid_interesting"] = interesting

    if interesting:
        print_finding(
            "SUID/SGID Binaries — GTFOBins Matches",
            "\n".join(f"  {b[0]}" for b in interesting),
            "high"
        )
        if verbose:
            print_table(["Path", "Binary", "Note"], interesting)
    else:
        print_status(f"Found {len(binaries)} SUID binaries, none match GTFOBins.", "miss")


def _check_sudo(results, verbose):
    print_status("Checking sudo configuration…", "info")
    rc, out = run_cmd("sudo -l 2>/dev/null")

    results["sudo_raw"] = out
    findings = []

    if "(ALL) NOPASSWD: ALL" in out or "(ALL : ALL) NOPASSWD: ALL" in out:
        findings.append(("NOPASSWD ALL", "critical", "Full sudo without password"))
    
    nopasswd = re.findall(r"NOPASSWD:\s*(.+)", out)
    for entry in nopasswd:
        findings.append((entry.strip(), "high", "NOPASSWD command"))

    wildcard = re.findall(r"NOPASSWD:.*\*", out)
    for entry in wildcard:
        findings.append((entry.strip(), "high", "Wildcard in sudo rule"))

    env_keep = "env_keep" in out.lower()
    if env_keep:
        findings.append(("env_keep directive", "medium", "LD_PRELOAD / env hijack possible"))

    results["sudo_findings"] = findings

    if findings:
        for f in findings:
            print_finding(f"Sudo: {f[0]}", f[2], f[1])
    else:
        print_status("No dangerous sudo configurations found.", "miss")


def _check_cron(results, verbose):
    print_status("Auditing cron jobs…", "info")
    cron_paths = [
        "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/",
        "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
        "/var/spool/cron/", "/var/spool/cron/crontabs/"
    ]
    writable = []
    all_scripts = []

    _, user_cron = run_cmd("crontab -l 2>/dev/null")

    for path in cron_paths:
        if os.path.isdir(path):
            rc, ls = run_cmd(f"ls {path} 2>/dev/null")
            for fname in ls.splitlines():
                full = os.path.join(path, fname.strip())
                content = read_file(full) or ""
                for line in content.splitlines():
                    if line.strip() and not line.startswith("#"):
                        # Extract script paths
                        tokens = line.split()
                        for t in tokens:
                            if t.startswith("/") and os.path.isfile(t):
                                all_scripts.append((t, full))
                                if is_writable(t):
                                    writable.append((t, "WRITABLE", "high"))
        else:
            if os.path.isfile(path):
                content = read_file(path) or ""
                for line in content.splitlines():
                    if not line.startswith("#") and line.strip():
                        tokens = line.split()
                        for t in tokens:
                            if t.startswith("/") and os.path.isfile(t):
                                all_scripts.append((t, path))
                                if is_writable(t):
                                    writable.append((t, "WRITABLE", "high"))

    results["cron_writable"] = writable

    if writable:
        print_finding(
            "Writable Cron Script(s) Detected",
            "\n".join(f"  {w[0]}" for w in writable),
            "high"
        )
    else:
        print_status(f"No writable cron scripts found (checked {len(all_scripts)} scripts).", "miss")


def _check_capabilities(results, verbose):
    print_status("Checking Linux capabilities…", "info")
    rc, out = run_cmd("getcap -r / 2>/dev/null", timeout=20)

    dangerous_caps = {"cap_setuid", "cap_setgid", "cap_dac_read_search",
                      "cap_dac_override", "cap_net_raw", "cap_sys_ptrace",
                      "cap_sys_admin"}
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        for cap in dangerous_caps:
            if cap in lower:
                findings.append((line, cap, "dangerous capability"))
                break
        else:
            if verbose:
                findings.append((line, "other", ""))

    results["capabilities"] = findings

    if findings:
        print_finding(
            "Dangerous Linux Capabilities Found",
            "\n".join(f"  {f[0]}" for f in findings if f[1] != "other"),
            "high"
        )
    else:
        print_status("No dangerous capabilities found.", "miss")


def _check_kernel(results, verbose):
    print_status("Checking kernel version for known CVEs…", "info")
    rc, kver = run_cmd("uname -r")
    results["kernel_version"] = kver

    cves = []
    for prefix, cve_list in KERNEL_CVES.items():
        if kver.startswith(prefix):
            cves.extend(cve_list)

    results["kernel_cves"] = cves
    print_status(f"Kernel: {kver}", "info")

    if cves:
        print_finding(
            f"Kernel {kver} — Potential CVEs",
            "\n".join(f"  → {c}" for c in cves),
            "medium"
        )
    else:
        print_status("No matching kernel CVEs in local database.", "miss")


def _check_passwd_shadow(results, verbose):
    print_status("Checking /etc/passwd and /etc/shadow permissions…", "info")
    issues = []

    if is_writable("/etc/passwd"):
        issues.append(("/etc/passwd", "WRITABLE", "critical", "Add root user directly"))
    if is_writable("/etc/shadow"):
        issues.append(("/etc/shadow", "WRITABLE", "critical", "Overwrite root password hash"))
    if os.access("/etc/shadow", os.R_OK):
        issues.append(("/etc/shadow", "READABLE", "high", "Harvest password hashes"))

    results["passwd_shadow"] = issues
    for iss in issues:
        print_finding(f"{iss[0]} is {iss[1]}", iss[3], iss[2])
    if not issues:
        print_status("/etc/passwd and /etc/shadow permissions are secure.", "miss")


def _check_group_escape(results, verbose):
    print_status("Checking group-based escape vectors (docker/lxd/disk/adm)…", "info")
    rc, groups = run_cmd("id")
    dangerous_groups = ["docker", "lxd", "lxc", "disk", "adm", "shadow", "video", "audio", "plugdev"]
    found = [g for g in dangerous_groups if g in groups.lower()]
    results["dangerous_groups"] = found

    if found:
        for g in found:
            tips = {
                "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "lxd":    "lxc init ubuntu:18.04 test -c security.privileged=true && mount host /",
                "disk":   "debugfs /dev/sda  →  read any file on disk",
                "shadow": "read /etc/shadow directly",
                "adm":    "read system logs, may expose credentials",
            }
            print_finding(
                f"Member of '{g}' group",
                tips.get(g, "Research GTFOBins for this group"),
                "critical" if g in ("docker","lxd","disk") else "high"
            )
    else:
        print_status("No dangerous group memberships found.", "miss")


def _check_path_hijack(results, verbose):
    print_status("Checking PATH hijacking vectors…", "info")
    path_dirs = os.environ.get("PATH", "").split(":")
    writable_dirs = [d for d in path_dirs if d and is_writable(d)]
    results["writable_path_dirs"] = writable_dirs

    if writable_dirs:
        print_finding(
            "Writable Directories in PATH",
            "\n".join(f"  {d}" for d in writable_dirs),
            "medium"
        )
    else:
        print_status("No writable directories in PATH.", "miss")


def _check_nfs(results, verbose):
    print_status("Checking NFS exports for no_root_squash…", "info")
    content = read_file("/etc/exports") or ""
    findings = [l for l in content.splitlines() if "no_root_squash" in l.lower()]
    results["nfs_no_root_squash"] = findings

    if findings:
        print_finding(
            "NFS Export with no_root_squash",
            "\n".join(f"  {l}" for l in findings),
            "high"
        )
    else:
        print_status("No NFS no_root_squash exports found.", "miss")


def _check_writable_root_scripts(results, verbose):
    print_status("Checking for world-writable scripts run by root processes…", "info")
    rc, root_procs = run_cmd(
        "ps aux 2>/dev/null | awk '$1==\"root\" {print $NF}' | grep '^/' | sort -u",
        timeout=10
    )
    writable = []
    for path in root_procs.splitlines():
        path = path.strip()
        if os.path.isfile(path) and is_writable(path):
            writable.append(path)

    results["writable_root_scripts"] = writable

    if writable:
        print_finding(
            "World-Writable Script(s) Running as Root",
            "\n".join(f"  {p}" for p in writable),
            "critical"
        )
    else:
        print_status("No world-writable root-executed scripts found.", "miss")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(results):
    total_high = (
        len(results.get("suid_interesting", [])) +
        len(results.get("sudo_findings", [])) +
        len(results.get("cron_writable", [])) +
        len(results.get("capabilities", [])) +
        len(results.get("passwd_shadow", [])) +
        len(results.get("dangerous_groups", [])) +
        len(results.get("writable_path_dirs", [])) +
        len(results.get("nfs_no_root_squash", [])) +
        len(results.get("writable_root_scripts", []))
    )
    print_status(
        f"PrivEsc scan complete — {total_high} potential vector(s) identified.",
        "success" if total_high else "info"
    )
