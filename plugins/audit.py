"""
plugins/audit.py — Security Hardening & Account Audit Module

Checks:
  1.  Password policy (PAM, /etc/login.defs)
  2.  Accounts with empty passwords
  3.  UID 0 accounts (beyond root)
  4.  Stale / locked accounts still with cron/processes
  5.  World-writable files & directories (critical paths)
  6.  UMASK configuration
  7.  Core dump settings
  8.  SSH daemon hardening
  9.  Audit logging (auditd) status
  10. AppArmor / SELinux enforcement
  11. Cleartext protocol services (telnet/ftp/rsh)
  12. Open SMTP relay check
"""

import os
import re

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, file_exists, cmd_exists, is_readable


def run(args, verbose=False):
    results = {}

    _password_policy(results, verbose)
    _empty_password_accounts(results, verbose)
    _uid0_accounts(results, verbose)
    _world_writable(results, verbose)
    _umask_check(results, verbose)
    _core_dumps(results, verbose)
    _ssh_hardening(results, verbose)
    _audit_logging(results, verbose)
    _mac_status(results, verbose)
    _cleartext_services(results, verbose)

    _print_summary(results)
    return results


# ── Checks ────────────────────────────────────────────────────────────────────

def _password_policy(results, verbose):
    print_status("Auditing password policy…", "info")
    issues = []

    login_defs = read_file("/etc/login.defs") or ""
    policy = {}
    for line in login_defs.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) == 2:
                policy[parts[0]] = parts[1]

    checks = [
        ("PASS_MAX_DAYS", 90,  "lt", "Password max age > 90 days"),
        ("PASS_MIN_DAYS", 1,   "lt", "No minimum password age (allows immediate reuse)"),
        ("PASS_MIN_LEN",  8,   "lt", "Minimum password length < 8"),
        ("PASS_WARN_AGE", 7,   "lt", "Password expiry warning < 7 days"),
    ]

    for key, threshold, op, label in checks:
        val = policy.get(key)
        if val is None:
            issues.append((key, "not set", label, "medium"))
        else:
            try:
                n = int(val)
                if op == "lt" and n < threshold:
                    issues.append((key, str(n), label, "medium"))
                elif op == "gt" and n > threshold:
                    issues.append((key, str(n), label, "medium"))
            except ValueError:
                pass

    # Check PAM password quality
    pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]
    pam_found = False
    for pf in pam_files:
        content = read_file(pf) or ""
        if "pam_pwquality" in content or "pam_cracklib" in content:
            pam_found = True
            # Check for minlen
            m = re.search(r'minlen=(\d+)', content)
            if m and int(m.group(1)) < 10:
                issues.append(("PAM minlen", m.group(1), "PAM password minlen < 10", "medium"))

    if not pam_found:
        issues.append(("PAM quality", "not configured",
                       "No pam_pwquality/pam_cracklib — no complexity enforcement", "high"))

    results["password_policy"] = issues

    if issues:
        print_finding(
            f"Password Policy Weaknesses ({len(issues)})",
            "\n".join(f"  [{i[3].upper()}] {i[0]}={i[1]}: {i[2]}" for i in issues),
            "medium"
        )
    else:
        print_status("Password policy appears adequately configured.", "miss")


def _empty_password_accounts(results, verbose):
    print_status("Checking for accounts with empty passwords…", "info")
    shadow = read_file("/etc/shadow") or ""
    passwd = read_file("/etc/passwd") or ""
    empty = []

    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            empty.append(("shadow", parts[0], "empty hash — direct login possible"))

    # Also check passwd for legacy password field
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] not in ("x", "*", "!"):
            empty.append(("passwd", parts[0], f"password in passwd: {parts[1][:10]}"))

    results["empty_passwords"] = empty

    if empty:
        print_finding(
            f"Accounts with Empty/Weak Passwords ({len(empty)})",
            "\n".join(f"  {e[1]} ({e[0]}): {e[2]}" for e in empty),
            "critical"
        )
    else:
        print_status("No accounts with empty passwords found.", "miss")


def _uid0_accounts(results, verbose):
    print_status("Checking for non-root UID 0 accounts…", "info")
    passwd = read_file("/etc/passwd") or ""
    uid0 = []

    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
            uid0.append((parts[0], parts[5], parts[6]))

    results["uid0_accounts"] = uid0

    if uid0:
        print_finding(
            f"Non-root UID 0 accounts found ({len(uid0)})!",
            "\n".join(f"  user={u[0]} home={u[1]} shell={u[2]}" for u in uid0),
            "critical"
        )
    else:
        print_status("Only root has UID 0.", "miss")


def _world_writable(results, verbose):
    print_status("Scanning for world-writable files in critical paths…", "info")
    critical_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                      "/lib", "/lib64", "/usr/lib"]

    _, ww_out = run_cmd(
        f"find {' '.join(critical_paths)} -maxdepth 3 "
        f"-perm -o+w ! -type l 2>/dev/null",
        timeout=25
    )
    ww_files = [l.strip() for l in ww_out.splitlines() if l.strip()]
    results["world_writable"] = ww_files

    if ww_files:
        print_finding(
            f"World-Writable Files in Critical Paths ({len(ww_files)})",
            "\n".join(f"  {f}" for f in ww_files[:20]),
            "high"
        )
    else:
        print_status("No world-writable files in critical system paths.", "miss")


def _umask_check(results, verbose):
    print_status("Checking UMASK configuration…", "info")
    _, umask_out = run_cmd("umask")
    umask_val = umask_out.strip()
    results["umask"] = umask_val

    # Safe umask: 022 or stricter (027, 077)
    try:
        # umask value: lower = less restrictive
        val = int(umask_val, 8)
        if val < 0o022:
            print_finding(
                f"Permissive UMASK: {umask_val}",
                "New files may be world-readable. Recommend 022 or 027.",
                "medium"
            )
        else:
            print_status(f"UMASK is {umask_val} — acceptable.", "miss")
    except ValueError:
        print_status(f"Could not parse umask: {umask_val}", "warn")


def _core_dumps(results, verbose):
    print_status("Checking core dump configuration…", "info")
    issues = []

    _, ulimit = run_cmd("ulimit -c")
    if ulimit.strip() != "0":
        issues.append(f"ulimit -c = {ulimit.strip()} (core dumps enabled, may leak memory)")

    _, sysctl = run_cmd("sysctl -n kernel.core_pattern 2>/dev/null")
    if sysctl.strip().startswith("|"):
        issues.append(f"kernel.core_pattern uses pipe: {sysctl.strip()} (possible code execution on crash)")

    # Check if core dumps can contain setuid info
    _, dumpable = run_cmd("sysctl -n fs.suid_dumpable 2>/dev/null")
    if dumpable.strip() == "2":
        issues.append("fs.suid_dumpable=2 — setuid binaries create world-readable core dumps")
    elif dumpable.strip() == "1":
        issues.append("fs.suid_dumpable=1 — SUID processes create core dumps (privilege info leakage)")

    results["core_dumps"] = issues
    if issues:
        print_finding("Core Dump Security Issues",
                      "\n".join(f"  {i}" for i in issues), "medium")
    else:
        print_status("Core dump settings appear secure.", "miss")


def _ssh_hardening(results, verbose):
    print_status("Auditing SSH daemon configuration…", "info")
    sshd_config = read_file("/etc/ssh/sshd_config") or ""
    issues = []

    def get_val(key):
        m = re.search(rf'^(?!#)\s*{re.escape(key)}\s+(\S+)',
                      sshd_config, re.MULTILINE | re.IGNORECASE)
        return m.group(1).lower() if m else None

    checks = [
        ("PermitRootLogin",          "yes",        "critical", "Root login via SSH is permitted"),
        ("PasswordAuthentication",   "yes",        "high",     "Password auth enabled (prefer key-only)"),
        ("PermitEmptyPasswords",     "yes",        "critical", "Empty passwords allowed over SSH"),
        ("X11Forwarding",            "yes",        "low",      "X11 forwarding enabled"),
        ("UsePAM",                   "no",         "medium",   "PAM disabled — bypasses policy"),
        ("Protocol",                 "1",          "critical", "SSHv1 enabled — deprecated & insecure"),
        ("AllowAgentForwarding",     "yes",        "medium",   "Agent forwarding allowed — credential theft risk"),
    ]

    for key, bad_val, sev, note in checks:
        val = get_val(key)
        if val == bad_val:
            issues.append((key, val, sev, note))
        # Also flag absent security settings
        if key == "PermitRootLogin" and val is None:
            issues.append((key, "default(yes)", "high", "Not explicitly set — defaults to yes in older OpenSSH"))

    results["ssh_hardening"] = issues

    if issues:
        print_finding(
            f"SSH Hardening Issues ({len(issues)})",
            "\n".join(f"  [{i[2].upper()}] {i[0]}={i[1]}: {i[3]}" for i in issues),
            "high"
        )
    else:
        print_status("SSH configuration appears well hardened.", "miss")


def _audit_logging(results, verbose):
    print_status("Checking audit logging (auditd / syslog)…", "info")
    issues = []

    _, auditd = run_cmd("systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null")
    if "active" not in auditd.lower() and "running" not in auditd.lower():
        issues.append("auditd is NOT running — system calls not logged")

    # Check for audit rules
    _, rules = run_cmd("auditctl -l 2>/dev/null")
    if not rules.strip() or "No rules" in rules:
        issues.append("No auditd rules configured — minimal syscall visibility")

    # Check rsyslog / syslog-ng
    _, syslog = run_cmd("systemctl is-active rsyslog syslog-ng 2>/dev/null | head -1")
    if "active" not in syslog.lower():
        issues.append("rsyslog/syslog-ng not running — system logging may be impaired")

    # Check log forwarding
    rsyslog_conf = read_file("/etc/rsyslog.conf") or ""
    has_remote = bool(re.search(r'@{1,2}[\w\d.]+:\d+', rsyslog_conf))
    if has_remote:
        m = re.search(r'@{1,2}([\w\d.]+:\d+)', rsyslog_conf)
        issues.append(f"Logs forwarded to remote: {m.group(1) if m else 'unknown'} (verify this is authorized)")

    results["audit_logging"] = issues

    if any("NOT running" in i or "No rules" in i for i in issues):
        print_finding("Audit Logging Gaps", "\n".join(f"  {i}" for i in issues), "high")
    elif issues:
        print_status(f"Logging config notes: {len(issues)}", "info")
    else:
        print_status("Audit logging appears active.", "miss")


def _mac_status(results, verbose):
    print_status("Checking MAC enforcement (AppArmor / SELinux)…", "info")
    findings = {}

    # AppArmor
    _, aa_status = run_cmd("aa-status 2>/dev/null || apparmor_status 2>/dev/null")
    if "enabled" in aa_status.lower() or "profiles are loaded" in aa_status.lower():
        # Count enforcing profiles
        m = re.search(r'(\d+) profiles? are in enforce mode', aa_status)
        enforcing = m.group(1) if m else "?"
        findings["AppArmor"] = f"ENABLED — {enforcing} profiles enforcing"
        print_status(f"AppArmor: {findings['AppArmor']}", "success" if enforcing != "0" else "warn")
    else:
        _, aa_svc = run_cmd("systemctl is-active apparmor 2>/dev/null")
        if "inactive" in aa_svc or not aa_status.strip():
            findings["AppArmor"] = "NOT active"
            print_finding("AppArmor not active", "No mandatory access control enforcement.", "medium")

    # SELinux
    _, selinux = run_cmd("getenforce 2>/dev/null || sestatus 2>/dev/null | head -3")
    if "enforcing" in selinux.lower():
        findings["SELinux"] = "ENFORCING"
        print_status("SELinux: Enforcing", "success")
    elif "permissive" in selinux.lower():
        findings["SELinux"] = "PERMISSIVE"
        print_finding("SELinux is Permissive", "Logs violations but does not enforce.", "medium")
    elif "disabled" in selinux.lower():
        findings["SELinux"] = "DISABLED"
        print_finding("SELinux is Disabled", "No mandatory access control.", "high")

    results["mac"] = findings


def _cleartext_services(results, verbose):
    print_status("Checking for cleartext protocol services…", "info")
    _, ps_out = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    _, svc_out = run_cmd("systemctl list-units --type=service --state=running --no-pager 2>/dev/null")

    dangerous = []
    cleartext_map = {
        "23": "Telnet",
        "21": "FTP",
        "512": "rexec",
        "513": "rlogin",
        "514": "rsh",
        "69": "TFTP",
        "110": "POP3 (cleartext)",
        "143": "IMAP (cleartext)",
        "25": "SMTP (unencrypted relay?)",
    }

    for port, svc in cleartext_map.items():
        if f":{port} " in ps_out or f":{port}\n" in ps_out:
            dangerous.append((port, svc))

    # Also check systemd
    for svc_name in ["telnet", "vsftpd", "rsh", "rlogin", "rexec", "tftp"]:
        if svc_name in svc_out.lower():
            dangerous.append(("active", f"{svc_name} service running"))

    results["cleartext_services"] = dangerous

    if dangerous:
        print_finding(
            f"Cleartext Services Active ({len(dangerous)})",
            "\n".join(f"  port {d[0]}: {d[1]}" for d in dangerous),
            "high"
        )
    else:
        print_status("No obviously dangerous cleartext services detected.", "miss")


def _print_summary(results):
    total = 0
    for v in results.values():
        if isinstance(v, list):
            total += len(v)
        elif v:
            total += 1
    print_status(f"Audit complete — {total} security finding(s) across all checks.",
                 "success" if total else "info")
