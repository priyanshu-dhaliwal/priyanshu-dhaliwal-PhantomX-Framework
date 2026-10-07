"""
plugins/persistence.py — Persistence Mechanism Analysis Module

Checks (read-only audit):
  1. User & system crontab entries
  2. Shell profile injections (.bashrc, .profile, .bash_profile, .zshrc)
  3. SSH authorized_keys audit
  4. Suspicious systemd user/system units
  5. MOTD / update-motd.d hooks
  6. rc.local
  7. /etc/profile.d scripts
  8. At jobs
  9. XDG autostart entries
  10. LD_PRELOAD / /etc/ld.so.preload
"""

import os
import re
from pathlib import Path

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, is_writable, file_exists


SHELL_PROFILES = [
    "~/.bashrc", "~/.bash_profile", "~/.profile",
    "~/.zshrc", "~/.zprofile", "~/.bash_logout",
    "/etc/bash.bashrc", "/etc/profile",
]

SUSPICIOUS_PATTERNS = [
    (r'bash\s+-i\s+>&\s*/dev/tcp', "Reverse shell one-liner"),
    (r'nc\s+-e\s+/bin',            "Netcat shell"),
    (r'python.*socket.*connect',   "Python socket reverse shell"),
    (r'curl\s+.*\|\s*(ba)?sh',     "Curl pipe to shell"),
    (r'wget\s+.*-O-\s*\|',         "Wget pipe to shell"),
    (r'base64\s+-d\s*\|',          "Base64-decoded execution"),
    (r'eval\s+\$\(',               "eval subshell (obfuscation)"),
    (r'/tmp/[a-zA-Z0-9_\-]+\s',    "Execution from /tmp"),
    (r'nohup\s+',                  "nohup background process"),
    (r'crontab\s+-l\s*\|',         "Crontab manipulation"),
]


def run(args, verbose=False):
    results = {}

    _check_crontabs(results, verbose)
    _check_shell_profiles(results, verbose)
    _check_ssh_keys(results, verbose)
    _check_systemd_units(results, verbose)
    _check_motd(results, verbose)
    _check_rc_local(results, verbose)
    _check_profile_d(results, verbose)
    _check_at_jobs(results, verbose)
    _check_xdg_autostart(results, verbose)
    _check_ld_preload(results, verbose)

    return results


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_crontabs(results, verbose):
    print_status("Auditing crontab entries…", "info")
    _, user_cron = run_cmd("crontab -l 2>/dev/null")
    _, root_cron = run_cmd("sudo crontab -l 2>/dev/null")
    _, sys_cron  = run_cmd("cat /etc/crontab 2>/dev/null")

    all_entries = []
    for src, content in [("user", user_cron), ("root", root_cron), ("system", sys_cron)]:
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                suspicious = _detect_suspicious(line)
                all_entries.append((src, line[:100], suspicious or ""))

    results["crontab_entries"] = all_entries
    sus = [e for e in all_entries if e[2]]

    if sus:
        print_finding(
            f"Suspicious Crontab Entries ({len(sus)})",
            "\n".join(f"  [{e[0]}] {e[1]}" for e in sus),
            "high"
        )
    else:
        print_status(f"Crontab entries: {len(all_entries)} — none flagged as suspicious.", "miss")

    if verbose and all_entries:
        print_table(["Source", "Entry", "Flag"], all_entries[:20])


def _check_shell_profiles(results, verbose):
    print_status("Scanning shell profile files for injections…", "info")
    findings = []

    for profile in SHELL_PROFILES:
        path = os.path.expanduser(profile)
        if not os.path.isfile(path):
            continue
        content = read_file(path) or ""
        for line in content.splitlines():
            sus = _detect_suspicious(line)
            if sus:
                findings.append((path, line.strip()[:100], sus))

    results["profile_injections"] = findings

    if findings:
        print_finding(
            f"Shell Profile Injections ({len(findings)} found)",
            "\n".join(f"  {f[0]}: {f[1]}" for f in findings),
            "high"
        )
    else:
        print_status("No suspicious injections in shell profiles.", "miss")


def _check_ssh_keys(results, verbose):
    print_status("Auditing SSH authorized_keys…", "info")
    home_dirs = _get_home_dirs()
    auth_key_entries = []

    for home in home_dirs:
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        if not os.path.isfile(ak_path):
            continue
        content = read_file(ak_path) or ""
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Extract comment / key type
                parts = line.split()
                key_type    = parts[0] if parts else "?"
                key_comment = parts[2] if len(parts) > 2 else "no-comment"
                auth_key_entries.append((home, key_type, key_comment))

    results["ssh_authorized_keys"] = auth_key_entries

    if auth_key_entries:
        print_status(f"SSH authorized_keys entries: {len(auth_key_entries)}", "info")
        print_table(["Home Dir", "Key Type", "Comment"], auth_key_entries)
    else:
        print_status("No SSH authorized_keys entries found.", "miss")

    # Also check for private keys world-readable
    _, priv_keys = run_cmd(
        "find /home /root /etc /opt /tmp -name 'id_rsa' -o -name 'id_ed25519' "
        "-o -name '*.pem' -o -name '*.key' 2>/dev/null | head -30"
    )
    priv_list = [l.strip() for l in priv_keys.splitlines() if l.strip()]
    results["exposed_private_keys"] = priv_list

    if priv_list:
        print_finding(
            f"Private Key Files Found ({len(priv_list)})",
            "\n".join(f"  {p}" for p in priv_list),
            "high"
        )


def _check_systemd_units(results, verbose):
    print_status("Checking for suspicious systemd units…", "info")
    unit_dirs = [
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        os.path.expanduser("~/.config/systemd/user/"),
    ]
    suspicious_units = []

    for udir in unit_dirs:
        if not os.path.isdir(udir):
            continue
        for fname in os.listdir(udir):
            if not fname.endswith(".service"):
                continue
            path    = os.path.join(udir, fname)
            content = read_file(path) or ""
            for line in content.splitlines():
                sus = _detect_suspicious(line)
                if sus:
                    suspicious_units.append((fname, line.strip()[:100], sus))
                    break

    results["suspicious_systemd"] = suspicious_units

    if suspicious_units:
        print_finding(
            f"Suspicious Systemd Units ({len(suspicious_units)})",
            "\n".join(f"  {u[0]}: {u[1]}" for u in suspicious_units),
            "high"
        )
    else:
        print_status("No suspicious systemd units found.", "miss")


def _check_motd(results, verbose):
    print_status("Checking MOTD hooks…", "info")
    motd_dir = "/etc/update-motd.d/"
    hooks = []

    if os.path.isdir(motd_dir):
        for fname in sorted(os.listdir(motd_dir)):
            path    = os.path.join(motd_dir, fname)
            content = read_file(path) or ""
            sus     = any(_detect_suspicious(l) for l in content.splitlines())
            writable = is_writable(path)
            if sus or writable:
                hooks.append((path, "SUSPICIOUS" if sus else "", "WRITABLE" if writable else ""))

    results["motd_hooks"] = hooks

    if hooks:
        print_finding(
            f"MOTD Hooks — {len(hooks)} concern(s)",
            "\n".join(f"  {h[0]} [{h[1]}{h[2]}]" for h in hooks),
            "medium"
        )
    else:
        print_status("MOTD hooks appear clean.", "miss")


def _check_rc_local(results, verbose):
    print_status("Checking /etc/rc.local…", "info")
    content = read_file("/etc/rc.local") or ""
    sus = [l.strip() for l in content.splitlines()
           if l.strip() and not l.startswith("#") and _detect_suspicious(l)]

    results["rc_local_suspicious"] = sus

    if sus:
        print_finding("Suspicious /etc/rc.local entries",
                      "\n".join(f"  {s}" for s in sus), "high")
    else:
        print_status("/etc/rc.local looks clean.", "miss")


def _check_profile_d(results, verbose):
    print_status("Checking /etc/profile.d/ scripts…", "info")
    findings = []
    pdir = "/etc/profile.d/"

    if os.path.isdir(pdir):
        for fname in os.listdir(pdir):
            path    = os.path.join(pdir, fname)
            content = read_file(path) or ""
            for line in content.splitlines():
                sus = _detect_suspicious(line)
                if sus:
                    findings.append((fname, line.strip()[:100], sus))

    results["profile_d"] = findings

    if findings:
        print_finding("Suspicious /etc/profile.d Scripts",
                      "\n".join(f"  {f[0]}: {f[1]}" for f in findings), "high")
    else:
        print_status("profile.d scripts appear clean.", "miss")


def _check_at_jobs(results, verbose):
    print_status("Checking at/batch jobs…", "info")
    _, at_jobs = run_cmd("atq 2>/dev/null")
    results["at_jobs"] = at_jobs
    count = len([l for l in at_jobs.splitlines() if l.strip()])

    if count:
        print_finding(f"{count} at/batch job(s) scheduled", at_jobs, "medium")
    else:
        print_status("No at/batch jobs scheduled.", "miss")


def _check_xdg_autostart(results, verbose):
    print_status("Checking XDG autostart entries…", "info")
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart/"),
        "/etc/xdg/autostart/",
    ]
    entries = []
    for adir in autostart_dirs:
        if os.path.isdir(adir):
            for fname in os.listdir(adir):
                if fname.endswith(".desktop"):
                    entries.append(os.path.join(adir, fname))

    results["xdg_autostart"] = entries

    if entries:
        print_finding(f"XDG Autostart Entries ({len(entries)})",
                      "\n".join(f"  {e}" for e in entries), "low")
    else:
        print_status("No XDG autostart entries.", "miss")


def _check_ld_preload(results, verbose):
    print_status("Checking LD_PRELOAD / ld.so.preload…", "info")
    env_preload = os.environ.get("LD_PRELOAD", "")
    file_preload = read_file("/etc/ld.so.preload") or ""

    results["ld_preload"] = {
        "env": env_preload,
        "file": file_preload.strip()
    }

    if env_preload:
        print_finding("LD_PRELOAD is set in environment",
                      f"  Value: {env_preload}", "critical")
    if file_preload.strip():
        print_finding("/etc/ld.so.preload is non-empty",
                      file_preload[:300], "critical")
    if not env_preload and not file_preload.strip():
        print_status("LD_PRELOAD not set.", "miss")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_suspicious(line: str) -> str:
    for pattern, label in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return label
    return ""


def _get_home_dirs() -> list:
    dirs = []
    passwd = read_file("/etc/passwd") or ""
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            home = parts[5]
            if home.startswith("/") and os.path.isdir(home):
                dirs.append(home)
    return list(set(dirs))
