"""
plugins/loot.py — Credential & Sensitive Data Harvesting Module

Checks:
  1.  /etc/shadow readability
  2.  SSH private key discovery
  3.  Shell history files
  4.  Config files containing passwords / tokens
  5.  Cloud credential files (AWS, GCP, Azure)
  6.  Database connection strings
  7.  .netrc / .pgpass / .my.cnf
  8.  Browser credential stores (paths only — no decryption)
  9.  Environment variable secrets
  10. Docker config.json / kubeconfig
"""

import os
import re
from pathlib import Path

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, file_exists, is_readable


# Regex patterns for credential scanning
CRED_PATTERNS = [
    (r'password\s*[=:]\s*\S+',              "password assignment"),
    (r'passwd\s*[=:]\s*\S+',               "passwd assignment"),
    (r'secret\s*[=:]\s*\S+',               "secret value"),
    (r'api[_-]?key\s*[=:]\s*\S+',          "API key"),
    (r'access[_-]?token\s*[=:]\s*\S+',     "access token"),
    (r'AKIA[0-9A-Z]{16}',                  "AWS Access Key ID"),
    (r'[0-9a-zA-Z/+]{40}',                 "Possible AWS Secret"),
    (r'-----BEGIN\s+\w+\s+PRIVATE KEY-----',"Private key block"),
    (r'ghp_[0-9a-zA-Z]{36}',               "GitHub PAT"),
    (r'xox[baprs]-[0-9a-zA-Z\-]+',         "Slack token"),
    (r'mysql://[^\s]+',                    "MySQL connection string"),
    (r'postgres(?:ql)?://[^\s]+',          "PostgreSQL connection string"),
    (r'mongodb(?:\+srv)?://[^\s]+',        "MongoDB connection string"),
    (r'redis://[^\s]+',                    "Redis connection string"),
]

CLOUD_CRED_PATHS = {
    "AWS":   ["~/.aws/credentials", "~/.aws/config"],
    "GCP":   ["~/.config/gcloud/credentials.db",
               "~/.config/gcloud/application_default_credentials.json"],
    "Azure": ["~/.azure/accessTokens.json", "~/.azure/azureProfile.json"],
    "Kube":  ["~/.kube/config"],
    "Docker":["~/.docker/config.json"],
    "Helm":  ["~/.helm/repositories.yaml"],
}

INTERESTING_CONFIGS = [
    "/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf",
    "/etc/postgresql/*/main/pg_hba.conf",
    "/etc/apache2/sites-enabled/*.conf",
    "/etc/nginx/sites-enabled/*.conf",
    "/opt/tomcat/conf/tomcat-users.xml",
    "/var/www/html/wp-config.php",
    "/var/www/html/config.php",
    "/srv/*/config.php",
    "/opt/*/config.yml",
    "/opt/*/settings.py",
    "/home/*/.netrc",
    "/home/*/.pgpass",
    "/home/*/.my.cnf",
    "/root/.netrc",
    "/root/.pgpass",
    "/root/.my.cnf",
]


def run(args, verbose=False):
    results = {}

    _check_shadow(results, verbose)
    _check_ssh_keys(results, verbose)
    _check_history(results, verbose)
    _check_config_files(results, verbose)
    _check_cloud_creds(results, verbose)
    _check_database_creds(results, verbose)
    _check_browser_stores(results, verbose)
    _check_docker_kube(results, verbose)

    _print_loot_summary(results)
    return results


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_shadow(results, verbose):
    print_status("Attempting to read /etc/shadow…", "info")
    if not os.path.exists("/etc/shadow"):
        results["shadow"] = {"readable": False, "reason": "not found"}
        print_status("/etc/shadow not found.", "miss")
        return

    if is_readable("/etc/shadow"):
        content = read_file("/etc/shadow") or ""
        hashes = []
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] not in ("!", "*", "x", ""):
                hashes.append((parts[0], parts[1][:20] + "…"))
        results["shadow"] = {"readable": True, "hash_count": len(hashes), "hashes": hashes}
        print_finding(
            f"/etc/shadow is readable — {len(hashes)} hash(es)",
            "\n".join(f"  {h[0]}: {h[1]}" for h in hashes[:10]),
            "critical"
        )
    else:
        results["shadow"] = {"readable": False}
        print_status("/etc/shadow exists but is not readable (expected).", "miss")


def _check_ssh_keys(results, verbose):
    print_status("Searching for SSH private keys…", "info")
    _, out = run_cmd(
        "find /home /root /etc /opt /var /srv /tmp -maxdepth 6 "
        r"\( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' "
        r"-o -name 'id_dsa' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null",
        timeout=20
    )
    keys = []
    for path in out.splitlines():
        path = path.strip()
        if not path:
            continue
        readable = is_readable(path)
        content  = read_file(path) or ""
        is_private = "PRIVATE KEY" in content
        keys.append((path, "PRIVATE" if is_private else "public/other",
                     "✓ readable" if readable else "✗ locked"))

    results["ssh_keys"] = keys
    private_readable = [k for k in keys if k[1] == "PRIVATE" and "readable" in k[2]]

    if private_readable:
        print_finding(
            f"Readable SSH Private Keys ({len(private_readable)})",
            "\n".join(f"  {k[0]}" for k in private_readable),
            "critical"
        )
    elif keys:
        print_status(f"Found {len(keys)} key file(s), none readable as private.", "info")
    else:
        print_status("No SSH key files found.", "miss")


def _check_history(results, verbose):
    print_status("Harvesting shell history files…", "info")
    history_files = [
        "~/.bash_history", "~/.zsh_history", "~/.sh_history",
        "~/.python_history", "~/.mysql_history", "~/.psql_history",
        "~/.irb_history", "/root/.bash_history", "/root/.zsh_history",
    ]
    # Also find all users' history
    _, user_homes = run_cmd("awk -F: '$3>=1000 {print $6}' /etc/passwd 2>/dev/null")
    for home in user_homes.splitlines():
        history_files.append(os.path.join(home.strip(), ".bash_history"))

    found = []
    cred_hits = []

    for hf in set(history_files):
        path = os.path.expanduser(hf)
        if not os.path.isfile(path) or not is_readable(path):
            continue
        content = read_file(path) or ""
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        found.append((path, len(lines)))

        # Scan for credentials in history
        for line in lines:
            for pat, label in CRED_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    cred_hits.append((path, line[:120], label))
                    break

    results["history_files"] = found
    results["history_cred_hits"] = cred_hits

    if found:
        print_status(f"Shell history files found: {len(found)}", "info")
        if verbose:
            print_table(["File", "Lines"], found)

    if cred_hits:
        print_finding(
            f"Credentials in Shell History ({len(cred_hits)} hits)",
            "\n".join(f"  [{h[2]}] {h[1]}" for h in cred_hits[:15]),
            "high"
        )
    else:
        print_status("No credentials found in history files.", "miss")


def _check_config_files(results, verbose):
    print_status("Scanning config files for credentials…", "info")
    hits = []

    # Expand glob patterns
    import glob
    all_files = []
    for pattern in INTERESTING_CONFIGS:
        all_files.extend(glob.glob(os.path.expanduser(pattern)))

    for path in all_files:
        if not os.path.isfile(path) or not is_readable(path):
            continue
        content = read_file(path) or ""
        for line in content.splitlines():
            for pat, label in CRED_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    # Avoid false-positive comment lines
                    if not line.strip().startswith("#"):
                        hits.append((path, line.strip()[:120], label))
                    break

    results["config_creds"] = hits

    if hits:
        print_finding(
            f"Credentials in Config Files ({len(hits)} matches)",
            "\n".join(f"  {h[0]}: [{h[2]}]" for h in hits[:15]),
            "high"
        )
    else:
        print_status("No credentials found in scanned config files.", "miss")


def _check_cloud_creds(results, verbose):
    print_status("Checking cloud provider credential files…", "info")
    found = []

    for provider, paths in CLOUD_CRED_PATHS.items():
        for p in paths:
            expanded = os.path.expanduser(p)
            if os.path.isfile(expanded) and is_readable(expanded):
                content = read_file(expanded) or ""
                found.append((provider, expanded, len(content)))

    results["cloud_creds"] = found

    if found:
        print_finding(
            f"Cloud Credential Files Found ({len(found)})",
            "\n".join(f"  [{f[0]}] {f[1]}" for f in found),
            "critical"
        )
    else:
        print_status("No cloud credential files found.", "miss")


def _check_database_creds(results, verbose):
    print_status("Checking .netrc, .pgpass, .my.cnf…", "info")
    db_files = [
        "~/.netrc", "~/.pgpass", "~/.my.cnf",
        "/root/.netrc", "/root/.pgpass", "/root/.my.cnf"
    ]
    found = []
    for f in db_files:
        path = os.path.expanduser(f)
        if os.path.isfile(path) and is_readable(path):
            content = read_file(path) or ""
            found.append((path, content[:200]))

    results["db_cred_files"] = found

    if found:
        print_finding(
            f"Database Credential Files ({len(found)})",
            "\n".join(f"  {f[0]}" for f in found),
            "high"
        )
    else:
        print_status("No .netrc/.pgpass/.my.cnf files found.", "miss")


def _check_browser_stores(results, verbose):
    print_status("Locating browser credential stores (paths only)…", "info")
    browser_paths = {
        "Chrome":  "~/.config/google-chrome/Default/Login Data",
        "Chromium":"~/.config/chromium/Default/Login Data",
        "Firefox": "~/.mozilla/firefox/*.default*/logins.json",
        "Brave":   "~/.config/BraveSoftware/Brave-Browser/Default/Login Data",
    }
    import glob
    found = []
    for browser, pattern in browser_paths.items():
        for path in glob.glob(os.path.expanduser(pattern)):
            if os.path.isfile(path):
                found.append((browser, path))

    results["browser_stores"] = found

    if found:
        print_finding(
            f"Browser Credential Stores Found ({len(found)})",
            "\n".join(f"  [{f[0]}] {f[1]}" for f in found),
            "medium"
        )
        print_status("Tip: Use tools like 'secretdump' or 'HackBrowserData' for extraction.", "info")
    else:
        print_status("No browser credential stores found.", "miss")


def _check_docker_kube(results, verbose):
    print_status("Checking Docker/Kubernetes config files…", "info")
    targets = [
        ("~/.docker/config.json",  "Docker registry auth"),
        ("~/.kube/config",         "Kubeconfig (cluster access)"),
        ("/etc/kubernetes/admin.conf", "Kubernetes admin config"),
        ("/var/lib/kubelet/config.json", "Kubelet config"),
    ]
    found = []
    for path, desc in targets:
        expanded = os.path.expanduser(path)
        if os.path.isfile(expanded) and is_readable(expanded):
            content = read_file(expanded) or ""
            found.append((desc, expanded, len(content)))

    results["docker_kube"] = found

    if found:
        print_finding(
            f"Docker/Kubernetes Configs ({len(found)})",
            "\n".join(f"  [{f[0]}] {f[1]}" for f in found),
            "high"
        )
    else:
        print_status("No Docker/Kubernetes config files found.", "miss")


def _print_loot_summary(results):
    total = sum([
        len(results.get("history_cred_hits", [])),
        len(results.get("config_creds", [])),
        len(results.get("cloud_creds", [])),
        len(results.get("db_cred_files", [])),
        len(results.get("ssh_keys", [])),
        1 if results.get("shadow", {}).get("readable") else 0,
    ])
    print_status(f"Loot scan complete — {total} item(s) worth investigating.", "success" if total else "info")
