"""
core/scoring.py — Risk Scoring Engine

Assigns CVSS-like risk scores to findings, generates a prioritised
action plan, and produces an executive summary table.

Severity → Base Score mapping:
  critical → 9.0 – 10.0
  high     → 7.0 –  8.9
  medium   → 4.0 –  6.9
  low      → 0.1 –  3.9
  info     → 0.0
"""

import json
from datetime import datetime
from pathlib import Path

from core.banner import print_status, print_finding, print_table, C

SESSION_FILE = Path(__file__).parent.parent / "reports" / ".last_session.json"

# ── Scoring rules: (keyword_in_key, keyword_in_value) → (score, severity, remediation) ──
SCORING_RULES = [
    # Container / Cloud
    ("docker_socket",    "writable",         10.0, "critical",
     "Remove world-write on /var/run/docker.sock or restrict docker group membership."),
    ("cloud_metadata",   "",                  9.8, "critical",
     "Block IMDS from containers: add iptables rule to drop 169.254.169.254."),
    ("privileged",       "ALL capabilities",  9.5, "critical",
     "Remove --privileged flag from container. Minimise capabilities with --cap-drop ALL."),
    ("ld_preload",       "env",               9.5, "critical",
     "Investigate LD_PRELOAD injection. Audit /etc/ld.so.preload immediately."),

    # PrivEsc
    ("uid0_accounts",    "",                  9.5, "critical",
     "Remove extra UID-0 accounts. Only root should have UID 0."),
    ("empty_passwords",  "",                  9.5, "critical",
     "Set passwords for all accounts. Lock unused accounts with passwd -l."),
    ("passwd_shadow",    "writable",          9.2, "critical",
     "Fix permissions: chmod 644 /etc/passwd && chmod 640 /etc/shadow."),
    ("sudo_findings",    "NOPASSWD ALL",      9.0, "critical",
     "Remove NOPASSWD:ALL from sudoers. Enforce MFA for sudo."),
    ("dangerous_groups", "docker",            9.0, "critical",
     "Remove users from docker/lxd/disk groups. Use rootless Docker instead."),
    ("writable_root_scripts","",              8.8, "critical",
     "Secure permissions on scripts executed by root. Use chmod 700."),
    ("suid_interesting", "",                  8.5, "high",
     "Remove unnecessary SUID bits: chmod u-s <binary>. Review GTFOBins list."),
    ("cron_writable",    "",                  8.5, "high",
     "Fix permissions on cron-executed scripts. Ensure they're owned by root."),
    ("nfs_no_root_squash","",                 8.0, "high",
     "Add root_squash to all NFS exports in /etc/exports."),
    ("kernel_cves",      "DirtyCow",          8.0, "high",
     "Apply kernel patches immediately. Consider kernel hardening (grsecurity)."),
    ("capabilities",     "cap_setuid",        7.5, "high",
     "Remove dangerous capabilities: setcap -r <binary>."),
    ("sudo_findings",    "NOPASSWD",          7.5, "high",
     "Remove NOPASSWD entries from /etc/sudoers or /etc/sudoers.d/*."),

    # Loot
    ("shadow",           "readable",          8.8, "critical",
     "Fix /etc/shadow permissions: chmod 640 /etc/shadow && chown root:shadow /etc/shadow."),
    ("ssh_keys",         "PRIVATE",           8.5, "high",
     "Protect private keys: chmod 600. Consider passphrase protection."),
    ("cloud_creds",      "",                  8.5, "high",
     "Rotate cloud credentials immediately. Store secrets in a vault, not flat files."),
    ("history_cred_hits","",                  7.8, "high",
     "Clear history: history -c. Prevent credential logging with HISTIGNORE."),
    ("config_creds",     "",                  7.5, "high",
     "Move credentials to environment variables or a secrets manager (Vault, AWS SM)."),

    # Persistence
    ("suspicious_systemd","",                 8.0, "high",
     "Investigate and remove suspicious systemd units. Run systemd-analyse security."),
    ("profile_injections","",                 8.0, "high",
     "Remove injected commands from shell profiles. Audit with diff against clean baseline."),
    ("ld_preload",       "file",              8.0, "high",
     "Clear /etc/ld.so.preload and investigate how it was modified."),

    # Network / Web
    ("cleartext_services","Telnet",           8.5, "high",
     "Disable Telnet: systemctl disable telnet. Replace with SSH."),
    ("cleartext_services","FTP",              7.5, "high",
     "Disable FTP: use SFTP/FTPS. Purge vsftpd if unused."),
    ("cors_issues",      "reflected",         8.5, "high",
     "Fix CORS: specify exact allowed origins. Never reflect Origin header blindly."),
    ("dangerous_methods","PUT",               7.5, "high",
     "Disable PUT/DELETE on web server unless required by API. Restrict via WAF."),
    ("found_paths",      "200",               6.5, "medium",
     "Remove or password-protect sensitive endpoints. Implement proper access controls."),
    ("missing",          "CSP",               6.0, "medium",
     "Add Content-Security-Policy header to prevent XSS."),
    ("missing",          "HSTS",              6.5, "medium",
     "Add Strict-Transport-Security header. Minimum max-age=31536000."),
    ("ssh_hardening",    "PermitRootLogin",   7.0, "high",
     "Set PermitRootLogin no in /etc/ssh/sshd_config. Restart sshd."),

    # Audit
    ("world_writable",   "",                  7.0, "high",
     "Fix world-writable files: find / -perm -o+w -exec chmod o-w {} +"),
    ("firewall",         "ACCEPT",            6.5, "medium",
     "Implement default-deny iptables policy: iptables -P INPUT DROP."),
    ("mac",              "DISABLED",          6.0, "medium",
     "Enable AppArmor/SELinux. Start with permissive mode, then enforce."),
    ("audit_logging",    "NOT running",       5.5, "medium",
     "Install and configure auditd: apt install auditd && systemctl enable auditd."),
    ("password_policy",  "not configured",    5.5, "medium",
     "Install libpam-pwquality and configure /etc/pam.d/common-password."),
    ("cookie_issues",    "HttpOnly",          5.0, "medium",
     "Set HttpOnly and Secure flags on all session cookies."),
    ("info_disclosure",  "trace",             5.0, "medium",
     "Disable debug mode in production. Configure custom error pages."),
    ("ssl_issues",       "tls1",              6.5, "medium",
     "Disable TLS 1.0/1.1. Configure: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1."),
    ("snmp",             "public",            6.0, "medium",
     "Change default SNMP community strings. Restrict SNMP to management network."),
    ("writable_path_dirs","",                 5.5, "medium",
     "Remove world-writable directories from $PATH. Review /etc/environment."),
    ("ipv6_neighbors",   "",                  2.0, "info",
     "Audit IPv6 neighbors. Disable IPv6 if not required."),
]


class RiskScorer:
    """Score and prioritise findings from a PhantomX session."""

    def __init__(self, session_file: str = None):
        self.session_file = session_file or str(SESSION_FILE)
        self.session = {}
        self.scored_findings = []

    def load(self):
        try:
            with open(self.session_file) as f:
                self.session = json.load(f)
            return True
        except Exception:
            return False

    def score(self):
        """Score all findings and return prioritised list."""
        all_results = self.session.get("results", {})
        self.scored_findings = []

        for module, module_results in all_results.items():
            self._score_module(module, module_results)

        # Sort by score descending
        self.scored_findings.sort(key=lambda x: x["score"], reverse=True)
        return self.scored_findings

    def _score_module(self, module, results, prefix=""):
        """Recursively scan results dict for matching scoring rules."""
        if not isinstance(results, dict):
            return

        for key, value in results.items():
            full_key = f"{prefix}.{key}" if prefix else key
            val_str  = str(value).lower() if value else ""

            for (key_kw, val_kw, score, severity, remediation) in SCORING_RULES:
                if (key_kw.lower() in full_key.lower() and
                        (not val_kw or val_kw.lower() in val_str)):
                    # Check for duplicates
                    if not any(f["key"] == full_key and f["rule_key"] == key_kw
                               for f in self.scored_findings):
                        count = len(value) if isinstance(value, list) else 1
                        adj_score = min(10.0, score + (count - 1) * 0.1)

                        self.scored_findings.append({
                            "module":      module,
                            "key":         full_key,
                            "rule_key":    key_kw,
                            "score":       round(adj_score, 1),
                            "severity":    severity,
                            "count":       count,
                            "remediation": remediation,
                        })

            # Recurse into nested dicts
            if isinstance(value, dict):
                self._score_module(module, value, full_key)

    def get_overall_risk(self):
        """Calculate overall risk score (0-10)."""
        if not self.scored_findings:
            return 0.0
        critical = [f for f in self.scored_findings if f["severity"] == "critical"]
        high     = [f for f in self.scored_findings if f["severity"] == "high"]

        if critical:
            base = 9.0
        elif high:
            base = 7.0
        elif self.scored_findings:
            base = 5.0
        else:
            base = 0.0

        # Adjust for volume
        adj = min(1.0, len(self.scored_findings) * 0.05)
        return round(min(10.0, base + adj), 1)

    def print_report(self):
        """Print the full scored findings report to terminal."""
        if not self.scored_findings:
            print_status("No scored findings available.", "miss")
            return

        overall = self.get_overall_risk()
        critical_count = len([f for f in self.scored_findings if f["severity"] == "critical"])
        high_count     = len([f for f in self.scored_findings if f["severity"] == "high"])
        medium_count   = len([f for f in self.scored_findings if f["severity"] == "medium"])

        # ── Header ────────────────────────────────────────────────────────────
        sev_color = {
            "critical": C.RED + C.BOLD,
            "high":     C.RED,
            "medium":   C.YELLOW,
            "low":      C.CYAN,
            "info":     C.DIM,
        }

        risk_color = C.RED + C.BOLD if overall >= 9 else (
                     C.RED            if overall >= 7 else (
                     C.YELLOW         if overall >= 4 else C.GREEN))

        print(f"\n  {C.BOLD}{'─'*62}{C.RESET}")
        print(f"  {C.BOLD}  RISK SCORING REPORT{C.RESET}")
        print(f"  {'─'*62}")
        print(f"  Host        : {self.session.get('hostname','?')}")
        print(f"  User        : {self.session.get('user','?')}")
        print(f"  Scan Time   : {self.session.get('start_time','?')}")
        print(f"  {'─'*62}")
        print(f"  Overall Risk: {risk_color}{overall}/10.0{C.RESET}")
        print(f"  Findings    : {C.RED+C.BOLD}{critical_count} CRITICAL{C.RESET}  "
              f"{C.RED}{high_count} HIGH{C.RESET}  "
              f"{C.YELLOW}{medium_count} MEDIUM{C.RESET}  "
              f"{len(self.scored_findings) - critical_count - high_count - medium_count} LOW/INFO")
        print(f"  {'─'*62}\n")

        # ── Findings Table ────────────────────────────────────────────────────
        print(f"  {C.BOLD}{'Score':<7} {'Sev':<10} {'Module':<12} {'Finding':<30}{C.RESET}")
        print(f"  {'─'*62}")

        for f in self.scored_findings:
            sc   = sev_color.get(f["severity"], C.WHITE)
            score_str = f"{f['score']:.1f}"
            finding_key = f["key"].split(".")[-1][:28]
            print(f"  {sc}{score_str:<7}{C.RESET}"
                  f"{sc}{f['severity']:<10}{C.RESET}"
                  f"{f['module']:<12}"
                  f"{finding_key}")

        # ── Top 5 Remediation Actions ──────────────────────────────────────
        print(f"\n  {C.BOLD}TOP REMEDIATION ACTIONS{C.RESET}")
        print(f"  {'─'*62}")
        for i, finding in enumerate(self.scored_findings[:7], 1):
            sc = sev_color.get(finding["severity"], C.WHITE)
            print(f"\n  {sc}{i}. [{finding['severity'].upper()}] Score: {finding['score']}{C.RESET}")
            print(f"     Finding    : {finding['key']}")
            print(f"     Remediation: {C.DIM}{finding['remediation']}{C.RESET}")

        print(f"\n  {'─'*62}\n")

    def export_json(self, path: str):
        """Export scored findings to JSON."""
        data = {
            "generated":       datetime.now().isoformat(),
            "hostname":        self.session.get("hostname"),
            "overall_risk":    self.get_overall_risk(),
            "finding_counts":  {
                "critical": len([f for f in self.scored_findings if f["severity"]=="critical"]),
                "high":     len([f for f in self.scored_findings if f["severity"]=="high"]),
                "medium":   len([f for f in self.scored_findings if f["severity"]=="medium"]),
                "total":    len(self.scored_findings),
            },
            "findings": self.scored_findings,
        }
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2)
        return path
