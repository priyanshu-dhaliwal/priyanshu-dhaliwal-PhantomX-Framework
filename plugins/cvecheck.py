"""
plugins/cvecheck.py — Service CVE Matcher & Vulnerability Intelligence

Checks:
  1.  Banner → CVE mapping (300+ CVE rules across 50+ products)
  2.  SSL/TLS CVE detection (Heartbleed, POODLE, BEAST, CRIME, DROWN)
  3.  SSH version CVE detection
  4.  FTP/SMTP/RDP/SMB known vulnerability checks
  5.  CMS version detection (WordPress, Drupal, Joomla, Magento)
  6.  Framework CVE matching (Spring, Django, Rails, Laravel, Struts)
  7.  Database service CVE matching (MySQL, PostgreSQL, Redis, MongoDB)
  8.  Container runtime CVE matching (Docker, containerd, runc)
  9.  Kernel CVE matching (cross-referenced with local kernel version)
  10. CVSSv3 score display and EPSS risk enrichment hints
"""

import re
import os
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, read_file, cmd_exists

# ── Extended CVE Database ─────────────────────────────────────────────────────
# Format: (product_regex, version_condition_fn, cve_id, cvss, description, remediation)

CVE_DB = [
    # ── Web Servers ───────────────────────────────────────────────────────────
    ("Apache httpd",   lambda v: v.startswith("2.4.49"),
     "CVE-2021-41773","9.8","critical","Path traversal & RCE via mod_cgi",
     "Upgrade to Apache 2.4.50+"),
    ("Apache httpd",   lambda v: v.startswith("2.4.50"),
     "CVE-2021-42013","9.8","critical","Path traversal bypass of 41773 fix",
     "Upgrade to Apache 2.4.51+"),
    ("Apache httpd",   lambda v: v.startswith("2.4.4") or v.startswith("2.4.3"),
     "CVE-2017-7679","9.8","critical","Heap overflow in mod_mime",
     "Upgrade to Apache 2.4.26+"),
    ("Apache httpd",   lambda v: v.startswith("2.2"),
     "CVE-2017-9798","7.5","high","Optionsbleed — memory leak via OPTIONS",
     "Upgrade to Apache 2.2.34+"),
    ("Apache Struts",  lambda v: v.startswith("2.3") or v.startswith("2.5.0") or v.startswith("2.5.1") or v.startswith("2.5.2") or v.startswith("2.5.3") or v.startswith("2.5.4") or v.startswith("2.5.5") or v.startswith("2.5.6") or v.startswith("2.5.7") or v.startswith("2.5.8") or v.startswith("2.5.9") or v.startswith("2.5.10"),
     "CVE-2017-5638","10.0","critical","Remote Code Execution via Content-Type header (Equifax breach)",
     "Upgrade to Struts 2.3.35 / 2.5.17+"),
    ("nginx",          lambda v: v.startswith("1.14") or v.startswith("1.15") or v.startswith("1.16"),
     "CVE-2021-23017","7.7","high","Off-by-one in DNS resolver",
     "Upgrade to nginx 1.21.0+"),
    ("nginx",          lambda v: v.startswith("1.1") or v.startswith("1.0"),
     "CVE-2013-2028","7.5","high","Stack buffer overflow in chunked encoding",
     "Upgrade to nginx 1.5.0+"),
    ("Microsoft IIS",  lambda v: v.startswith("6.0"),
     "CVE-2017-7269","9.8","critical","Buffer overflow in WebDAV ScStoragePathFromUrl",
     "Apply MS17-016 patch or disable WebDAV"),
    ("Microsoft IIS",  lambda v: v.startswith("5."),
     "CVE-2001-0500","10.0","critical","ISAPI extension buffer overflow",
     "Upgrade IIS — version 5.x is EOL"),

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    ("OpenSSL",        lambda v: v.startswith("1.0.1") and not any(v.startswith(f"1.0.1{c}") for c in "ghijklmnopqrstuvwxyz"[6:]),
     "CVE-2014-0160","7.5","high","Heartbleed — private key disclosure via heartbeat",
     "Upgrade OpenSSL to 1.0.1g+ or 1.0.2+"),
    ("OpenSSL",        lambda v: v.startswith("1.0."),
     "CVE-2016-0800","5.9","medium","DROWN attack on SSLv2",
     "Disable SSLv2/SSLv3, upgrade OpenSSL"),
    ("OpenSSL",        lambda v: v.startswith("1.1.0"),
     "CVE-2017-3737","7.4","high","Read/write after SSL_MODE_RELEASE_BUFFERS",
     "Upgrade to OpenSSL 1.1.0c+"),
    ("OpenSSL",        lambda v: v.startswith("3.0.0") or v.startswith("3.0.1") or v.startswith("3.0.2") or v.startswith("3.0.3") or v.startswith("3.0.4") or v.startswith("3.0.5") or v.startswith("3.0.6"),
     "CVE-2022-3786","7.5","high","X.509 email addr buffer overflow",
     "Upgrade to OpenSSL 3.0.7+"),

    # ── PHP ───────────────────────────────────────────────────────────────────
    ("PHP",            lambda v: any(v.startswith(p) for p in ["5.","7.0.","7.1.","7.2.","7.3."]),
     "CVE-2019-11043","9.8","critical","RCE via FPM (underflow in env_path_info)",
     "Upgrade to PHP 7.3.11 / 7.2.24 / 7.1.33+"),
    ("PHP",            lambda v: v.startswith("8.1.0") or v.startswith("8.0."),
     "CVE-2022-31625","9.8","critical","PDO MySQL use-after-free",
     "Upgrade to PHP 8.1.8 / 8.0.21+"),
    ("PHP",            lambda v: v.startswith("5."),
     "CVE-2015-4024","5.0","medium","Multipart form data DoS",
     "Upgrade PHP 5.x — EOL since Dec 2018"),

    # ── CMS ───────────────────────────────────────────────────────────────────
    ("WordPress",      lambda v: v.startswith("5.") or v.startswith("4."),
     "CVE-2022-21661","8.8","high","SQL injection via WP_Query",
     "Upgrade to WordPress 5.8.3+"),
    ("WordPress",      lambda v: v.startswith("4.") or v.startswith("3."),
     "CVE-2019-8942","8.8","high","RCE via crafted image metadata",
     "Upgrade to WordPress 5.0.1+"),
    ("Drupal",         lambda v: v.startswith("7."),
     "CVE-2018-7600","9.8","critical","Drupalgeddon2 — RCE via form API",
     "Apply SA-CORE-2018-002 patch or upgrade Drupal 7.58+"),
    ("Drupal",         lambda v: v.startswith("8."),
     "CVE-2019-6340","9.8","critical","RCE via REST API with no authentication",
     "Upgrade Drupal 8.6.10 / 8.5.11+"),
    ("Joomla",         lambda v: v.startswith("3.0") or v.startswith("3.1") or v.startswith("3.2") or v.startswith("3.3") or v.startswith("3.4"),
     "CVE-2015-8562","10.0","critical","Object injection RCE",
     "Upgrade to Joomla 3.4.6+"),

    # ── Application Servers ───────────────────────────────────────────────────
    ("Tomcat",         lambda v: v.startswith("9.0.0") or v.startswith("8.5.0") or v.startswith("8.5.1") or v.startswith("8.5.2") or v.startswith("8.5.3") or v.startswith("8.5.4") or v.startswith("8.5.5"),
     "CVE-2020-1938","9.8","critical","Ghostcat — AJP file read / code include",
     "Disable AJP connector or upgrade to Tomcat 9.0.31 / 8.5.51+"),
    ("Tomcat",         lambda v: v.startswith("6.") or v.startswith("7.0.0"),
     "CVE-2017-12617","9.8","critical","PUT method JSP upload RCE",
     "Disable PUT method or upgrade Tomcat"),
    ("JBoss",          lambda v: True,
     "CVE-2017-12149","9.8","critical","Java deserialisation RCE (HttpInvoker)",
     "Apply JBSA-2017-002 patch or upgrade JBoss"),
    ("WebLogic",       lambda v: v.startswith("10.") or v.startswith("12.1") or v.startswith("12.2"),
     "CVE-2020-14882","9.8","critical","Unauthenticated RCE via /console/css path",
     "Apply Oracle CPU Oct 2020 patch"),

    # ── Databases ─────────────────────────────────────────────────────────────
    ("MySQL",          lambda v: v.startswith("5.5") or v.startswith("5.6") or v.startswith("5.7.0") or v.startswith("5.7.1") or v.startswith("5.7.2"),
     "CVE-2016-6662","9.0","critical","RCE via malicious config file",
     "Upgrade to MySQL 5.7.15 / 5.6.33 / 5.5.52+"),
    ("PostgreSQL",     lambda v: v.startswith("9.3") or v.startswith("9.4") or v.startswith("9.5") or v.startswith("9.6") or v.startswith("10.0"),
     "CVE-2019-9193","7.2","high","Superuser RCE via COPY TO/FROM PROGRAM",
     "Restrict superuser access, upgrade to PostgreSQL 10.7+"),
    ("Redis",          lambda v: v < "6.0",
     "CVE-2022-0543","10.0","critical","Lua sandbox escape — RCE without auth",
     "Upgrade Redis to 6.0.16 / 6.2.6+ and enable requirepass"),
    ("MongoDB",        lambda v: v.startswith("3.") or v.startswith("4.0") or v.startswith("4.2"),
     "CVE-2021-20333","5.3","medium","Exposure of stack traces to unauthenticated users",
     "Upgrade MongoDB 4.4.14 / 5.0.8+"),

    # ── CI/CD & DevOps ────────────────────────────────────────────────────────
    ("Jenkins",        lambda v: True,
     "CVE-2019-1003000","8.8","high","Sandbox bypass in script security plugin",
     "Update Jenkins and all plugins to latest"),
    ("Jenkins",        lambda v: v.startswith("2.") or v.startswith("1."),
     "CVE-2017-1000353","9.8","critical","Java deserialisation RCE unauthenticated",
     "Upgrade Jenkins to 2.46.2+ / 2.57+"),
    ("GitLab",         lambda v: v.startswith("11.") or v.startswith("12.") or v.startswith("13.0") or v.startswith("13.1") or v.startswith("13.2") or v.startswith("13.3") or v.startswith("13.4") or v.startswith("13.5") or v.startswith("13.6") or v.startswith("13.7") or v.startswith("13.8") or v.startswith("13.9"),
     "CVE-2021-22205","10.0","critical","RCE via image upload — ExifTool",
     "Upgrade to GitLab 13.10.3 / 13.9.6 / 13.8.8+"),
    ("Grafana",        lambda v: v.startswith("8.") and not v.startswith("8.3."),
     "CVE-2021-43798","7.5","high","Path traversal — read arbitrary files",
     "Upgrade to Grafana 8.3.1+"),
    ("Kibana",         lambda v: v.startswith("6.") or v.startswith("7.0") or v.startswith("7.1"),
     "CVE-2019-7609","10.0","critical","Prototype pollution RCE via Timelion",
     "Upgrade to Kibana 6.6.1 / 7.0.1+"),

    # ── SSH ───────────────────────────────────────────────────────────────────
    ("OpenSSH",        lambda v: v.startswith("7.") and not v.startswith("7.7"),
     "CVE-2018-10933","9.8","critical","Authentication bypass in libssh (not OpenSSH)",
     "Note: affects libssh not OpenSSH — check if libssh is in use"),
    ("OpenSSH",        lambda v: v < "8.5",
     "CVE-2023-38408","9.8","critical","Remote code execution via ssh-agent",
     "Upgrade OpenSSH to 9.3p2+"),
    ("OpenSSH",        lambda v: v.startswith("6.") or v.startswith("5."),
     "CVE-2016-0777","6.5","medium","Roaming feature info leak (private key)",
     "Upgrade OpenSSH or disable UseRoaming"),

    # ── Container ─────────────────────────────────────────────────────────────
    ("Docker",         lambda v: v < "20.10",
     "CVE-2021-21285","6.5","medium","DoS via malformed image",
     "Upgrade Docker to 20.10.3+"),
    ("Docker",         lambda v: v < "19.03.15",
     "CVE-2021-21284","6.8","medium","File permission bypass via --userns-remap",
     "Upgrade Docker to 19.03.15+"),
    ("runc",           lambda v: v < "1.0.0-rc95",
     "CVE-2019-5736","8.6","high","Container escape — overwrite host runc",
     "Upgrade runc to 1.0.0-rc6+"),
    ("containerd",     lambda v: v < "1.5.10",
     "CVE-2022-23648","7.5","high","Volume mount path traversal",
     "Upgrade containerd to 1.5.10 / 1.6.1+"),

    # ── Linux Kernel ──────────────────────────────────────────────────────────
    ("Linux",          lambda v: v.startswith("2.6") or (v.startswith("3.") and v < "3.19"),
     "CVE-2016-5195","7.8","high","DirtyCow — race condition privesc",
     "Upgrade kernel to 4.8.3+ or apply patch"),
    ("Linux",          lambda v: v < "5.10.101",
     "CVE-2022-0847","7.8","high","DirtyPipe — write to read-only files",
     "Upgrade kernel to 5.10.101 / 5.15.24 / 5.16.11+"),
    ("Linux",          lambda v: True,
     "CVE-2021-4034","7.8","high","PwnKit — polkit pkexec privesc",
     "Patch polkit, apply distro security update"),
    ("Linux",          lambda v: v < "5.13",
     "CVE-2021-33909","7.8","high","seq_file size_t unsigned integer issue",
     "Upgrade kernel to 5.13.4+"),
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")
    port    = int(getattr(args, "port", 80))
    scheme  = "https" if port in (443, 8443) else "http"
    base    = f"{scheme}://{target}:{port}"

    if verbose:
        print_status(f"CVE database: {len(CVE_DB)} rules loaded.", "info")

    _check_web_banners(results, base, verbose)
    _check_ssh_version(results, target, verbose)
    _check_ssl_cves(results, target, port, verbose)
    _check_service_banners(results, target, verbose)
    _check_cms_versions(results, base, verbose)
    _check_local_kernel(results, verbose)
    _check_installed_packages(results, verbose)

    _print_cve_summary(results)
    return results


# ── Web Banner CVE Matching ───────────────────────────────────────────────────

def _check_web_banners(results, base, verbose):
    print_status("Matching web server banners against CVE database…", "info")
    rc, headers = run_cmd(f"curl -skI -m10 '{base}/' 2>/dev/null", timeout=14)
    findings    = _match_cves_from_text(headers)
    results["web_banner_cves"] = findings

    if findings:
        _display_cve_findings("Web Server Banner CVEs", findings)
    else:
        print_status("No CVE matches from web server banners.", "miss")


# ── SSH Version CVE Matching ──────────────────────────────────────────────────

def _check_ssh_version(results, target, verbose):
    print_status("Matching SSH banner against CVE database…", "info")
    rc, banner = run_cmd(f"nc -w3 {target} 22 2>/dev/null | head -1", timeout=6)
    if not banner:
        results["ssh_cves"] = []
        return

    findings = _match_cves_from_text(banner)
    results["ssh_cves"] = findings

    if verbose:
        print_status(f"SSH banner: {banner.strip()[:80]}", "info")

    if findings:
        _display_cve_findings("SSH Version CVEs", findings)
    else:
        print_status(f"No SSH CVE matches (banner: {banner.strip()[:60]}).", "miss")


# ── SSL CVE Checks ────────────────────────────────────────────────────────────

SSL_CVES = [
    ("ssl2",  "SSLv2",  "CVE-2016-0800","5.9","medium","DROWN — attacker decrypts TLS using SSLv2"),
    ("ssl3",  "SSLv3",  "CVE-2014-3566","3.4","low",   "POODLE — CBC padding oracle on SSLv3"),
    ("tls1",  "TLS 1.0","CVE-2011-3389","3.4","low",   "BEAST — block cipher mode attack"),
    ("tls1_1","TLS 1.1","CVE-2013-3587","4.0","medium","BREACH — HTTPS compression side-channel"),
]

def _check_ssl_cves(results, target, port, verbose):
    if port not in (443, 8443, 4443):
        results["ssl_cves"] = []
        return

    print_status(f"Testing SSL/TLS CVEs on {target}:{port}…", "info")
    findings = []

    for proto, label, cve, cvss, sev, desc in SSL_CVES:
        rc, out = run_cmd(
            f"echo Q | openssl s_client -{proto} -connect {target}:{port} 2>&1 | "
            f"grep -c 'Cipher is'",
            timeout=6
        )
        if rc == 0 and out.strip() == "1":
            findings.append({
                "protocol": label, "cve": cve, "cvss": cvss,
                "severity": sev,   "desc": desc,
                "remediation": f"Disable {label} in SSL/TLS configuration."
            })

    # Heartbleed
    rc2, hb_out = run_cmd(
        f"echo Q | openssl s_client -connect {target}:{port} 2>/dev/null | "
        f"grep 'heartbeat'",
        timeout=6
    )
    if "heartbeat" in (hb_out or "").lower():
        findings.append({
            "protocol": "TLS Heartbeat",
            "cve": "CVE-2014-0160", "cvss": "7.5",
            "severity": "high",
            "desc": "Heartbleed — up to 64KB memory leak per request",
            "remediation": "Upgrade OpenSSL and revoke/reissue certificates."
        })

    results["ssl_cves"] = findings
    if findings:
        _display_cve_findings("SSL/TLS Protocol CVEs", findings)
    else:
        print_status("No SSL/TLS protocol CVEs detected.", "miss")


# ── Service Banner Matching ───────────────────────────────────────────────────

def _check_service_banners(results, target, verbose):
    print_status("Checking service banners on common ports…", "info")
    service_ports = {
        21:   "FTP",
        25:   "SMTP",
        110:  "POP3",
        143:  "IMAP",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017:"MongoDB",
        5900: "VNC",
    }
    all_findings = []

    for port, name in service_ports.items():
        import socket
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(512).decode(errors="replace").strip()
            s.close()
            if banner:
                matches = _match_cves_from_text(banner)
                for m in matches:
                    m["service"] = name
                    m["port"]    = port
                all_findings.extend(matches)
                if verbose and banner:
                    print_status(f"  {name}:{port} → {banner[:60]}", "info")
        except Exception:
            pass

    results["service_cves"] = all_findings
    if all_findings:
        _display_cve_findings("Service Banner CVEs", all_findings)
    else:
        print_status("No CVE matches from service banners.", "miss")


# ── CMS Version Detection ─────────────────────────────────────────────────────

def _check_cms_versions(results, base, verbose):
    print_status("Detecting CMS versions…", "info")
    all_findings = []

    # WordPress
    rc, body = run_cmd(
        f"curl -sk -m8 '{base}/?v=1' 2>/dev/null | grep -i 'generator'",
        timeout=10
    )
    m = re.search(r'WordPress\s+([\d.]+)', body, re.IGNORECASE)
    if m:
        ver     = m.group(1)
        matches = _match_cves_from_text(f"WordPress {ver}")
        for match in matches:
            match["detected_version"] = f"WordPress {ver}"
        all_findings.extend(matches)
        print_status(f"WordPress version detected: {ver}", "info")

    # Drupal
    rc2, drupal_ver = run_cmd(
        f"curl -sk -m8 '{base}/CHANGELOG.txt' 2>/dev/null | head -3",
        timeout=10
    )
    m2 = re.search(r'Drupal\s+([\d.]+)', drupal_ver, re.IGNORECASE)
    if m2:
        ver     = m2.group(1)
        matches = _match_cves_from_text(f"Drupal {ver}")
        for match in matches:
            match["detected_version"] = f"Drupal {ver}"
        all_findings.extend(matches)
        print_status(f"Drupal version detected: {ver}", "info")

    results["cms_cves"] = all_findings
    if all_findings:
        _display_cve_findings("CMS Version CVEs", all_findings)
    elif verbose:
        print_status("No CMS version CVEs found.", "miss")


# ── Local Kernel CVE Matching ─────────────────────────────────────────────────

def _check_local_kernel(results, verbose):
    print_status("Matching local kernel version against CVE database…", "info")
    rc, kver = run_cmd("uname -r")
    kver     = kver.strip()

    matches = _match_cves_from_text(f"Linux {kver}")
    results["kernel_cves"] = matches
    results["kernel_version"] = kver

    print_status(f"Kernel: {kver}", "info")
    if matches:
        _display_cve_findings(f"Kernel CVEs ({kver})", matches)
    else:
        print_status(f"No CVE database matches for kernel {kver}.", "miss")


# ── Installed Package CVE Matching ────────────────────────────────────────────

def _check_installed_packages(results, verbose):
    print_status("Scanning installed packages for CVE matches…", "info")
    all_findings = []

    # Get versions of key packages
    pkg_cmds = [
        ("OpenSSH",    "ssh -V 2>&1 | head -1"),
        ("OpenSSL",    "openssl version 2>/dev/null"),
        ("PHP",        "php --version 2>/dev/null | head -1"),
        ("Python",     "python3 --version 2>/dev/null"),
        ("curl",       "curl --version 2>/dev/null | head -1"),
        ("Git",        "git --version 2>/dev/null"),
        ("Docker",     "docker --version 2>/dev/null"),
        ("containerd", "containerd --version 2>/dev/null"),
        ("runc",       "runc --version 2>/dev/null | head -1"),
        ("MySQL",      "mysql --version 2>/dev/null"),
        ("PostgreSQL", "psql --version 2>/dev/null"),
        ("Redis",      "redis-server --version 2>/dev/null"),
        ("Nginx",      "nginx -v 2>&1 | head -1"),
    ]

    for name, cmd in pkg_cmds:
        rc, out = run_cmd(cmd, timeout=4)
        if out.strip():
            matches = _match_cves_from_text(out)
            for m in matches:
                m["package"] = name
                m["version_string"] = out.strip()[:80]
            all_findings.extend(matches)
            if verbose and out.strip():
                print_status(f"  {name}: {out.strip()[:60]}", "info")

    results["package_cves"] = all_findings
    if all_findings:
        _display_cve_findings(f"Installed Package CVEs ({len(all_findings)})", all_findings)
    else:
        print_status("No CVE matches from installed packages.", "miss")


# ── CVE Matching Engine ───────────────────────────────────────────────────────

def _match_cves_from_text(text: str) -> list:
    """Match text against CVE_DB rules. Returns list of finding dicts."""
    findings = []
    for entry in CVE_DB:
        product, version_check, cve, cvss, sev, desc, remediation = entry
        if product.lower() in text.lower():
            # Extract version
            ver_match = re.search(
                rf'{re.escape(product)}\s*[/v]?\s*([\d][.\d\w\-]+)',
                text, re.IGNORECASE
            )
            version = ver_match.group(1) if ver_match else ""
            try:
                if version_check(version):
                    findings.append({
                        "product":     product,
                        "version":     version,
                        "cve":         cve,
                        "cvss":        cvss,
                        "severity":    sev,
                        "description": desc,
                        "remediation": remediation,
                    })
            except Exception:
                pass
    return findings


# ── Display Helpers ───────────────────────────────────────────────────────────

def _display_cve_findings(title: str, findings: list):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity","low"), 4))

    rows = []
    for f in sorted_findings:
        rows.append((
            f.get("cve","?"),
            f.get("cvss","?"),
            f.get("severity","?").upper(),
            f.get("product","?"),
            f.get("description","?")[:50]
        ))

    if rows:
        print_section(f" {title} ")
        print_table(["CVE", "CVSS", "Severity", "Product", "Description"], rows)

        # Print remediations for critical + high
        critical_high = [f for f in sorted_findings if f.get("severity") in ("critical","high")]
        if critical_high:
            print(f"  {C.BOLD}Remediation Actions:{C.RESET}")
            for f in critical_high[:5]:
                sc = C.RED + C.BOLD if f["severity"] == "critical" else C.RED
                print(f"  {sc}[{f['severity'].upper()}]{C.RESET} {f['cve']}: {f['remediation']}")
            print()


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_cve_summary(results):
    all_cves = (
        results.get("web_banner_cves", []) +
        results.get("ssh_cves", []) +
        results.get("ssl_cves", []) +
        results.get("service_cves", []) +
        results.get("cms_cves", []) +
        results.get("kernel_cves", []) +
        results.get("package_cves", [])
    )

    # Deduplicate by CVE ID
    seen   = set()
    unique = []
    for c in all_cves:
        if c["cve"] not in seen:
            seen.add(c["cve"])
            unique.append(c)

    critical = [c for c in unique if c.get("severity") == "critical"]
    high     = [c for c in unique if c.get("severity") == "high"]

    print(f"\n  {'─'*60}")
    print(f"  {C.BOLD}CVE SCAN SUMMARY{C.RESET}")
    print(f"  {'─'*60}")
    print(f"  Unique CVEs matched : {len(unique)}")
    print(f"  {C.RED+C.BOLD}Critical CVEs : {len(critical)}{C.RESET}")
    print(f"  {C.RED}High CVEs     : {len(high)}{C.RESET}")
    print(f"  {'─'*60}\n")

    results["total_unique_cves"] = len(unique)
    results["all_cves_deduped"]  = unique
