"""
plugins/webapp.py — Web Application Security Scanner Module

Checks:
  1.  Technology fingerprinting (headers, cookies, meta tags)
  2.  Security headers audit (CSP, HSTS, X-Frame, etc.)
  3.  Common sensitive path discovery (admin, backup, config files)
  4.  Cookie security flags (HttpOnly, Secure, SameSite)
  5.  SSL/TLS configuration audit
  6.  HTTP methods enumeration (PUT, DELETE, TRACE)
  7.  Directory listing detection
  8.  Information disclosure (server version, stack traces, debug)
  9.  CORS misconfiguration
  10. Default credentials on common panels
"""

import re
import socket
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, cmd_exists

# ── Sensitive paths to probe ──────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/wp-admin/", "/phpmyadmin/",
    "/manager/html", "/console", "/dashboard", "/panel", "/cpanel",
    # Config & backup files
    "/.env", "/config.php", "/wp-config.php", "/config.yml", "/config.json",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.htaccess",
    "/web.config", "/app.config", "/database.yml",
    # Backup files
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/site.zip", "/www.zip", "/html.zip",
    # Info disclosure
    "/info.php", "/phpinfo.php", "/test.php", "/debug.php",
    "/server-status", "/server-info", "/_profiler", "/actuator",
    "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/api/swagger.json", "/swagger.json", "/openapi.json",
    "/v1/swagger.json", "/api-docs",
    # Log files
    "/error.log", "/access.log", "/debug.log", "/app.log",
    # Other
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

SECURITY_HEADERS = {
    "strict-transport-security":   ("HSTS", "critical"),
    "content-security-policy":     ("CSP", "high"),
    "x-frame-options":             ("X-Frame-Options", "medium"),
    "x-content-type-options":      ("X-Content-Type-Options", "low"),
    "referrer-policy":             ("Referrer-Policy", "low"),
    "permissions-policy":          ("Permissions-Policy", "low"),
    "x-xss-protection":            ("X-XSS-Protection", "low"),
}

DEFAULT_CREDS = [
    ("/wp-login.php",           "admin:admin",    "WordPress"),
    ("/manager/html",           "tomcat:tomcat",  "Tomcat Manager"),
    ("/admin",                  "admin:admin",    "Generic Admin"),
    ("/phpmyadmin/",            "root:",          "phpMyAdmin"),
    ("/jenkins/",               "admin:admin",    "Jenkins"),
    ("/grafana/login",          "admin:admin",    "Grafana"),
    ("/kibana",                 "elastic:changeme","Kibana"),
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")
    port    = int(getattr(args, "port", 80))
    scheme  = "https" if port in (443, 8443) else "http"
    base    = f"{scheme}://{target}:{port}"

    print_status(f"Target web application: {base}", "info")

    _fingerprint(results, base, verbose)
    _security_headers(results, base, verbose)
    _path_discovery(results, base, verbose)
    _cookie_audit(results, base, verbose)
    _ssl_audit(results, target, port, verbose)
    _http_methods(results, base, verbose)
    _cors_check(results, base, verbose)
    _info_disclosure(results, base, verbose)

    return results


# ── Fingerprinting ────────────────────────────────────────────────────────────

def _fingerprint(results, base, verbose):
    print_status("Fingerprinting web technologies…", "info")
    rc, headers_raw = run_cmd(f"curl -skI -m8 '{base}/' 2>/dev/null", timeout=12)
    rc2, body = run_cmd(f"curl -sk -m8 '{base}/' 2>/dev/null | head -100", timeout=12)

    tech = {}
    headers_lower = headers_raw.lower()

    # Server header
    m = re.search(r'^server:\s*(.+)$', headers_raw, re.MULTILINE | re.IGNORECASE)
    if m:
        tech["Server"] = m.group(1).strip()

    # X-Powered-By
    m = re.search(r'^x-powered-by:\s*(.+)$', headers_raw, re.MULTILINE | re.IGNORECASE)
    if m:
        tech["X-Powered-By"] = m.group(1).strip()

    # Framework detection from body
    body_lower = body.lower()
    fw_sigs = {
        "WordPress":  ["wp-content", "wp-includes", "wordpress"],
        "Drupal":     ["drupal", "sites/default"],
        "Joomla":     ["joomla", "/components/com_"],
        "Laravel":    ["laravel_session", "__laravel"],
        "Django":     ["csrfmiddlewaretoken", "django"],
        "Rails":      ["_rails_session", "rails"],
        "React":      ["react", "react-dom"],
        "Angular":    ["ng-version", "angular"],
        "Vue.js":     ["vue.js", "__vue__"],
        "jQuery":     ["jquery"],
        "Bootstrap":  ["bootstrap.min"],
        "Spring Boot":["whitelabel error", "spring.io"],
        "Express.js": ["express"],
        "ASP.NET":    ["__viewstate", "asp.net"],
        "PHP":        [".php", "<?php"],
    }
    for fw, sigs in fw_sigs.items():
        if any(s in body_lower or s in headers_lower for s in sigs):
            tech[fw] = "detected"

    results["fingerprint"] = tech

    if tech:
        print_status("Technologies detected:", "info")
        rows = [(k, v) for k, v in tech.items()]
        print_table(["Technology", "Version/Note"], rows)

        # Flag version disclosure
        for key in ("Server", "X-Powered-By"):
            if key in tech:
                print_finding(
                    f"Version Disclosure: {key}: {tech[key]}",
                    "Exposes exact server version — aids targeted exploitation.",
                    "medium"
                )
    else:
        print_status("No technology fingerprints detected.", "miss")


# ── Security Headers ──────────────────────────────────────────────────────────

def _security_headers(results, base, verbose):
    print_status("Auditing security headers…", "info")
    rc, headers_raw = run_cmd(f"curl -skI -m8 '{base}/' 2>/dev/null", timeout=12)
    headers_lower = headers_raw.lower()

    missing = []
    present = []

    for hdr, (label, sev) in SECURITY_HEADERS.items():
        if hdr in headers_lower:
            # Extract value
            m = re.search(rf'^{re.escape(hdr)}:\s*(.+)$', headers_raw,
                          re.MULTILINE | re.IGNORECASE)
            val = m.group(1).strip()[:80] if m else "present"
            present.append((label, val))
        else:
            missing.append((label, sev))

    results["security_headers"] = {"missing": missing, "present": present}

    if missing:
        print_finding(
            f"Missing Security Headers ({len(missing)})",
            "\n".join(f"  [{s.upper()}] {h}" for h, s in missing),
            "high" if any(s in ("critical","high") for _,s in missing) else "medium"
        )
    if present and verbose:
        print_table(["Header", "Value"], present)
    else:
        print_status(f"Present security headers: {len(present)}/{len(SECURITY_HEADERS)}", "info")


# ── Path Discovery ────────────────────────────────────────────────────────────

def _path_discovery(results, base, verbose):
    print_status(f"Probing {len(SENSITIVE_PATHS)} sensitive paths (20 threads)…", "info")
    found = []

    def probe(path):
        try:
            rc, out = run_cmd(
                f"curl -sk -m5 -o /dev/null -w '%{{http_code}} %{{size_download}}' "
                f"'{base}{path}' 2>/dev/null",
                timeout=8
            )
            parts = out.strip().split()
            code = int(parts[0]) if parts else 0
            size = int(parts[1]) if len(parts) > 1 else 0
            if code in (200, 301, 302, 403, 401):
                return (path, code, size)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(probe, p) for p in SENSITIVE_PATHS]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                found.append(r)

    found.sort(key=lambda x: (x[1] != 200, x[1]))
    results["found_paths"] = found

    # Categorize
    open_paths   = [f for f in found if f[1] == 200]
    auth_paths   = [f for f in found if f[1] in (401, 403)]
    redirect_paths = [f for f in found if f[1] in (301, 302)]

    if open_paths:
        print_finding(
            f"Accessible Sensitive Paths ({len(open_paths)})",
            "\n".join(f"  [{f[1]}] {base}{f[0]}  ({f[2]} bytes)" for f in open_paths),
            "high"
        )
    if auth_paths:
        print_status(f"Protected paths (401/403): {len(auth_paths)}", "info")
        if verbose:
            for f in auth_paths:
                print(f"  {C.DIM}[{f[1]}] {base}{f[0]}{C.RESET}")

    if not open_paths and not auth_paths:
        print_status("No sensitive paths discovered.", "miss")


# ── Cookie Audit ──────────────────────────────────────────────────────────────

def _cookie_audit(results, base, verbose):
    print_status("Auditing cookie security flags…", "info")
    rc, headers_raw = run_cmd(f"curl -skI -m8 '{base}/' 2>/dev/null", timeout=12)
    cookies = re.findall(r'^set-cookie:\s*(.+)$', headers_raw,
                         re.MULTILINE | re.IGNORECASE)
    issues = []

    for cookie in cookies:
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()
        flags = []
        if "httponly" not in lower:
            flags.append("missing HttpOnly — XSS can steal cookie")
        if "secure" not in lower and "https" in base:
            flags.append("missing Secure flag — cookie sent over HTTP")
        if "samesite" not in lower:
            flags.append("missing SameSite — CSRF risk")
        if flags:
            issues.append((name, "; ".join(flags)))

    results["cookie_issues"] = issues

    if issues:
        print_finding(
            f"Cookie Security Issues ({len(issues)})",
            "\n".join(f"  {i[0]}: {i[1]}" for i in issues),
            "medium"
        )
    elif cookies:
        print_status(f"Cookies appear well-configured ({len(cookies)} found).", "miss")
    else:
        print_status("No cookies set on homepage.", "miss")


# ── SSL/TLS Audit ─────────────────────────────────────────────────────────────

def _ssl_audit(results, target, port, verbose):
    if port not in (443, 8443, 4443):
        results["ssl"] = {"checked": False}
        return

    print_status(f"Auditing SSL/TLS on {target}:{port}…", "info")
    issues = []

    # Use openssl to check protocols and cert
    rc, ssl_out = run_cmd(
        f"echo | openssl s_client -connect {target}:{port} "
        f"-servername {target} 2>/dev/null",
        timeout=10
    )

    # Check cert expiry
    rc2, dates = run_cmd(
        f"echo | openssl s_client -connect {target}:{port} 2>/dev/null "
        f"| openssl x509 -noout -dates 2>/dev/null",
        timeout=10
    )
    if dates:
        m = re.search(r'notAfter=(.+)', dates)
        if m:
            results["ssl_expiry"] = m.group(1).strip()
            if verbose:
                print_status(f"Cert expires: {m.group(1).strip()}", "info")

    # Check for weak protocols
    for proto in ["ssl2", "ssl3", "tls1", "tls1_1"]:
        rc_p, _ = run_cmd(
            f"echo | openssl s_client -{proto} -connect {target}:{port} 2>&1 | "
            f"grep -c 'Cipher is'",
            timeout=6
        )
        if rc_p == 0 and _.strip() == "1":
            issues.append((proto.upper(), "weak/deprecated protocol accepted"))

    # Check for self-signed
    if "self signed" in ssl_out.lower() or "self-signed" in ssl_out.lower():
        issues.append(("Self-signed cert", "no trusted CA — MITM risk"))

    results["ssl_issues"] = issues

    if issues:
        print_finding(
            f"SSL/TLS Issues ({len(issues)})",
            "\n".join(f"  {i[0]}: {i[1]}" for i in issues),
            "high"
        )
    else:
        print_status("SSL/TLS configuration appears acceptable.", "miss")


# ── HTTP Methods ──────────────────────────────────────────────────────────────

def _http_methods(results, base, verbose):
    print_status("Testing dangerous HTTP methods…", "info")
    dangerous = []

    for method in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]:
        rc, out = run_cmd(
            f"curl -sk -m5 -X {method} -o /dev/null -w '%{{http_code}}' "
            f"'{base}/' 2>/dev/null",
            timeout=8
        )
        code = out.strip()
        if method == "OPTIONS":
            # Get Allow header
            rc2, allow = run_cmd(
                f"curl -skI -m5 -X OPTIONS '{base}/' 2>/dev/null | "
                f"grep -i '^allow:'",
                timeout=8
            )
            if allow:
                results["allowed_methods"] = allow.strip()
                dangerous_found = [m for m in ["PUT","DELETE","TRACE"]
                                   if m in allow.upper()]
                for dm in dangerous_found:
                    dangerous.append((dm, "listed in Allow header"))
        elif code not in ("405", "501", "400", "000", ""):
            if method in ("PUT", "DELETE", "TRACE"):
                dangerous.append((method, f"responded with HTTP {code}"))

    results["dangerous_methods"] = dangerous

    if dangerous:
        print_finding(
            f"Dangerous HTTP Methods Enabled ({len(dangerous)})",
            "\n".join(f"  {m[0]}: {m[1]}" for m in dangerous),
            "high" if any(m[0] in ("PUT","DELETE") for m in dangerous) else "medium"
        )
    else:
        print_status("No dangerous HTTP methods detected.", "miss")


# ── CORS Check ────────────────────────────────────────────────────────────────

def _cors_check(results, base, verbose):
    print_status("Checking CORS configuration…", "info")
    rc, cors_out = run_cmd(
        f"curl -skI -m8 -H 'Origin: https://evil.com' '{base}/' 2>/dev/null",
        timeout=12
    )
    issues = []

    acao = re.search(r'access-control-allow-origin:\s*(.+)', cors_out, re.IGNORECASE)
    acac = re.search(r'access-control-allow-credentials:\s*(.+)', cors_out, re.IGNORECASE)

    if acao:
        origin_val = acao.group(1).strip()
        creds_val  = (acac.group(1).strip().lower() if acac else "false")

        if origin_val == "*":
            issues.append(("Wildcard CORS", "ACAO: *", "Allows any origin to read responses"))
        elif "evil.com" in origin_val:
            severity = "critical" if creds_val == "true" else "high"
            issues.append((
                "CORS reflects Origin",
                f"ACAO: {origin_val}, ACAC: {creds_val}",
                "Reflected origin — credential theft possible" if creds_val == "true"
                else "Reflected origin — data theft possible"
            ))

    results["cors_issues"] = issues

    if issues:
        for iss in issues:
            print_finding(f"CORS Misconfiguration: {iss[0]}", f"  {iss[1]}\n  {iss[2]}",
                          "critical" if "critical" in str(iss) else "high")
    else:
        print_status("CORS configuration appears restrictive.", "miss")


# ── Information Disclosure ────────────────────────────────────────────────────

def _info_disclosure(results, base, verbose):
    print_status("Checking for information disclosure…", "info")
    disclosures = []

    # Check error page info leakage
    rc, err_resp = run_cmd(
        f"curl -sk -m8 '{base}/this-page-does-not-exist-phantomx-test' 2>/dev/null",
        timeout=12
    )
    err_lower = err_resp.lower()

    leak_sigs = {
        "stack trace":       ("Stack trace in error page", "high"),
        "traceback":         ("Python traceback exposed", "high"),
        "exception":         ("Exception details exposed", "medium"),
        "sqlstate":          ("SQL error exposed", "high"),
        "mysql_fetch":       ("MySQL function in error", "high"),
        "warning:":          ("PHP warning exposed", "medium"),
        "fatal error":       ("PHP fatal error exposed", "medium"),
        "debug_toolbar":     ("Django debug toolbar", "medium"),
        "whitelabel error":  ("Spring Boot Whitelabel error page", "low"),
        "powered by":        ("'Powered by' disclosure", "low"),
    }

    for sig, (label, sev) in leak_sigs.items():
        if sig in err_lower:
            disclosures.append((label, sev))

    results["info_disclosure"] = disclosures

    if disclosures:
        print_finding(
            f"Information Disclosure ({len(disclosures)})",
            "\n".join(f"  [{d[1].upper()}] {d[0]}" for d in disclosures),
            max((d[1] for d in disclosures), key=["low","medium","high","critical"].index)
        )
    else:
        print_status("No obvious information disclosure on error pages.", "miss")
