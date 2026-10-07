"""
plugins/recon.py — Passive & Active Reconnaissance Module

Passive Techniques (no direct target contact):
  1.  DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR)
  2.  Zone transfer attempt (AXFR/IXFR)
  3.  Subdomain brute-force (wordlist-based)
  4.  Reverse DNS (PTR) sweep on discovered subnets
  5.  Certificate Transparency log mining (crt.sh)
  6.  WHOIS / ASN lookup
  7.  Google dork hints generator
  8.  SPF / DMARC / DKIM policy extraction
  9.  Autonomous System Number (ASN) → IP range mapping
  10. Shodan query hints (no API key needed)

Active Techniques (direct target contact):
  11. DNS cache snooping (non-recursive query)
  12. Wildcard DNS detection
  13. DNS security testing (DNSSEC presence, zone walking)
  14. PTR record sweep on /24 subnet
  15. HTTP/S technology fingerprinting via multiple headers
  16. WAF detection and fingerprinting
  17. CDN detection (Cloudflare, Akamai, Fastly, CloudFront)
  18. Load balancer detection (multiple A records, TTL variance)
  19. Virtual host discovery (Host header fuzzing)
  20. Email security record analysis
"""

import re
import socket
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists, read_file

# ── Subdomain wordlist ────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","ns","ww1","host","support",
    "dev","web","bbs","ww42","mx","email","cloud","1","mail1","2","forum","owa",
    "www2","gw","admin","store","mx1","cdn","api","exchange","app","gov","2tty",
    "vps","govyty","hgfgdf","cache","mysql","cpanel","whm","autodiscover","autoconfig",
    "m","imap","pop","pop3","mx2","staging","beta","direct","help","old","new",
    "corporate","proxy","crm","docs","static","assets","media","upload","img",
    "video","download","files","wiki","intranet","extranet","jenkins","gitlab",
    "jira","confluence","sonar","nexus","artifactory","vault","kibana","grafana",
    "elastic","mongo","redis","mysql","postgres","backup","archive","monitor",
    "log","logs","syslog","gateway","firewall","router","switch","core","edge",
    "internal","external","public","private","dmz","vpn2","ras","rdp","citrix",
    "remote","mobile","wireless","wifi","voip","sip","asterisk","pbx",
]

# ── WAF Fingerprint signatures ─────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":      ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF":         ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":          ["akamai", "x-akamai-transformed", "x-check-cacheable"],
    "Imperva/Incapsula":["x-iinfo", "incap_ses", "visid_incap", "incapsula"],
    "F5 BIG-IP":       ["bigipserver", "f5-", "ts=", "x-waf-event-info"],
    "Barracuda":       ["barra_counter_session", "barracuda_"],
    "Sucuri":          ["x-sucuri-id", "sucuri"],
    "ModSecurity":     ["mod_security", "modsecurity", "owasp_crs"],
    "Fastly":          ["fastly", "x-served-by", "x-cache-hits"],
    "Nginx WAF":       ["naxsi", "nginx"],
    "Palo Alto":       ["x-pan-remip"],
    "Citrix ADC":      ["ns_af", "nsspin", "citrix_ns_id"],
    "Fortinet":        ["fortigate", "fortiweb", "cookiesession1"],
}

CDN_SIGNATURES = {
    "Cloudflare":  ["cloudflare.com", "1.1.1.1"],
    "CloudFront":  ["cloudfront.net", ".cloudfront.net"],
    "Akamai":      ["akamaiedge.net", "akamaitechnologies.com"],
    "Fastly":      ["fastly.net", "fastlylb.net"],
    "Incapsula":   ["incapdns.net"],
    "Sucuri":      ["sucuri.net"],
    "KeyCDN":      ["kxcdn.com"],
    "MaxCDN":      ["netdna-cdn.com", "stackpathcdn.com"],
}

GOOGLE_DORKS = [
    'site:{domain}',
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xlsx OR filetype:csv',
    'site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin',
    'site:{domain} ext:php inurl:?',
    'site:{domain} "index of /"',
    'site:{domain} intitle:"dashboard" OR intitle:"admin"',
    '"@{domain}" email',
    'site:{domain} -www',
    'inurl:{domain} filetype:env OR filetype:config OR filetype:bak',
    'site:{domain} filetype:sql OR filetype:backup',
    'site:linkedin.com/in/ "{company}"',
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "")
    domain  = getattr(args, "domain", target)

    # If target looks like an IP, try reverse DNS to get domain
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        rc, rdns = run_cmd(f"host {domain} 2>/dev/null | head -1")
        m = re.search(r'domain name pointer (.+?)\.?\s*$', rdns)
        if m:
            domain = m.group(1).rstrip(".")
            print_status(f"Reverse DNS: {target} → {domain}", "info")

    print_status(f"Reconnaissance target: {domain or target}", "info")
    print_section("  PASSIVE RECONNAISSANCE  ")

    _whois_asn(results, domain, verbose)
    _dns_records(results, domain, verbose)
    _zone_transfer(results, domain, verbose)
    _cert_transparency(results, domain, verbose)
    _email_security(results, domain, verbose)
    _google_dork_hints(results, domain, verbose)
    _asn_ranges(results, domain, verbose)

    print_section("  ACTIVE RECONNAISSANCE  ")

    _subdomain_brute(results, domain, verbose)
    _reverse_dns_sweep(results, target, verbose)
    _wildcard_detection(results, domain, verbose)
    _waf_detection(results, target, getattr(args, "port", 80), verbose)
    _cdn_detection(results, domain, verbose)
    _vhost_discovery(results, target, domain, getattr(args, "port", 80), verbose)
    _load_balancer_detection(results, domain, verbose)
    _dns_security_check(results, domain, verbose)

    return results


# ── WHOIS / ASN ───────────────────────────────────────────────────────────────

def _whois_asn(results, domain, verbose):
    print_status("WHOIS and ASN lookup…", "info")
    rc, whois_out = run_cmd(f"whois {domain} 2>/dev/null | head -40", timeout=10)

    # Extract key fields
    fields = {}
    for field in ["Registrar", "Creation Date", "Expiry Date", "Name Server",
                  "Registrant Organization", "Admin Email", "Tech Email"]:
        m = re.search(rf'{field}[:\s]+(.+)', whois_out, re.IGNORECASE)
        if m:
            fields[field] = m.group(1).strip()[:80]

    results["whois"] = fields
    if fields and verbose:
        print_table(["Field", "Value"], list(fields.items()))
    elif fields:
        org = fields.get("Registrant Organization", "N/A")
        exp = fields.get("Expiry Date", "N/A")
        print_status(f"Registrar: {fields.get('Registrar','?')} | Org: {org} | Expiry: {exp}", "info")

    # ASN lookup
    rc2, asn_out = run_cmd(f"whois -h whois.cymru.com ' -v {domain}' 2>/dev/null | head -5", timeout=8)
    if not asn_out:
        try:
            ip = socket.gethostbyname(domain)
            rc3, asn_out = run_cmd(f"whois -h whois.cymru.com ' -v {ip}' 2>/dev/null | head -5", timeout=8)
        except Exception:
            pass
    results["asn_raw"] = asn_out
    if asn_out and verbose:
        print_status(f"ASN data: {asn_out.strip()[:100]}", "info")


# ── DNS Records ───────────────────────────────────────────────────────────────

def _dns_records(results, domain, verbose):
    print_status("Enumerating DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)…", "info")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV"]
    all_records  = {}

    for rtype in record_types:
        rc, out = run_cmd(f"dig +short {rtype} {domain} 2>/dev/null", timeout=6)
        if out.strip():
            all_records[rtype] = [l.strip() for l in out.splitlines() if l.strip()]

    results["dns_records"] = all_records

    # Display in table
    rows = []
    for rtype, values in all_records.items():
        for val in values:
            rows.append((rtype, val[:80]))
    if rows:
        print_table(["Type", "Value"], rows)

    # Flag interesting TXT records (tokens, cloud verification, etc.)
    txt_records = all_records.get("TXT", [])
    for txt in txt_records:
        if any(kw in txt.lower() for kw in ["verify", "google-site", "docusign",
                                              "atlassian", "stripe", "sendgrid"]):
            print_finding("Cloud service TXT verification found",
                          f"  {txt[:100]}\n  Reveals: third-party service usage", "info")


# ── Zone Transfer ─────────────────────────────────────────────────────────────

def _zone_transfer(results, domain, verbose):
    print_status("Attempting DNS zone transfer (AXFR)…", "info")

    # Get nameservers
    rc, ns_out = run_cmd(f"dig +short NS {domain} 2>/dev/null", timeout=6)
    nameservers = [ns.strip().rstrip(".") for ns in ns_out.splitlines() if ns.strip()]

    if not nameservers:
        print_status("No nameservers found for zone transfer.", "miss")
        results["zone_transfer"] = []
        return

    findings = []
    for ns in nameservers:
        rc, axfr = run_cmd(f"dig AXFR @{ns} {domain} 2>/dev/null", timeout=10)
        if axfr and "Transfer failed" not in axfr and len(axfr.splitlines()) > 5:
            hosts = re.findall(rf'([\w\-\.]+\.{re.escape(domain)})', axfr)
            findings.append({"ns": ns, "records": len(axfr.splitlines()),
                              "hosts": list(set(hosts))[:20]})
            print_finding(
                f"Zone Transfer SUCCESSFUL via {ns}",
                f"  {len(axfr.splitlines())} records transferred\n"
                f"  Sample hosts: {', '.join(list(set(hosts))[:5])}",
                "critical"
            )
        else:
            print_status(f"  {ns}: Zone transfer refused (expected).", "miss")

    results["zone_transfer"] = findings


# ── Certificate Transparency ──────────────────────────────────────────────────

def _cert_transparency(results, domain, verbose):
    print_status("Mining Certificate Transparency logs (crt.sh)…", "info")

    rc, ct_out = run_cmd(
        f"curl -sk -m15 'https://crt.sh/?q=%.{domain}&output=json' 2>/dev/null | "
        f"python3 -c \"import json,sys; d=json.load(sys.stdin); "
        f"[print(e.get('name_value','')) for e in d[:100]]\" 2>/dev/null",
        timeout=20
    )

    subdomains = set()
    for line in ct_out.splitlines():
        for sub in line.split("\\n"):
            sub = sub.strip().lstrip("*.")
            if sub.endswith(domain) and " " not in sub:
                subdomains.add(sub)

    results["ct_subdomains"] = sorted(subdomains)
    if subdomains:
        print_status(f"Certificate Transparency: {len(subdomains)} unique hostname(s)", "success")
        if verbose:
            for s in sorted(subdomains)[:20]:
                print(f"     {C.GREEN}↳ {s}{C.RESET}")
        else:
            print_status(f"  Sample: {', '.join(sorted(subdomains)[:5])}", "info")
    else:
        print_status("No CT log entries found (may require internet access).", "miss")


# ── Email Security Records ────────────────────────────────────────────────────

def _email_security(results, domain, verbose):
    print_status("Analysing email security records (SPF, DMARC, DKIM)…", "info")
    issues = []

    # SPF
    rc, spf = run_cmd(f"dig +short TXT {domain} 2>/dev/null | grep -i spf", timeout=6)
    if spf:
        if "+all" in spf:
            issues.append(("SPF", spf.strip()[:100], "critical",
                           "SPF +all allows ANY sender — email spoofing trivial"))
        elif "~all" in spf:
            issues.append(("SPF", spf.strip()[:100], "medium",
                           "SPF ~all (softfail) — emails may still pass"))
        elif "-all" in spf:
            print_status(f"SPF: Strict (-all) — good.", "miss")
    else:
        issues.append(("SPF", "not set", "high", "No SPF record — domain spoofable"))

    # DMARC
    rc2, dmarc = run_cmd(f"dig +short TXT _dmarc.{domain} 2>/dev/null", timeout=6)
    if dmarc:
        if "p=none" in dmarc.lower():
            issues.append(("DMARC", dmarc.strip()[:80], "medium",
                           "DMARC p=none — no enforcement, monitoring only"))
        elif "p=quarantine" in dmarc.lower():
            print_status("DMARC: p=quarantine — partial enforcement.", "miss")
        elif "p=reject" in dmarc.lower():
            print_status("DMARC: p=reject — strict enforcement.", "miss")
    else:
        issues.append(("DMARC", "not set", "high", "No DMARC — phishing/spoofing enabled"))

    results["email_security"] = issues
    if issues:
        print_finding(
            f"Email Security Issues ({len(issues)})",
            "\n".join(f"  [{i[2].upper()}] {i[0]}: {i[3]}" for i in issues),
            "high" if any(i[2] in ("high","critical") for i in issues) else "medium"
        )


# ── Google Dork Hints ─────────────────────────────────────────────────────────

def _google_dork_hints(results, domain, verbose):
    print_status("Generating Google Dork queries for manual OSINT…", "info")
    company = domain.split(".")[0]
    dorks   = [d.replace("{domain}", domain).replace("{company}", company)
                for d in GOOGLE_DORKS]
    results["google_dorks"] = dorks

    print(f"\n  {C.CYAN}{C.BOLD}Google Dork Queries (paste into Google):{C.RESET}")
    for dork in dorks:
        print(f"  {C.DIM}  {dork}{C.RESET}")
    print()


# ── ASN IP Ranges ─────────────────────────────────────────────────────────────

def _asn_ranges(results, domain, verbose):
    print_status("Fetching ASN → IP range mapping…", "info")
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        results["asn_ranges"] = []
        return

    rc, asn_out = run_cmd(
        f"whois -h whois.cymru.com ' -v {ip}' 2>/dev/null | tail -1",
        timeout=8
    )
    asn_num = ""
    m = re.search(r'\|\s*(\d+)\s*\|', asn_out)
    if m:
        asn_num = m.group(1)

    ip_ranges = []
    if asn_num:
        rc2, prefix_out = run_cmd(
            f"whois -h whois.radb.net -- '-i origin AS{asn_num}' 2>/dev/null | "
            f"grep -i 'route:' | awk '{{print $2}}'",
            timeout=10
        )
        ip_ranges = [l.strip() for l in prefix_out.splitlines() if l.strip()]

    results["asn_ranges"] = {"asn": asn_num, "ranges": ip_ranges[:20]}
    if ip_ranges:
        print_status(f"ASN{asn_num}: {len(ip_ranges)} IP range(s) found", "info")
        if verbose:
            for r in ip_ranges[:10]:
                print(f"     {C.DIM}{r}{C.RESET}")
    else:
        print_status(f"Target IP: {ip} (ASN lookup requires internet)", "info")


# ── Subdomain Brute-Force ─────────────────────────────────────────────────────

def _subdomain_brute(results, domain, verbose):
    if not domain or "." not in domain:
        results["subdomains"] = []
        return

    print_status(f"Subdomain brute-force ({len(SUBDOMAIN_WORDLIST)} entries, 30 threads)…", "info")
    found = []

    def resolve(sub):
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            ips = socket.gethostbyname_ex(fqdn)[2]
            return (fqdn, ips)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(resolve, s) for s in SUBDOMAIN_WORDLIST]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                found.append(r)

    found.sort(key=lambda x: x[0])
    results["subdomains"] = found

    if found:
        print_finding(
            f"Subdomains Discovered ({len(found)})",
            "\n".join(f"  {f[0]:<40} → {', '.join(f[1])}" for f in found),
            "info"
        )
        rows = [(f[0], ', '.join(f[1][:2])) for f in found]
        print_table(["Subdomain", "IP(s)"], rows)
    else:
        print_status("No subdomains found via brute-force.", "miss")


# ── Reverse DNS Sweep ─────────────────────────────────────────────────────────

def _reverse_dns_sweep(results, target, verbose):
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        results["reverse_dns"] = []
        return

    print_status(f"Reverse DNS sweep on /24 subnet of {target}…", "info")
    prefix = ".".join(target.split(".")[:3])
    ptr_records = []

    def ptr_lookup(i):
        ip = f"{prefix}.{i}"
        try:
            socket.setdefaulttimeout(1.5)
            hostname = socket.gethostbyaddr(ip)[0]
            return (ip, hostname)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(ptr_lookup, i) for i in range(1, 255)]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                ptr_records.append(r)

    ptr_records.sort(key=lambda x: int(x[0].split(".")[-1]))
    results["reverse_dns"] = ptr_records
    print_status(f"PTR records found: {len(ptr_records)}", "info")
    if ptr_records:
        print_table(["IP", "Hostname"], ptr_records[:20])


# ── Wildcard DNS Detection ────────────────────────────────────────────────────

def _wildcard_detection(results, domain, verbose):
    print_status("Testing for wildcard DNS…", "info")
    random_sub = f"phantomx-test-{int(__import__('time').time())}.{domain}"
    try:
        socket.setdefaulttimeout(3)
        ip = socket.gethostbyname(random_sub)
        results["wildcard_dns"] = {"detected": True, "ip": ip}
        print_finding(
            f"Wildcard DNS Detected",
            f"  *.{domain} resolves to {ip}\n"
            f"  Subdomain brute-force results may include false positives.",
            "medium"
        )
    except Exception:
        results["wildcard_dns"] = {"detected": False}
        print_status("No wildcard DNS detected.", "miss")


# ── WAF Detection ─────────────────────────────────────────────────────────────

def _waf_detection(results, target, port, verbose):
    print_status("Detecting WAF / security appliances…", "info")
    scheme = "https" if port in (443, 8443) else "http"

    # Probe 1: Normal request headers
    rc, normal_hdrs = run_cmd(
        f"curl -skI -m8 '{scheme}://{target}:{port}/' 2>/dev/null",
        timeout=12
    )
    # Probe 2: Malicious UA + XSS payload to trigger WAF
    rc2, waf_resp = run_cmd(
        f"curl -skI -m8 "
        f"-H 'User-Agent: () {{ :; }}; /bin/bash -c id' "
        f"'{scheme}://{target}:{port}/?q=<script>alert(1)</script>' 2>/dev/null",
        timeout=12
    )

    detected = []
    all_headers = (normal_hdrs + waf_resp).lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in all_headers for sig in sigs):
            detected.append(waf_name)

    # Check if WAF is blocking the malicious request
    rc_blocked = re.search(r'^HTTP/\d[\.\d]* (403|406|429|501|999)',
                           waf_resp, re.MULTILINE)
    if rc_blocked and not detected:
        detected.append(f"Unknown WAF (blocking — HTTP {rc_blocked.group(1)})")

    results["waf"] = detected
    if detected:
        print_finding(
            f"WAF/Security Appliance Detected: {', '.join(detected)}",
            "  WAF is present — consider evasion techniques in testing.\n"
            "  Standard bypasses: encoding, case variation, chunked transfer.",
            "info"
        )
    else:
        print_status("No WAF detected (or WAF is not revealing itself).", "miss")


# ── CDN Detection ─────────────────────────────────────────────────────────────

def _cdn_detection(results, domain, verbose):
    print_status("Detecting CDN / reverse proxy…", "info")
    detected = []

    # Check CNAME chain
    rc, cname_out = run_cmd(f"dig CNAME {domain} +short 2>/dev/null", timeout=6)
    for cdn, sigs in CDN_SIGNATURES.items():
        if any(sig in cname_out.lower() for sig in sigs):
            detected.append(f"{cdn} (CNAME)")

    # Check response headers
    rc2, headers = run_cmd(f"curl -skI -m8 'http://{domain}/' 2>/dev/null", timeout=12)
    for cdn, sigs in CDN_SIGNATURES.items():
        if any(sig in headers.lower() for sig in sigs):
            if cdn not in detected:
                detected.append(f"{cdn} (headers)")

    results["cdn"] = detected
    if detected:
        print_status(f"CDN/Reverse Proxy: {', '.join(detected)}", "info")
        print_finding(
            "CDN Detected — Real IP May Be Hidden",
            "  Bypass techniques: historical DNS, email headers, SSL certs,\n"
            "  SecurityTrails, Shodan, censys.io, favicon hash search.",
            "info"
        )
    else:
        print_status("No CDN/reverse proxy detected.", "miss")


# ── Virtual Host Discovery ────────────────────────────────────────────────────

def _vhost_discovery(results, target, domain, port, verbose):
    print_status("Virtual host (vhost) discovery via Host header fuzzing…", "info")
    scheme   = "https" if port in (443, 8443) else "http"
    subdomains = results.get("subdomains", [])
    vhosts_to_try = [s[0] for s in subdomains[:20]]

    # Also try from CT subdomains
    vhosts_to_try += results.get("ct_subdomains", [])[:20]

    if not vhosts_to_try:
        vhosts_to_try = [f"{s}.{domain}" for s in SUBDOMAIN_WORDLIST[:20]]

    # Get baseline response size
    rc0, base_resp = run_cmd(
        f"curl -sk -m8 -o /dev/null -w '%{{size_download}} %{{http_code}}' "
        f"'{scheme}://{target}:{port}/' 2>/dev/null",
        timeout=12
    )
    parts      = base_resp.strip().split()
    base_size  = int(parts[0]) if parts else 0
    base_code  = parts[1] if len(parts) > 1 else "0"

    found_vhosts = []
    def check_vhost(vhost):
        rc, resp = run_cmd(
            f"curl -sk -m6 -o /dev/null -w '%{{size_download}} %{{http_code}}' "
            f"-H 'Host: {vhost}' '{scheme}://{target}:{port}/' 2>/dev/null",
            timeout=8
        )
        parts = resp.strip().split()
        size  = int(parts[0]) if parts else 0
        code  = parts[1] if len(parts) > 1 else "0"
        # Different response = different vhost
        if code not in ("000","") and abs(size - base_size) > 100:
            return (vhost, code, size)
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(check_vhost, v) for v in vhosts_to_try[:40]]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                found_vhosts.append(r)

    results["vhosts"] = found_vhosts
    if found_vhosts:
        print_finding(
            f"Virtual Hosts Found ({len(found_vhosts)})",
            "\n".join(f"  {v[0]} → HTTP {v[1]} ({v[2]} bytes)" for v in found_vhosts),
            "medium"
        )
    else:
        print_status("No additional virtual hosts discovered.", "miss")


# ── Load Balancer Detection ───────────────────────────────────────────────────

def _load_balancer_detection(results, domain, verbose):
    print_status("Checking for load balancers / multiple backends…", "info")
    try:
        all_ips = socket.getaddrinfo(domain, None)
        ips     = list(set(info[4][0] for info in all_ips))
    except Exception:
        ips = []

    results["resolved_ips"] = ips
    if len(ips) > 1:
        print_finding(
            f"Multiple IPs — Load Balancer or Anycast Detected",
            f"  {domain} resolves to: {', '.join(ips)}",
            "info"
        )
    elif ips:
        print_status(f"{domain} → {ips[0]}", "info")


# ── DNS Security Check ────────────────────────────────────────────────────────

def _dns_security_check(results, domain, verbose):
    print_status("Testing DNS security configuration…", "info")
    issues = []

    # DNSSEC
    rc, dnssec = run_cmd(f"dig +dnssec A {domain} 2>/dev/null | grep -c 'RRSIG'", timeout=6)
    if rc != 0 or dnssec.strip() == "0":
        issues.append(("DNSSEC", "not enabled", "medium",
                       "DNSSEC not enabled — DNS responses can be spoofed"))

    # DNS over HTTPS / DNS over TLS hints
    rc2, doh = run_cmd(f"dig _dns.resolver.arpa TXT 2>/dev/null", timeout=5)

    # Open resolver check
    rc3, open_res = run_cmd(
        f"dig @{domain} google.com A +short 2>/dev/null | head -3",
        timeout=6
    )
    if open_res.strip():
        issues.append(("Open Resolver", domain, "medium",
                       "DNS server allows recursive queries from internet"))

    results["dns_security"] = issues
    if issues:
        print_finding(
            f"DNS Security Issues ({len(issues)})",
            "\n".join(f"  [{i[2].upper()}] {i[0]}: {i[3]}" for i in issues),
            "medium"
        )
    else:
        print_status("DNS security configuration appears adequate.", "miss")
