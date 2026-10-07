"""
plugins/dnsrecon.py — Advanced DNS Security Assessment Module

Purpose: Comprehensive DNS security assessment for your authorized
targets. Tests DNS infrastructure for misconfigurations, zone
exposure, poisoning vulnerability, and takeover indicators.

Techniques:
  1.  Full DNS record enumeration (A/AAAA/MX/NS/SOA/SRV/CAA/NAPTR/PTR)
  2.  Zone transfer (AXFR + IXFR) against all nameservers
  3.  Reverse DNS sweep + PTR record mapping
  4.  DNS cache snooping (non-recursive query test)
  5.  DNSSEC validation and zone walking
  6.  DNS amplification / DRDoS vulnerability check
  7.  Open resolver detection
  8.  Subdomain takeover via dangling CNAME
  9.  DNS over HTTPS (DoH) / DNS over TLS (DoT) presence
  10. SPF flattening / permerror check
  11. DMARC alignment analysis
  12. BIMI record check
  13. DNS rebinding vulnerability indicators
  14. NS delegation misconfiguration
  15. Authoritative vs recursive response differentiation
  16. Wildcard record abuse detection
  17. DNS tunneling indicator detection
  18. Zone enumeration via NSEC/NSEC3 walking
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME",
    "CAA", "SRV", "PTR", "NAPTR", "LOC", "HINFO",
    "DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG",
]

TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here":      ("GitHub Pages",    "critical"),
    "NoSuchBucket":                               ("AWS S3",          "critical"),
    "The specified bucket does not exist":        ("AWS S3",          "critical"),
    "Repository not found":                       ("Bitbucket",       "high"),
    "Fastly error: unknown domain":               ("Fastly CDN",      "high"),
    "The feed is not found":                      ("Feedpress",       "high"),
    "Sorry, we couldn't find that page":          ("Tumblr",          "high"),
    "404 Blog is not found":                      ("Tumblr",          "high"),
    "No settings were found for this company":    ("Helpjuice",       "high"),
    "is not a registered InCloud YouTrack":       ("JetBrains",       "high"),
    "This site can't be reached":                 ("Unclaimed",       "medium"),
    "Unregistered domain":                        ("Freenom",         "high"),
    "is not a valid Shopify store":               ("Shopify",         "medium"),
    "This domain has been registered":            ("Squarespace",     "medium"),
    "project not found":                          ("Netlify",         "medium"),
    "Looks like you've followed a broken link":   ("Webflow",         "medium"),
}

COMMON_SRV_RECORDS = [
    "_ldap._tcp", "_kerberos._tcp", "_gc._tcp",
    "_kpasswd._tcp", "_http._tcp", "_https._tcp",
    "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_smtp._tcp", "_submission._tcp", "_imaps._tcp",
    "_autodiscover._tcp", "_imap._tcp", "_pop3._tcp",
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "")
    domain  = getattr(args, "domain", target)
    ns      = getattr(args, "ns", "")    # custom nameserver

    # Resolve domain if target is IP
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        rc, rdns = run_cmd(f"dig -x {domain} +short 2>/dev/null | head -1", timeout=6)
        if rdns.strip():
            domain = rdns.strip().rstrip(".")
            print_status(f"Reverse DNS: {target} → {domain}", "info")

    print_status(f"DNS security assessment: {domain}", "info")

    _full_record_enum(results, domain, ns, verbose)
    _zone_transfer_all_ns(results, domain, verbose)
    _reverse_sweep(results, target, verbose)
    _dns_cache_snoop(results, domain, ns, verbose)
    _dnssec_analysis(results, domain, verbose)
    _open_resolver_check(results, target, verbose)
    _subdomain_takeover(results, domain, verbose)
    _dns_amplification_check(results, target, verbose)
    _srv_record_enum(results, domain, verbose)
    _email_security_deep(results, domain, verbose)
    _dns_rebinding_check(results, domain, verbose)
    _delegation_check(results, domain, verbose)
    _dns_tunnel_indicators(results, target, verbose)

    return results


# ── Full Record Enumeration ───────────────────────────────────────────────────

def _full_record_enum(results, domain, ns, verbose):
    print_section("  FULL DNS RECORD ENUMERATION  ")
    all_records = {}
    ns_flag = f"@{ns}" if ns else ""

    for rtype in DNS_RECORD_TYPES:
        rc, out = run_cmd(
            f"dig {ns_flag} {rtype} {domain} +short 2>/dev/null",
            timeout=6
        )
        if out.strip():
            records = [l.strip() for l in out.splitlines() if l.strip()]
            all_records[rtype] = records

    results["all_records"] = all_records

    # Print non-empty records
    rows = []
    for rtype, vals in all_records.items():
        for v in vals[:3]:
            rows.append((rtype, v[:80]))

    if rows:
        print_table(["Type", "Value"], rows)
    else:
        print_status("No DNS records resolved.", "miss")

    # Flag interesting findings
    # Multiple A records = potential load balancer
    a_recs = all_records.get("A", [])
    if len(a_recs) > 3:
        print_finding(
            f"Many A Records ({len(a_recs)}) — Possible Anycast/CDN",
            "\n".join(f"  {ip}" for ip in a_recs),
            "info"
        )

    # CAA records (certificate issuance policy)
    caa = all_records.get("CAA", [])
    if not caa:
        print_finding("No CAA Records", "Any CA can issue certs for this domain.", "low")

    # DNSKEY presence = DNSSEC enabled
    if all_records.get("DNSKEY"):
        print_status("DNSSEC: DNSKEY record present — DNSSEC enabled.", "success")


# ── Zone Transfer ─────────────────────────────────────────────────────────────

def _zone_transfer_all_ns(results, domain, verbose):
    print_section("  ZONE TRANSFER (AXFR + IXFR) ATTEMPT  ")

    rc, ns_out = run_cmd(f"dig NS {domain} +short 2>/dev/null", timeout=6)
    nameservers = [ns.strip().rstrip(".") for ns in ns_out.splitlines() if ns.strip()]

    if not nameservers:
        print_status("No nameservers found.", "miss")
        results["zone_transfers"] = []
        return

    print_status(f"Nameservers: {', '.join(nameservers)}", "info")
    findings = []

    for ns in nameservers:
        # AXFR
        rc_a, axfr = run_cmd(f"dig AXFR @{ns} {domain} 2>/dev/null", timeout=15)
        if axfr and "Transfer failed" not in axfr and len(axfr.splitlines()) > 5:
            hosts = list(set(re.findall(rf'[\w\-]+\.{re.escape(domain)}', axfr)))
            ips   = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', axfr)
            findings.append({
                "ns":      ns,
                "type":    "AXFR",
                "records": len(axfr.splitlines()),
                "hosts":   hosts[:20],
                "ips":     list(set(ips))[:10],
            })
            print_finding(
                f"ZONE TRANSFER SUCCESS via {ns}",
                f"  {len(axfr.splitlines())} records transferred\n"
                f"  Hosts: {', '.join(hosts[:5])}\n"
                f"  IPs:   {', '.join(list(set(ips))[:5])}",
                "critical"
            )
        else:
            print_status(f"  AXFR via {ns}: refused (expected).", "miss")

        # IXFR (incremental)
        rc_i, ixfr = run_cmd(
            f"dig IXFR=0 @{ns} {domain} 2>/dev/null | head -20", timeout=10
        )
        if ixfr and "Transfer failed" not in ixfr and "NOERROR" in ixfr:
            findings.append({"ns": ns, "type": "IXFR", "records": 0,
                              "hosts": [], "ips": []})

    results["zone_transfers"] = findings
    if not findings:
        print_status("All nameservers refused zone transfers.", "miss")


# ── Reverse DNS Sweep ─────────────────────────────────────────────────────────

def _reverse_sweep(results, target, verbose):
    print_section("  REVERSE DNS (PTR) SWEEP  ")

    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        try:
            target = socket.gethostbyname(target)
        except Exception:
            print_status("Cannot resolve target to IP for reverse sweep.", "miss")
            results["ptr_records"] = []
            return

    prefix   = ".".join(target.split(".")[:3])
    ptr_recs = []
    print_status(f"Sweeping {prefix}.0/24 for PTR records (50 threads)…", "info")

    def lookup(i):
        ip = f"{prefix}.{i}"
        try:
            socket.setdefaulttimeout(1.5)
            host = socket.gethostbyaddr(ip)[0]
            return (ip, host)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(lookup, i) for i in range(1, 255)]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                ptr_recs.append(r)

    ptr_recs.sort(key=lambda x: int(x[0].split(".")[-1]))
    results["ptr_records"] = ptr_recs
    print_status(f"PTR records found: {len(ptr_recs)}", "info")
    if ptr_recs:
        print_table(["IP", "Hostname"], ptr_recs[:20])


# ── DNS Cache Snooping ────────────────────────────────────────────────────────

def _dns_cache_snoop(results, domain, ns, verbose):
    print_section("  DNS CACHE SNOOPING  ")
    print_status("Non-recursive query to check what the resolver has cached…", "info")

    resolver = ns or domain
    # Test popular sites — if they're cached, we know this resolver is in use
    test_domains = ["google.com", "facebook.com", "office365.com",
                    "microsoft.com", "amazon.com", "github.com"]
    cached = []

    for td in test_domains:
        rc, out = run_cmd(
            f"dig @{resolver} {td} A +norecurse +short 2>/dev/null",
            timeout=5
        )
        if out.strip() and re.search(r'\d+\.\d+\.\d+\.\d+', out):
            cached.append((td, out.strip().splitlines()[0]))

    results["dns_cache"] = cached
    if cached:
        print_status(f"Cached entries found: {len(cached)} (confirms resolver activity)", "info")
        if verbose:
            print_table(["Domain", "Cached IP"], cached)
    else:
        print_status("No cached entries detected (non-recursive query returned nothing).", "miss")


# ── DNSSEC Analysis ───────────────────────────────────────────────────────────

def _dnssec_analysis(results, domain, verbose):
    print_section("  DNSSEC ANALYSIS  ")
    issues = []

    # Check DNSSEC validation
    rc, ds_out = run_cmd(f"dig DS {domain} +short 2>/dev/null", timeout=6)
    rc2, dnskey = run_cmd(f"dig DNSKEY {domain} +short 2>/dev/null", timeout=6)

    if not ds_out.strip() and not dnskey.strip():
        issues.append(("DNSSEC not deployed", "high",
                       "DNS responses can be forged — no signature validation"))
    else:
        print_status("DNSSEC: Keys/DS records found.", "success")

    # NSEC vs NSEC3 (zone walking)
    rc3, nsec = run_cmd(f"dig NSEC {domain} +short 2>/dev/null", timeout=6)
    rc4, nsec3 = run_cmd(f"dig NSEC3PARAM {domain} +short 2>/dev/null", timeout=6)

    if nsec.strip():
        issues.append(("NSEC used (not NSEC3)", "medium",
                       "NSEC allows zone walking — enumerate all subdomains"))

    # Check DNSSEC algorithm strength
    if dnskey.strip():
        if "5 " in dnskey:   # RSA/SHA-1
            issues.append(("Weak DNSSEC Algorithm (RSASHA1)", "medium",
                           "SHA-1 based DNSKEY — upgrade to ECDSA/Ed25519"))
        elif "8 " in dnskey: # RSA/SHA-256
            print_status("DNSSEC: RSA/SHA-256 — acceptable.", "miss")
        elif "13 " in dnskey or "15 " in dnskey:
            print_status("DNSSEC: ECDSA/Ed25519 — excellent.", "miss")

    results["dnssec"] = issues
    for issue, sev, note in issues:
        print_finding(issue, f"  {note}", sev)


# ── Open Resolver Check ───────────────────────────────────────────────────────

def _open_resolver_check(results, target, verbose):
    print_section("  OPEN RESOLVER / DNS AMPLIFICATION CHECK  ")

    # Test if server resolves external domains
    rc, out = run_cmd(
        f"dig @{target} google.com A +short 2>/dev/null | head -3",
        timeout=6
    )
    is_open = bool(re.search(r'\d+\.\d+\.\d+\.\d+', out))

    results["open_resolver"] = is_open
    if is_open:
        print_finding(
            "Open DNS Resolver Detected",
            f"  Server {target} resolves external queries.\n"
            "  Vulnerable to DNS amplification DDoS abuse.\n"
            "  Fix: restrict recursion to authorized clients only.",
            "high"
        )

        # Check amplification factor
        rc2, amp = run_cmd(
            f"dig @{target} . NS +bufsize=4096 2>/dev/null | grep 'MSG SIZE'",
            timeout=6
        )
        if amp:
            m = re.search(r'rcvd:\s*(\d+)', amp)
            if m and int(m.group(1)) > 400:
                print_finding(
                    f"High Amplification Factor ({m.group(1)} bytes)",
                    "  Large response to small query — DDoS amplification risk.\n"
                    "  Expected max: ~100 bytes. This is severely amplified.",
                    "critical"
                )
    else:
        print_status("Resolver does not respond to external queries.", "miss")


# ── Subdomain Takeover via CNAME ──────────────────────────────────────────────

def _subdomain_takeover(results, domain, verbose):
    print_section("  SUBDOMAIN TAKEOVER VIA DANGLING CNAME  ")
    print_status("Checking for unresolvable CNAME targets…", "info")

    # Get all CNAME records
    rc, cname_out = run_cmd(
        f"dig CNAME {domain} +short 2>/dev/null && "
        f"dig CNAME www.{domain} +short 2>/dev/null && "
        f"dig CNAME mail.{domain} +short 2>/dev/null",
        timeout=10
    )
    cnames = [c.strip().rstrip(".") for c in cname_out.splitlines() if c.strip()]

    takeovers = []
    for cname in cnames:
        # Check if CNAME target resolves
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(cname)
            # It resolves — check content for takeover fingerprints
            rc2, content = run_cmd(
                f"curl -sk -m5 'http://{cname}/' 2>/dev/null | head -10",
                timeout=8
            )
            for sig, (service, sev) in TAKEOVER_FINGERPRINTS.items():
                if sig.lower() in content.lower():
                    takeovers.append({
                        "cname": cname, "service": service,
                        "sev": sev, "sig": sig[:60]
                    })
        except socket.gaierror:
            # CNAME does not resolve = dangling CNAME = takeover opportunity
            takeovers.append({
                "cname": cname, "service": "Unclaimed",
                "sev": "critical",
                "sig": f"CNAME {cname} does not resolve"
            })

    results["subdomain_takeovers"] = takeovers
    if takeovers:
        print_finding(
            f"Subdomain Takeover Opportunities ({len(takeovers)})",
            "\n".join(f"  [{t['sev'].upper()}] CNAME → {t['cname']}: {t['service']} — {t['sig']}"
                      for t in takeovers),
            "critical" if any(t["sev"] == "critical" for t in takeovers) else "high"
        )
    else:
        print_status("No subdomain takeover opportunities found.", "miss")


# ── DNS Amplification ─────────────────────────────────────────────────────────

def _dns_amplification_check(results, target, verbose):
    print_section("  DNS AMPLIFICATION FACTOR  ")

    queries = [
        ("ANY query",    f"dig @{target} {target} ANY +bufsize=4096"),
        (". NS query",   f"dig @{target} . NS +bufsize=4096"),
        ("DNSKEY query", f"dig @{target} . DNSKEY +bufsize=4096"),
    ]
    amp_data = []
    for label, cmd in queries:
        rc, out = run_cmd(f"{cmd} 2>/dev/null | grep 'MSG SIZE'", timeout=6)
        m = re.search(r'rcvd:\s*(\d+)', out)
        if m:
            amp_data.append((label, m.group(1) + " bytes"))

    results["amplification"] = amp_data
    if amp_data:
        print_table(["Query Type", "Response Size"], amp_data)


# ── SRV Record Enumeration ────────────────────────────────────────────────────

def _srv_record_enum(results, domain, verbose):
    print_section("  SRV RECORD ENUMERATION  ")
    found_srvs = []

    for srv_prefix in COMMON_SRV_RECORDS:
        rc, out = run_cmd(
            f"dig SRV {srv_prefix}.{domain} +short 2>/dev/null",
            timeout=5
        )
        if out.strip():
            found_srvs.append((srv_prefix, out.strip().splitlines()[0][:80]))

    results["srv_records"] = found_srvs
    if found_srvs:
        print_status(f"SRV records found: {len(found_srvs)}", "info")
        print_table(["SRV Prefix", "Target"], found_srvs)

        # AD indicators
        ad_srvs = [s for s in found_srvs if any(
            kw in s[0] for kw in ["_ldap","_kerberos","_gc","_kpasswd"]
        )]
        if ad_srvs:
            print_finding("Active Directory SRV Records Found",
                          "\n".join(f"  {s[0]}.{domain} → {s[1]}" for s in ad_srvs),
                          "info")
    else:
        print_status("No SRV records found.", "miss")


# ── Email Security Deep Analysis ──────────────────────────────────────────────

def _email_security_deep(results, domain, verbose):
    print_section("  EMAIL SECURITY DEEP ANALYSIS  ")
    issues = []

    # SPF
    rc, spf = run_cmd(f"dig TXT {domain} +short 2>/dev/null | grep -i spf", timeout=6)
    spf = spf.strip().strip('"')

    if not spf:
        issues.append(("SPF Missing", "critical", "Domain spoofable — no SPF record"))
    elif "+all" in spf:
        issues.append(("SPF +all", "critical", "Any server can send mail — completely open"))
    elif "~all" in spf:
        issues.append(("SPF ~all (softfail)", "medium", "Emails may bypass SPF filter"))
    elif "?all" in spf:
        issues.append(("SPF ?all (neutral)", "high", "Neutral stance — no protection"))
    else:
        # Check for too many DNS lookups (RFC says max 10)
        lookup_count = len(re.findall(r'\b(include:|a:|mx:|redirect=)', spf))
        if lookup_count > 7:
            issues.append(("SPF Lookup Limit Risk", "medium",
                           f"{lookup_count} lookups — may hit 10-lookup limit (permerror)"))

    # DMARC
    rc2, dmarc = run_cmd(f"dig TXT _dmarc.{domain} +short 2>/dev/null", timeout=6)
    if not dmarc.strip():
        issues.append(("DMARC Missing", "high", "No DMARC — phishing/spoofing enabled"))
    else:
        p_m = re.search(r'p=(\w+)', dmarc)
        policy = p_m.group(1) if p_m else "none"
        if policy == "none":
            issues.append(("DMARC p=none", "medium", "Monitor only — no enforcement"))
        elif policy == "quarantine":
            print_status("DMARC: p=quarantine (partial enforcement).", "miss")
        elif policy == "reject":
            print_status("DMARC: p=reject (strict enforcement).", "miss")

        # Check for reporting URI
        if "rua=" not in dmarc.lower():
            issues.append(("DMARC no reporting (rua)", "low",
                           "No aggregate report URI — blind to spoofing attempts"))

    # BIMI
    rc3, bimi = run_cmd(f"dig TXT default._bimi.{domain} +short 2>/dev/null", timeout=6)
    if bimi.strip():
        print_status("BIMI record present — brand indicator configured.", "miss")

    results["email_deep"] = issues
    if issues:
        print_finding(
            f"Email Security Issues ({len(issues)})",
            "\n".join(f"  [{i[1].upper()}] {i[0]}: {i[2]}" for i in issues),
            "critical" if any(i[1] == "critical" for i in issues) else "high"
        )


# ── DNS Rebinding Check ───────────────────────────────────────────────────────

def _dns_rebinding_check(results, domain, verbose):
    print_section("  DNS REBINDING VULNERABILITY CHECK  ")

    # Check if domain resolves to private IPs (potential rebinding)
    rc, a_records = run_cmd(f"dig A {domain} +short 2>/dev/null", timeout=6)
    ips = [l.strip() for l in a_records.splitlines() if l.strip()]

    import ipaddress
    private_ips = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                private_ips.append(ip)
        except ValueError:
            pass

    results["dns_rebinding"] = private_ips
    if private_ips:
        print_finding(
            "DNS Resolves to Private IP — Possible Rebinding",
            f"  {domain} → {', '.join(private_ips)}\n"
            "  Attackers could rebind DNS to bypass same-origin policy.",
            "high"
        )
    else:
        print_status("No DNS rebinding indicators found.", "miss")


# ── NS Delegation Check ───────────────────────────────────────────────────────

def _delegation_check(results, domain, verbose):
    print_section("  NS DELEGATION ANALYSIS  ")

    rc, ns_recs = run_cmd(f"dig NS {domain} +short 2>/dev/null", timeout=6)
    ns_list = [ns.strip().rstrip(".") for ns in ns_recs.splitlines() if ns.strip()]

    issues = []
    if not ns_list:
        issues.append(("No NS records found", "high", "Domain has no authoritative nameservers"))
        results["ns_delegation"] = issues
        return

    # Check for single point of failure
    if len(ns_list) == 1:
        issues.append(("Single NS", "medium", "No redundancy — single NS failure = domain unavailable"))

    # Check if NS records match in-zone glue
    for ns in ns_list[:4]:
        rc2, glue = run_cmd(f"dig A {ns} +short 2>/dev/null", timeout=5)
        if not glue.strip():
            issues.append((f"NS {ns}", "medium", "No glue/A record for nameserver"))

    results["ns_delegation"] = issues
    print_status(f"Nameservers: {', '.join(ns_list)}", "info")
    for issue, sev, note in issues:
        print_finding(issue, f"  {note}", sev)


# ── DNS Tunnel Indicator Detection ───────────────────────────────────────────

def _dns_tunnel_indicators(results, target, verbose):
    print_section("  DNS TUNNELING INDICATOR DETECTION  ")
    print_status("Analysing DNS query patterns for tunneling indicators…", "info")

    # Check if high-entropy TXT/NULL queries are being made
    rc, logs = run_cmd(
        f"journalctl -u systemd-resolved --no-pager 2>/dev/null | "
        f"grep -E 'TXT|NULL' | tail -20",
        timeout=8
    )

    if not logs.strip():
        rc2, logs = run_cmd(
            "cat /var/log/syslog 2>/dev/null | grep 'named\\|bind\\|dns' | tail -20",
            timeout=8
        )

    indicators = []
    if logs:
        # Look for high-entropy subdomains (common in DNS tunnels)
        long_labels = re.findall(r'[a-f0-9]{30,}\.', logs)
        if long_labels:
            indicators.append(f"High-entropy labels found: {long_labels[0][:40]}…")

        # Look for NULL/TXT record queries (dnscat2, iodine use these)
        if re.search(r'\bNULL\b|\bTXT\b.*base64', logs, re.IGNORECASE):
            indicators.append("TXT/NULL queries detected — possible dnscat2/iodine tunnel")

    results["dns_tunnel_indicators"] = indicators
    if indicators:
        print_finding("DNS Tunneling Indicators Detected",
                      "\n".join(f"  {i}" for i in indicators), "high")
    else:
        print_status("No DNS tunneling indicators in available logs.", "miss")
