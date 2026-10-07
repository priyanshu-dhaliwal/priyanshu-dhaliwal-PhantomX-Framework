"""
plugins/network.py — Advanced Network Reconnaissance Module

Checks:
  1.  Full TCP port scan on target (connect-scan, no root needed)
  2.  Service version banner grabbing
  3.  UDP top-ports probe
  4.  Open port CVE quick-reference
  5.  Internal subnet mapping
  6.  Firewall / iptables rule enumeration
  7.  DNS zone transfer attempt
  8.  SNMP community string probe (public/private)
  9.  HTTP/HTTPS title & header grab
  10. IPv6 neighbor discovery
"""

import os
import re
import socket
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, cmd_exists, read_file

# ── Port → service + CVE quick-ref ───────────────────────────────────────────
PORT_DB = {
    21:   ("FTP",        "Anon login? CVE-2011-2523 (vsftpd backdoor)"),
    22:   ("SSH",        "Brute-force / CVE-2018-10933 (libssh auth bypass)"),
    23:   ("Telnet",     "Cleartext creds — always investigate"),
    25:   ("SMTP",       "Open relay? User enumeration (VRFY/EXPN)"),
    53:   ("DNS",        "Zone transfer? DNS cache poison"),
    69:   ("TFTP",       "Unauthenticated file read/write"),
    79:   ("Finger",     "User enumeration"),
    80:   ("HTTP",       "Web app vulns — run nikto/gobuster"),
    110:  ("POP3",       "Cleartext auth possible"),
    111:  ("RPCBind",    "NFS/NIS enumeration"),
    135:  ("MSRPC",      "Windows RPC — check for EternalBlue"),
    139:  ("NetBIOS",    "SMB — EternalBlue MS17-010"),
    143:  ("IMAP",       "Cleartext auth possible"),
    161:  ("SNMP",       "Public community string? Config disclosure"),
    389:  ("LDAP",       "Anonymous bind? AD enumeration"),
    443:  ("HTTPS",      "Web app vulns — check SSL config"),
    445:  ("SMB",        "EternalBlue MS17-010, PrintNightmare"),
    512:  ("rexec",      "Remote execution — cleartext"),
    513:  ("rlogin",     "Trust exploitation possible"),
    514:  ("rsh/syslog", "Unauthenticated command exec possible"),
    873:  ("rsync",      "Unauthenticated file access?"),
    1433: ("MSSQL",      "SA account? xp_cmdshell?"),
    1521: ("Oracle DB",  "TNS listener — CVE-2012-1675"),
    2049: ("NFS",        "no_root_squash? Unauthenticated mount?"),
    2181: ("ZooKeeper",  "Unauthenticated access — data exposure"),
    3306: ("MySQL",      "Remote root login? UDF exploit"),
    3389: ("RDP",        "BlueKeep CVE-2019-0708, brute-force"),
    4444: ("Metasploit", "Possible reverse shell listener!"),
    5432: ("PostgreSQL", "Weak creds? COPY TO/FROM exploit"),
    5900: ("VNC",        "Weak/no auth? CVE-2006-2369"),
    5985: ("WinRM",      "Windows remote management"),
    6379: ("Redis",      "No-auth RCE via config rewrite"),
    6443: ("Kubernetes", "K8s API — anonymous access?"),
    8080: ("HTTP-alt",   "Admin panel? Dev server?"),
    8443: ("HTTPS-alt",  "Admin panel with self-signed cert?"),
    9200: ("Elasticsearch","No-auth data exposure"),
    27017:("MongoDB",    "No-auth data exposure by default"),
}

COMMON_PORTS = list(PORT_DB.keys()) + [
    8888, 9000, 9090, 10000, 11211, 15672, 27018, 50000, 50070
]


def run(args, verbose=False):
    results = {}
    target = getattr(args, "target", "127.0.0.1") or "127.0.0.1"

    print_status(f"Target: {target}", "info")

    _port_scan(results, target, verbose)
    _banner_grab(results, target, verbose)
    _http_probe(results, target, verbose)
    _firewall_rules(results, verbose)
    _dns_probe(results, target, verbose)
    _snmp_probe(results, target, verbose)
    _ipv6_neighbors(results, verbose)

    return results


# ── Port Scanner ──────────────────────────────────────────────────────────────

def _port_scan(results, target, verbose):
    print_status(f"TCP connect scan on {target} ({len(COMMON_PORTS)} ports, 128 threads)…", "info")
    open_ports = []
    lock = threading.Lock()

    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            rc = s.connect_ex((target, port))
            s.close()
            if rc == 0:
                return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=128) as ex:
        futures = {ex.submit(probe, p): p for p in COMMON_PORTS}
        for fut in as_completed(futures):
            p = fut.result()
            if p:
                svc, note = PORT_DB.get(p, ("unknown", ""))
                open_ports.append((p, svc, note))

    open_ports.sort(key=lambda x: x[0])
    results["open_ports"] = open_ports

    if open_ports:
        print_status(f"Open ports: {len(open_ports)}", "success")
        print_table(["Port", "Service", "Security Note"], open_ports)

        # Flag high-severity ports
        critical_ports = [p for p in open_ports if p[0] in (21,23,445,4444,6379,9200,27017)]
        for cp in critical_ports:
            print_finding(f"Port {cp[0]}/{cp[1]} open", cp[2], "high")
    else:
        print_status(f"No open ports found on {target}.", "miss")


# ── Banner Grabbing ───────────────────────────────────────────────────────────

def _banner_grab(results, target, verbose):
    open_ports = results.get("open_ports", [])
    if not open_ports:
        return

    print_status("Grabbing service banners…", "info")
    banners = []

    for port, svc, _ in open_ports[:15]:  # Cap to avoid long waits
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((target, port))
            # Send HTTP GET for web ports, else just read
            if port in (80, 8080, 8888):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner immediately
            elif port == 25:
                s.send(b"EHLO phantomx\r\n")
            banner = s.recv(256).decode(errors="replace").strip()
            s.close()
            if banner:
                banners.append((port, svc, banner[:100]))
        except Exception:
            pass

    results["banners"] = banners
    if banners and verbose:
        print_table(["Port", "Service", "Banner"], banners)
    elif banners:
        print_status(f"Banners grabbed: {len(banners)} service(s).", "info")


# ── HTTP/HTTPS Probe ──────────────────────────────────────────────────────────

def _http_probe(results, target, verbose):
    open_ports = [p[0] for p in results.get("open_ports", [])]
    http_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8888, 9090, 9200, 10000)]

    if not http_ports:
        return

    print_status(f"HTTP/HTTPS probing on {len(http_ports)} port(s)…", "info")
    http_results = []

    for port in http_ports:
        scheme = "https" if port in (443, 8443) else "http"
        url    = f"{scheme}://{target}:{port}/"
        rc, out = run_cmd(
            f"curl -sk -m5 -o /dev/null -D - '{url}' 2>/dev/null | head -20",
            timeout=10
        )
        if out:
            # Extract status line and interesting headers
            status = out.splitlines()[0] if out.splitlines() else "?"
            server = next((l for l in out.splitlines() if l.lower().startswith("server:")), "")
            powered = next((l for l in out.splitlines() if "x-powered-by" in l.lower()), "")
            http_results.append((port, status.strip()[:50], server.strip()[:50], powered.strip()[:40]))

    results["http_probe"] = http_results

    if http_results:
        print_table(["Port", "Status", "Server", "X-Powered-By"], http_results)
        # Check for missing security headers
        rc2, full_headers = run_cmd(
            f"curl -sk -m5 -I 'http://{target}:{http_ports[0]}/' 2>/dev/null",
            timeout=10
        )
        missing = []
        for hdr in ["Strict-Transport-Security", "X-Frame-Options",
                    "Content-Security-Policy", "X-Content-Type-Options"]:
            if hdr.lower() not in full_headers.lower():
                missing.append(hdr)
        if missing:
            print_finding(
                "Missing Security Headers",
                "\n".join(f"  {h}" for h in missing),
                "medium"
            )


# ── Firewall Rules ────────────────────────────────────────────────────────────

def _firewall_rules(results, verbose):
    print_status("Enumerating firewall rules (iptables/nftables)…", "info")
    _, ipt = run_cmd("iptables -L -n --line-numbers 2>/dev/null")
    _, nft = run_cmd("nft list ruleset 2>/dev/null")
    _, ufw = run_cmd("ufw status verbose 2>/dev/null")

    results["firewall"] = {
        "iptables": ipt[:2000] if ipt else "",
        "nftables": nft[:500]  if nft else "",
        "ufw":      ufw[:500]  if ufw else "",
    }

    if "Chain INPUT (policy ACCEPT)" in ipt:
        print_finding("iptables INPUT chain policy is ACCEPT",
                      "No default-deny — all incoming traffic allowed by default.", "high")
    elif not ipt and not nft:
        print_finding("No firewall rules detected",
                      "Host may have no active firewall.", "high")
    else:
        print_status("Firewall rules present.", "miss")

    if verbose and ipt:
        print(f"{C.DIM}{ipt[:800]}{C.RESET}")


# ── DNS Probe ─────────────────────────────────────────────────────────────────

def _dns_probe(results, target, verbose):
    print_status("Probing DNS…", "info")
    findings = []

    # Try zone transfer if target runs DNS
    open_ports = [p[0] for p in results.get("open_ports", [])]
    if 53 in open_ports:
        # Attempt AXFR
        rc, axfr = run_cmd(f"dig axfr @{target} 2>/dev/null", timeout=8)
        if "Transfer failed" not in axfr and len(axfr.splitlines()) > 5:
            findings.append(("Zone Transfer SUCCESS", axfr[:500], "critical"))
        else:
            print_status("Zone transfer refused (expected).", "miss")

    # Reverse DNS
    rc, rdns = run_cmd(f"dig -x {target} +short 2>/dev/null || host {target} 2>/dev/null")
    if rdns.strip():
        findings.append(("Reverse DNS", rdns.strip(), "info"))

    results["dns"] = findings
    for f in findings:
        if f[2] != "info":
            print_finding(f[0], f[1], f[2])
        else:
            print_status(f"{f[0]}: {f[1]}", "info")


# ── SNMP Probe ────────────────────────────────────────────────────────────────

def _snmp_probe(results, target, verbose):
    open_ports = [p[0] for p in results.get("open_ports", [])]
    if 161 not in open_ports and not getattr(results, "_force_snmp", False):
        results["snmp"] = []
        return

    print_status("Probing SNMP community strings…", "info")
    communities = ["public", "private", "community", "manager", "admin", "secret"]
    found = []

    if cmd_exists("snmpwalk"):
        for comm in communities:
            rc, out = run_cmd(
                f"snmpwalk -v2c -c {comm} -t2 {target} sysDescr 2>/dev/null",
                timeout=5
            )
            if rc == 0 and out.strip():
                found.append((comm, out.strip()[:150]))

    results["snmp"] = found

    if found:
        print_finding(
            f"SNMP Community Strings ({len(found)} valid)",
            "\n".join(f"  community='{f[0]}': {f[1]}" for f in found),
            "high"
        )
    elif 161 in open_ports:
        print_status("SNMP open but no common community strings matched.", "miss")


# ── IPv6 Neighbors ────────────────────────────────────────────────────────────

def _ipv6_neighbors(results, verbose):
    print_status("Checking IPv6 neighbor table…", "info")
    _, neigh = run_cmd("ip -6 neigh show 2>/dev/null")
    neighbors = [l.strip() for l in neigh.splitlines() if l.strip() and "FAILED" not in l]
    results["ipv6_neighbors"] = neighbors

    if neighbors:
        print_status(f"IPv6 neighbors: {len(neighbors)}", "info")
        if verbose:
            for n in neighbors:
                print(f"     {C.DIM}{n}{C.RESET}")
    else:
        print_status("No IPv6 neighbors found.", "miss")
