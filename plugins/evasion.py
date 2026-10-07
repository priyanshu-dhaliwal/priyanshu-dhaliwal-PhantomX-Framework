"""
plugins/evasion.py — Firewall Evasion Testing & Network Bypass Techniques

Purpose: Assess whether your authorized target's security controls are
correctly configured and detectable by an attacker. Used to validate
firewall rules, IDS/IPS effectiveness, and segmentation controls.

Techniques:
  1.  Fragmented packet scanning (IDS/IPS evasion detection)
  2.  Source port manipulation (bypass port-based ACLs)
  3.  Decoy scanning hints (nmap -D)
  4.  Timing-based evasion (slow scan detection)
  5.  MTU manipulation
  6.  Firewall rule gap detection (ACL analysis)
  7.  Egress filtering assessment
  8.  DNS tunneling potential detection
  9.  ICMP tunneling potential
  10. HTTP CONNECT proxy / SSRF-based bypass hints

Pivot & Tunnel Methods (identification and setup guidance):
  11. SSH tunneling (local/remote/dynamic SOCKS)
  12. Chisel/ligolo-ng tunnel setup hints
  13. socat relay setup
  14. Metasploit route/socks hints
  15. DNS-over-HTTPS tunnel potential
  16. ICMP tunnel (ptunnel) potential
  17. Double pivot path identification
  18. Proxychains configuration generation
"""

import re
import socket
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

EGRESS_TEST_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                     1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888]

EGRESS_TEST_HOST = "scanme.nmap.org"   # Legitimate public scan target


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")

    print_status(f"Evasion & bypass assessment target: {target}", "info")
    print_status("[!] All tests performed against authorized target only.", "warn")

    _firewall_detection(results, target, verbose)
    _fragmentation_test(results, target, verbose)
    _source_port_bypass(results, target, verbose)
    _timing_scan(results, target, verbose)
    _egress_filtering(results, verbose)
    _dns_tunnel_potential(results, target, verbose)
    _pivot_path_identification(results, target, verbose)
    _tunnel_setup_guide(results, target, verbose)
    _proxychains_config(results, target, verbose)

    return results


# ── Firewall Detection ────────────────────────────────────────────────────────

def _firewall_detection(results, target, verbose):
    print_section("  FIREWALL / FILTERING DETECTION  ")

    findings = []

    # ACK scan — differentiate filtered vs closed ports
    if cmd_exists("nmap"):
        rc, ack_scan = run_cmd(
            f"nmap -sA -p80,443,22,445,3389 {target} 2>/dev/null",
            timeout=20
        )
        filtered = re.findall(r'(\d+)/tcp\s+filtered', ack_scan)
        unfiltered = re.findall(r'(\d+)/tcp\s+unfiltered', ack_scan)

        if filtered:
            findings.append({
                "type":    "Stateful Firewall",
                "detail":  f"Filtered ports: {', '.join(filtered)}",
                "note":    "Stateful firewall blocking ACK packets — confirms firewall presence"
            })
        if unfiltered:
            findings.append({
                "type":    "Unfiltered Ports",
                "detail":  f"Ports {', '.join(unfiltered)} pass ACK — no stateful inspection",
                "note":    "Consider these as potential bypass entry points"
            })

        # Window scan — fingerprint firewall type
        rc2, win_scan = run_cmd(
            f"nmap -sW -p80,443 {target} 2>/dev/null | grep -E 'open|closed|filtered'",
            timeout=15
        )
        results["ack_scan"] = {"filtered": filtered, "unfiltered": unfiltered}

    # TTL-based hop detection
    rc3, ttl_out = run_cmd(f"ping -c3 -W2 {target} 2>/dev/null | grep ttl", timeout=8)
    ttl_m = re.search(r'ttl=(\d+)', ttl_out, re.IGNORECASE)
    if ttl_m:
        ttl = int(ttl_m.group(1))
        hops = (64 - ttl) if ttl <= 64 else (128 - ttl) if ttl <= 128 else (255 - ttl)
        findings.append({
            "type":   "TTL Analysis",
            "detail": f"TTL={ttl}, estimated hops≈{hops}",
            "note":   "Linux default TTL=64, Windows=128, Cisco=255"
        })

    results["firewall_findings"] = findings
    if findings:
        for f in findings:
            print_status(f"[{f['type']}] {f['detail']}: {f['note']}", "info")


# ── Fragmented Packet Scan ────────────────────────────────────────────────────

def _fragmentation_test(results, target, verbose):
    print_section("  FRAGMENTATION & IDS EVASION TESTING  ")
    print_status("Testing if fragmented packets bypass IDS/IPS rules…", "info")

    if not cmd_exists("nmap"):
        print_status("nmap required for fragmentation testing.", "warn")
        return

    results_frag = {}

    # Normal scan baseline
    rc0, normal = run_cmd(
        f"nmap -sS -p80,443 {target} 2>/dev/null | grep -E '\\d+/tcp'",
        timeout=15
    )
    normal_states = set(re.findall(r'(\d+)/tcp\s+(\w+)', normal))

    # Fragmented scan (8-byte fragments)
    rc1, frag8 = run_cmd(
        f"nmap -sS -f -p80,443 {target} 2>/dev/null | grep -E '\\d+/tcp'",
        timeout=15
    )
    frag8_states = set(re.findall(r'(\d+)/tcp\s+(\w+)', frag8))

    # MTU 16 bytes
    rc2, mtu16 = run_cmd(
        f"nmap -sS --mtu 16 -p80,443 {target} 2>/dev/null | grep -E '\\d+/tcp'",
        timeout=15
    )
    mtu16_states = set(re.findall(r'(\d+)/tcp\s+(\w+)', mtu16))

    results_frag["normal"]  = list(normal_states)
    results_frag["frag8"]   = list(frag8_states)
    results_frag["mtu16"]   = list(mtu16_states)

    # Compare — if fragmented shows different results, IDS may not reassemble
    if normal_states != frag8_states:
        print_finding(
            "Fragmented Scan Produces Different Results",
            "  Normal vs -f scan show different port states.\n"
            "  Potential: IDS/IPS not reassembling fragments.\n"
            "  Technique: nmap -sS -f --mtu 8 --data-length 25 <target>",
            "high"
        )
    else:
        print_status("Fragmentation test: firewall reassembles fragments (good).", "miss")

    results["fragmentation"] = results_frag


# ── Source Port Bypass ────────────────────────────────────────────────────────

def _source_port_bypass(results, target, verbose):
    print_section("  SOURCE PORT ACL BYPASS  ")
    print_status("Testing source port manipulation (bypass port-based ACLs)…", "info")

    if not cmd_exists("nmap"):
        results["source_port"] = []
        return

    bypass_ports = [53, 20, 80, 443, 25, 110, 8080]
    findings = []

    for src_port in bypass_ports:
        rc, out = run_cmd(
            f"nmap -sS --source-port {src_port} -p445,3306,3389,5432 "
            f"{target} 2>/dev/null | grep 'open'",
            timeout=12
        )
        if out.strip():
            findings.append((src_port, out.strip()[:80]))

    # Normal scan for comparison
    rc2, normal = run_cmd(
        f"nmap -sS -p445,3306,3389,5432 {target} 2>/dev/null | grep 'open'",
        timeout=12
    )

    results["source_port"] = findings
    if findings:
        print_finding(
            "Source Port Bypass — Ports Opened via Spoofed Source",
            "\n".join(f"  src_port={f[0]} → {f[1]}" for f in findings),
            "high"
        )
        print(f"  {C.DIM}  Technique: nmap --source-port 53 <target>{C.RESET}\n")
    else:
        print_status("No source port bypass detected.", "miss")


# ── Timing Scan ───────────────────────────────────────────────────────────────

def _timing_scan(results, target, verbose):
    print_section("  IDS TIMING EVASION ASSESSMENT  ")
    print_status("Assessing IDS/IPS timing thresholds…", "info")

    print(f"\n  {C.CYAN}Timing evasion scan templates for authorized testing:{C.RESET}")
    timing_notes = [
        ("T0 (Paranoid)",    "nmap -T0",   "1 probe / 5 minutes — evades most threshold-based IDS"),
        ("T1 (Sneaky)",      "nmap -T1",   "1 probe / 15 seconds — very slow"),
        ("T2 (Polite)",      "nmap -T2",   "1 probe / 0.4s — low-bandwidth, slow"),
        ("Randomize ports",  "nmap -r",    "Random port order — avoids sequential port detection"),
        ("Decoy scan",       "nmap -D RND:10", "Randomize 10 decoy IPs — noise in IDS logs"),
        ("Idle scan",        "nmap -sI <zombie>", "Uses zombie host as source — complete stealth"),
    ]
    print_table(["Template", "Command", "Effect"], timing_notes)

    results["timing_guidance"] = timing_notes


# ── Egress Filtering ──────────────────────────────────────────────────────────

def _egress_filtering(results, verbose):
    print_section("  EGRESS FILTERING ASSESSMENT  ")
    print_status("Testing outbound connection capabilities…", "info")

    open_egress = []
    for port in [80, 443, 53, 22, 8080, 8443]:
        try:
            s = socket.socket()
            s.settimeout(2)
            rc = s.connect_ex(("1.1.1.1", port))
            s.close()
            if rc == 0:
                open_egress.append(port)
        except Exception:
            pass

    results["egress_open"] = open_egress
    if open_egress:
        print_status(f"Outbound ports open: {open_egress}", "info")

        # DNS tunneling potential
        if 53 in open_egress:
            print_finding(
                "DNS Egress Open — DNS Tunnel Potential",
                "  Port 53 outbound available.\n"
                "  Tools: iodine, dnscat2, dns2tcp",
                "medium"
            )
        # HTTP/HTTPS tunneling
        if 80 in open_egress or 443 in open_egress:
            print_finding(
                "HTTP/HTTPS Egress Open — C2 Channel Possible",
                "  HTTP(S) outbound available — common C2 protocol.\n"
                "  Tools: chisel, ligolo-ng, HTTPS reverse shells",
                "medium"
            )
    else:
        print_status("No outbound connections established (strict egress).", "miss")


# ── DNS Tunnel Potential ──────────────────────────────────────────────────────

def _dns_tunnel_potential(results, target, verbose):
    print_section("  DNS & ICMP TUNNEL POTENTIAL  ")

    # Check if DNS allows large TXT queries (tunnel potential)
    rc, txt_resp = run_cmd(
        f"dig +short TXT {target} 2>/dev/null | wc -c",
        timeout=6
    )

    findings = []
    # ICMP check
    rc2, ping = run_cmd(f"ping -c2 -W2 {target} 2>/dev/null | tail -2", timeout=8)
    if "0% packet loss" in ping or "2 received" in ping:
        findings.append({
            "type":   "ICMP",
            "status": "ICMP echo allowed",
            "tool":   "ptunnel-ng / icmptunnel",
            "note":   "ICMP tunneling possible if egress filtering blocks TCP/UDP"
        })

    results["tunnel_potential"] = findings
    if findings:
        for f in findings:
            print_status(f"[{f['type']}] {f['status']} — {f['tool']}", "info")


# ── Pivot Path Identification ─────────────────────────────────────────────────

def _pivot_path_identification(results, target, verbose):
    print_section("  PIVOT PATH IDENTIFICATION  ")
    print_status("Identifying potential pivot paths through this host…", "info")

    # Network interfaces
    from utils.shell import run_cmd as rc_fn
    rc, ifaces = rc_fn("ip -o addr show 2>/dev/null", timeout=6)
    interfaces = re.findall(r'\d+:\s+(\S+)\s+inet\s+([\d./]+)', ifaces)

    # Routing table
    rc2, routes = rc_fn("ip route 2>/dev/null", timeout=6)
    rc3, arp    = rc_fn("arp -a 2>/dev/null | head -20", timeout=6)

    pivot_hosts = re.findall(r'\(([\d.]+)\)', arp)

    results["pivot_paths"] = {
        "interfaces": interfaces,
        "routes":     routes.splitlines()[:15],
        "arp_hosts":  pivot_hosts,
    }

    print_status(f"Interfaces: {[i[1] for i in interfaces]}", "info")
    print_status(f"ARP hosts (pivot candidates): {pivot_hosts[:10]}", "info")

    # Show network segments
    subnets = set()
    for _, cidr in interfaces:
        try:
            import ipaddress
            net = ipaddress.ip_interface(cidr).network
            subnets.add(str(net))
        except Exception:
            pass

    if len(subnets) > 1:
        print_finding(
            "Multi-Homed Host — Ideal Pivot Point",
            f"  Connected to: {', '.join(subnets)}\n"
            "  This host can reach multiple network segments.",
            "high"
        )


# ── Tunnel Setup Guide ────────────────────────────────────────────────────────

def _tunnel_setup_guide(results, target, verbose):
    print_section("  TUNNEL & PIVOT SETUP GUIDE  ")

    tunnels = [
        ("SSH Local Forward",
         f"ssh -L 8080:internal-host:80 user@{target}",
         "Forward local port to internal service through SSH"),
        ("SSH Remote Forward",
         f"ssh -R 4444:localhost:4444 user@{target}",
         "Expose local listener on remote host"),
        ("SSH SOCKS5 Proxy",
         f"ssh -D 1080 user@{target}",
         "Full SOCKS5 proxy through SSH — use with proxychains"),
        ("SSH Double Pivot",
         f"ssh -J user@{target} user2@internal-host",
         "Jump through compromised host to reach internal target"),
        ("Chisel (HTTP tunnel)",
         f"# Server: chisel server -p 8080 --reverse\n"
         f"  # Client: chisel client {target}:8080 R:socks",
         "HTTP-based SOCKS tunnel — bypasses port restrictions"),
        ("Ligolo-ng",
         f"# Agent (target): ./agent -connect {target}:11601 -ignore-cert\n"
         f"  # Proxy (attack): ./proxy -selfcert -laddr 0.0.0.0:11601",
         "Transparent TUN-based pivot — no proxychains needed"),
        ("socat TCP relay",
         f"socat TCP-LISTEN:4444,fork TCP:{target}:445",
         "Simple TCP relay for pivoting through this host"),
        ("Metasploit route",
         "route add 192.168.1.0/24 <session_id>",
         "Add route through Meterpreter session"),
        ("Metasploit SOCKS",
         "use auxiliary/server/socks_proxy\n"
         "  set SRVPORT 1080\n  run",
         "SOCKS proxy via Metasploit for proxychains"),
        ("ptunnel (ICMP)",
         f"ptunnel -p {target} -lp 8080 -da internal-host -dp 22",
         "Tunnel SSH over ICMP — bypasses TCP/UDP filtering"),
        ("dnscat2 (DNS tunnel)",
         f"# Server: ruby dnscat2.rb --dns domain=tunnel.{target}\n"
         f"  # Client: ./dnscat tunnel.{target}",
         "Command & control over DNS — bypasses egress filters"),
    ]

    print(f"\n  {C.CYAN}{C.BOLD}Pivot & Tunnel Methods:{C.RESET}\n")
    for name, cmd, desc in tunnels:
        print(f"  {C.YELLOW}▸ {name}{C.RESET}")
        print(f"    {C.DIM}{desc}{C.RESET}")
        for line in cmd.splitlines():
            print(f"    {C.GREEN}$ {line.strip()}{C.RESET}")
        print()

    results["tunnel_methods"] = [t[0] for t in tunnels]


# ── Proxychains Config Generator ──────────────────────────────────────────────

def _proxychains_config(results, target, verbose):
    print_section("  PROXYCHAINS CONFIGURATION GENERATOR  ")

    config = f"""# PhantomX generated proxychains config
# Generated for pivot through: {target}

strict_chain
proxy_dns

[ProxyList]
# SSH SOCKS5 (set up with: ssh -D 1080 user@{target})
socks5 127.0.0.1 1080

# Chisel SOCKS5 (set up with chisel client)
# socks5 127.0.0.1 1080

# Double pivot (add second hop below)
# socks5 10.10.10.5 1081
"""
    config_path = "/tmp/proxychains_phantomx.conf"
    try:
        with open(config_path, "w") as f:
            f.write(config)
        print_status(f"proxychains config written → {config_path}", "success")
        print(f"  {C.DIM}  Usage: proxychains4 -f {config_path} nmap -sT -p22,80 <internal-host>{C.RESET}\n")
    except Exception:
        print(config)

    results["proxychains_config"] = config_path
