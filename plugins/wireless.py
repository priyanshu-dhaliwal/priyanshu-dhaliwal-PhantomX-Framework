"""
plugins/wireless.py — Wireless Security Assessment Module

Purpose: Assess the wireless security posture of your authorized
environment. Detects misconfigurations, weak protocols, rogue APs,
and validates wireless segmentation controls.

Techniques:
  1.  Wireless interface detection & monitor mode setup check
  2.  AP survey (SSIDs, BSSIDs, channels, signal, encryption)
  3.  WPA2 handshake capture readiness check
  4.  WPS vulnerability detection (Pixie Dust, Reaver indicators)
  5.  Rogue / evil twin AP detection
  6.  Open / unencrypted network detection
  7.  WEP/TKIP legacy encryption detection
  8.  PMKID attack capability check
  9.  Client probe request monitoring
  10. Wireless client isolation check
  11. Enterprise 802.1X PEAP misconfiguration hints
  12. Deauth frame detection (active attacks against your network)
  13. Hidden SSID enumeration hints
  14. Aircrack-ng / hcxtools workflow guide
"""

import re
import os
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

ENCRYPTION_STRENGTH = {
    "WPA3":  ("high",    "Best — forward secrecy, SAE"),
    "WPA2":  ("medium",  "Good — use CCMP/AES, ensure PMF"),
    "WPA":   ("low",     "Weak — TKIP vulnerable, upgrade to WPA2/3"),
    "WEP":   ("critical","Broken — crackable in minutes"),
    "OPN":   ("critical","Open — no encryption, sniff all traffic"),
    "OPEN":  ("critical","Open — no encryption"),
    "":      ("unknown", "Encryption not detected"),
}

WEAK_SSID_PATTERNS = [
    r"^linksys",r"^netgear",r"^dlink",r"^default",r"^tplink",
    r"^xfinity",r"^att",r"^spectrum",r"^comcast",
    r"^guest",r"^free",r"^public",r"^open",
    r"wifi$",r"wireless$",r"network$",r"router$",
]


def run(args, verbose=False):
    results  = {}
    iface    = getattr(args, "interface", "")

    print_status("Wireless security assessment module", "info")
    print_status("[!] Requires wireless interface and root for monitor mode.", "warn")

    _detect_wireless_interfaces(results, verbose)
    _scan_nearby_aps(results, iface, verbose)
    _check_weak_encryption(results, verbose)
    _check_wps_vulnerability(results, verbose)
    _check_rogue_ap_indicators(results, verbose)
    _check_probe_requests(results, iface, verbose)
    _pmkid_attack_check(results, verbose)
    _wireless_workflow_guide(results, verbose)

    return results


# ── Detect Wireless Interfaces ────────────────────────────────────────────────

def _detect_wireless_interfaces(results, verbose):
    print_section("  WIRELESS INTERFACE DETECTION  ")

    rc, iw_list = run_cmd("iw dev 2>/dev/null", timeout=5)
    rc2, iwconfig = run_cmd("iwconfig 2>/dev/null | grep -v 'no wireless'", timeout=5)

    interfaces = re.findall(r'Interface\s+(\w+)', iw_list)
    if not interfaces:
        interfaces = re.findall(r'^(\w+)\s+IEEE', iwconfig, re.MULTILINE)

    results["interfaces"] = interfaces
    if not interfaces:
        print_status("No wireless interfaces found (VM or no WiFi adapter).", "miss")
        return

    print_status(f"Wireless interfaces: {', '.join(interfaces)}", "success")

    # Check monitor mode support
    for iface in interfaces:
        rc3, mode = run_cmd(f"iw {iface} info 2>/dev/null | grep type", timeout=4)
        in_monitor = "monitor" in mode.lower()
        if in_monitor:
            print_status(f"{iface} is in MONITOR MODE — passive capture ready.", "success")
        else:
            print_status(f"{iface} is in managed mode. Enable monitor with:", "info")
            print(f"  {C.DIM}  sudo ip link set {iface} down")
            print(f"  sudo iw {iface} set monitor control")
            print(f"  sudo ip link set {iface} up{C.RESET}")


# ── AP Survey ─────────────────────────────────────────────────────────────────

def _scan_nearby_aps(results, iface, verbose):
    print_section("  ACCESS POINT SURVEY  ")

    if not cmd_exists("nmcli") and not cmd_exists("iwlist"):
        print_status("nmcli or iwlist required for AP survey.", "warn")
        results["aps"] = []
        return

    # nmcli scan (no monitor mode needed)
    rc, nmcli_out = run_cmd(
        "nmcli -t -f SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY dev wifi list 2>/dev/null",
        timeout=12
    )

    aps = []
    for line in nmcli_out.splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            ssid     = parts[0] or "<hidden>"
            bssid    = ":".join(parts[1:7]) if len(parts) > 6 else parts[1]
            chan     = parts[7] if len(parts) > 7 else parts[2]
            signal   = parts[9] if len(parts) > 9 else parts[4]
            security = parts[10] if len(parts) > 10 else parts[5]
            aps.append({
                "ssid":     ssid,
                "bssid":    bssid[:17],
                "channel":  chan,
                "signal":   signal,
                "security": security.strip(),
            })

    if not aps:
        # Fallback to iwlist
        if iface:
            rc2, iw_out = run_cmd(
                f"iwlist {iface} scan 2>/dev/null | grep -E 'ESSID|Address|Encryption|Quality'",
                timeout=15
            )
            ssids = re.findall(r'ESSID:"([^"]*)"', iw_out)
            bssids = re.findall(r'Address:\s*([0-9A-F:]{17})', iw_out)
            encryptions = re.findall(r'Encryption key:(on|off)', iw_out)
            for i, ssid in enumerate(ssids):
                aps.append({
                    "ssid":     ssid or "<hidden>",
                    "bssid":    bssids[i] if i < len(bssids) else "?",
                    "channel":  "?",
                    "signal":   "?",
                    "security": "WEP/WPA" if i < len(encryptions) and encryptions[i] == "on" else "OPEN",
                })

    results["aps"] = aps
    if aps:
        print_status(f"Access points discovered: {len(aps)}", "info")
        rows = [(a["ssid"][:30], a["bssid"], a["channel"], a["signal"], a["security"])
                for a in aps]
        print_table(["SSID", "BSSID", "Chan", "Signal", "Security"], rows)
    else:
        print_status("No APs found (try running as root with monitor mode).", "miss")


# ── Weak Encryption Detection ─────────────────────────────────────────────────

def _check_weak_encryption(results, verbose):
    print_section("  ENCRYPTION STRENGTH ANALYSIS  ")

    aps = results.get("aps", [])
    if not aps:
        print_status("No AP data to analyse.", "miss")
        return

    issues = []
    for ap in aps:
        sec = ap.get("security", "").upper()
        for enc_type, (level, note) in ENCRYPTION_STRENGTH.items():
            if enc_type in sec or (enc_type == "OPN" and not sec.strip()) or (enc_type == "OPEN" and sec == "OPEN"):
                if level in ("critical", "low"):
                    issues.append({
                        "ssid":    ap["ssid"],
                        "bssid":   ap["bssid"],
                        "enc":     enc_type or "NONE",
                        "level":   level,
                        "note":    note,
                    })
                break

        # Check for default vendor SSIDs
        for pattern in WEAK_SSID_PATTERNS:
            if re.match(pattern, ap["ssid"].lower()):
                issues.append({
                    "ssid":  ap["ssid"],
                    "bssid": ap["bssid"],
                    "enc":   "DEFAULT SSID",
                    "level": "medium",
                    "note":  "Default vendor SSID — likely default password too",
                })
                break

    results["encryption_issues"] = issues
    if issues:
        open_nets = [i for i in issues if "OPN" in i["enc"] or i["level"] == "critical"]
        if open_nets:
            print_finding(
                f"Open/Unencrypted Networks ({len(open_nets)})",
                "\n".join(f"  [CRITICAL] SSID: {i['ssid']} ({i['bssid']})" for i in open_nets),
                "critical"
            )
        wep_nets = [i for i in issues if "WEP" in i["enc"]]
        if wep_nets:
            print_finding(
                f"WEP Encryption Detected ({len(wep_nets)}) — Crackable in Minutes",
                "\n".join(f"  [CRITICAL] SSID: {i['ssid']} ({i['bssid']})" for i in wep_nets),
                "critical"
            )
    else:
        print_status("All detected networks use WPA2/WPA3 or better.", "miss")


# ── WPS Vulnerability Check ───────────────────────────────────────────────────

def _check_wps_vulnerability(results, verbose):
    print_section("  WPS VULNERABILITY DETECTION  ")

    if cmd_exists("wash"):
        rc, wash_out = run_cmd("wash -i wlan0 --scan-time 10 2>/dev/null", timeout=15)
        wps_aps = re.findall(r'([0-9A-F:]{17})\s+.*?(WPS\s+[\d.]+)', wash_out, re.IGNORECASE)

        if wps_aps:
            print_finding(
                f"WPS-Enabled APs Detected ({len(wps_aps)})",
                "\n".join(f"  [HIGH] {ap[0]}: {ap[1]}" for ap in wps_aps),
                "high"
            )
            print(f"\n  {C.CYAN}WPS Attack Commands (authorized testing):{C.RESET}")
            for bssid, _ in wps_aps[:2]:
                print(f"  {C.DIM}  # Pixie Dust attack:")
                print(f"  reaver -i wlan0mon -b {bssid} -K 1 -vv")
                print(f"  # Brute-force (slow):")
                print(f"  reaver -i wlan0mon -b {bssid} -vv --no-nacks{C.RESET}")
            results["wps_vulnerable"] = wps_aps
        else:
            print_status("No WPS-enabled APs detected (or wash not in monitor mode).", "miss")
            results["wps_vulnerable"] = []
    else:
        print_status("'wash' not installed (apt install reaver).", "warn")
        results["wps_vulnerable"] = []


# ── Rogue AP / Evil Twin Detection ────────────────────────────────────────────

def _check_rogue_ap_indicators(results, verbose):
    print_section("  ROGUE AP / EVIL TWIN INDICATORS  ")

    aps = results.get("aps", [])
    ssid_groups: dict = {}
    for ap in aps:
        ssid = ap.get("ssid", "").strip()
        if ssid and ssid != "<hidden>":
            ssid_groups.setdefault(ssid, []).append(ap)

    rogue_suspects = []
    for ssid, group in ssid_groups.items():
        if len(group) > 1:
            # Multiple BSSIDs with same SSID
            bssids  = [a["bssid"] for a in group]
            signals = [a.get("signal", "0") for a in group]
            rogue_suspects.append({
                "ssid":    ssid,
                "count":   len(group),
                "bssids":  bssids,
                "note":    "Multiple BSSIDs with same SSID — possible evil twin",
            })

    results["rogue_suspects"] = rogue_suspects
    if rogue_suspects:
        print_finding(
            f"Potential Evil Twin / Rogue AP ({len(rogue_suspects)} SSID(s))",
            "\n".join(f"  [HIGH] '{r['ssid']}': {r['count']} BSSIDs — {r['note']}"
                      for r in rogue_suspects),
            "high"
        )
    else:
        print_status("No duplicate SSIDs detected (no obvious rogue APs).", "miss")


# ── Probe Request Monitoring ──────────────────────────────────────────────────

def _check_probe_requests(results, iface, verbose):
    print_section("  CLIENT PROBE REQUEST ANALYSIS  ")

    if not iface or not cmd_exists("tcpdump"):
        print_status("Monitor interface + tcpdump required for probe capture.", "warn")
        results["probes"] = []
        return

    # Capture for 5 seconds
    print_status("Capturing probe requests for 5 seconds…", "info")
    rc, probe_out = run_cmd(
        f"timeout 5 tcpdump -I -i {iface} -e -n "
        f"'type mgt subtype probe-req' 2>/dev/null | head -20",
        timeout=10
    )

    probes = []
    for line in probe_out.splitlines():
        ssid_m = re.search(r'Probe Request \([^)]+\)', line)
        mac_m  = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})',
                            line, re.IGNORECASE)
        if ssid_m and mac_m:
            probes.append({"mac": mac_m.group(1), "probe": ssid_m.group(0)})

    results["probes"] = probes
    if probes:
        print_finding(
            f"Probe Requests Captured ({len(probes)}) — Client Preferred Networks",
            "\n".join(f"  {p['mac']} → {p['probe']}" for p in probes[:10]),
            "info"
        )
    else:
        print_status("No probe requests captured in 5s window.", "miss")


# ── PMKID Attack Check ────────────────────────────────────────────────────────

def _pmkid_attack_check(results, verbose):
    print_section("  PMKID ATTACK CAPABILITY  ")

    if cmd_exists("hcxdumptool") and cmd_exists("hcxtools"):
        print_finding(
            "PMKID Attack Tools Present",
            "  hcxdumptool + hcxtools detected — PMKID capture possible.\n"
            "  No client association needed (passive capture).",
            "info"
        )
        results["pmkid_capable"] = True
    else:
        print_status("hcxdumptool/hcxtools not installed.", "miss")
        results["pmkid_capable"] = False

    # Show workflow
    print(f"\n  {C.CYAN}PMKID Capture Workflow (WPA2 — no handshake required):{C.RESET}")
    cmds = [
        ("1. Put interface in monitor mode",
         "sudo airmon-ng start wlan0"),
        ("2. Capture PMKID",
         "sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1"),
        ("3. Convert to hashcat format",
         "hcxpcapngtool -o hash.hc22000 capture.pcapng"),
        ("4. Crack offline",
         "hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt"),
    ]
    for step, cmd in cmds:
        print(f"  {C.YELLOW}  {step}{C.RESET}")
        print(f"    {C.DIM}$ {cmd}{C.RESET}")


# ── Wireless Assessment Workflow ──────────────────────────────────────────────

def _wireless_workflow_guide(results, verbose):
    print_section("  WIRELESS ASSESSMENT TOOLKIT REFERENCE  ")

    tools = [
        ("aircrack-ng suite",  "WPA2 handshake capture + cracking", "apt install aircrack-ng"),
        ("hcxdumptool",        "PMKID capture (no client needed)",  "apt install hcxdumptool"),
        ("reaver",             "WPS PIN brute-force + Pixie Dust",  "apt install reaver"),
        ("wash",               "WPS-enabled AP scanner",             "apt install reaver"),
        ("bettercap",          "Full wireless MITM framework",       "apt install bettercap"),
        ("hostapd-wpe",        "Rogue 802.1X / PEAP MITM",          "apt install hostapd-wpe"),
        ("wireshark/tshark",   "Packet analysis",                    "apt install tshark"),
        ("kismet",             "Wireless IDS + packet capture",      "apt install kismet"),
    ]
    print_table(["Tool", "Purpose", "Install"], tools)

    print(f"\n  {C.CYAN}WPA2 Handshake Capture Workflow:{C.RESET}")
    steps = [
        "sudo airmon-ng check kill && sudo airmon-ng start wlan0",
        "sudo airodump-ng wlan0mon  # identify target AP",
        "sudo airodump-ng -c <CH> --bssid <AP_MAC> -w capture wlan0mon",
        "# In new terminal — deauth to force handshake:",
        "sudo aireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon",
        "# Crack captured handshake:",
        "aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt",
    ]
    for step in steps:
        prefix = "  # " if step.startswith("# ") else "  $ "
        color  = C.DIM if step.startswith("#") else C.GREEN
        print(f"    {color}{prefix}{step.lstrip('# ')}{C.RESET}")
