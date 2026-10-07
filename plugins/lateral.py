"""
plugins/lateral.py — Lateral Movement Preparation Module

Checks:
  1.  ARP cache & live host discovery
  2.  SSH service discovery on known hosts
  3.  NFS / SMB share enumeration
  4.  Host trust relationships (known_hosts, .rhosts)
  5.  Internal DNS names from /etc/hosts
  6.  Credential reuse candidates
  7.  Writable network shares
  8.  Proxy / tunnel pivot points
"""

import os
import re
import ipaddress

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, cmd_exists, is_readable


def run(args, verbose=False):
    results = {}

    _arp_discovery(results, args, verbose)
    _ssh_discovery(results, verbose)
    _share_enum(results, verbose)
    _host_trusts(results, verbose)
    _etc_hosts(results, verbose)
    _pivot_candidates(results, verbose)

    return results


# ── Checks ────────────────────────────────────────────────────────────────────

def _arp_discovery(results, args, verbose):
    print_status("Performing ARP cache & neighbor discovery…", "info")

    # Passive: read ARP cache
    _, arp_out = run_cmd("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
    hosts = []

    for line in arp_out.splitlines():
        # Parse IP addresses
        m = re.search(r'[\(\s]((\d{1,3}\.){3}\d{1,3})[\)\s]', line)
        if m:
            ip = m.group(1)
            if not ip.startswith("169.254"):  # Exclude APIPA
                mac_m = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.I)
                mac = mac_m.group(1) if mac_m else "unknown"
                state = "REACHABLE" if "reachable" in line.lower() else ""
                hosts.append((ip, mac, state))

    results["arp_hosts"] = hosts
    print_status(f"ARP cache: {len(hosts)} live host(s) discovered.", "info")

    if hosts:
        print_table(["IP Address", "MAC", "State"], hosts)

    # Active: optional ping sweep of /24
    if getattr(args, "arp_scan", False) or getattr(args, "all_checks", False):
        _, local_ip = run_cmd("hostname -I 2>/dev/null | awk '{print $1}'")
        if local_ip and re.match(r'\d+\.\d+\.\d+\.\d+', local_ip):
            prefix = ".".join(local_ip.split(".")[:3])
            print_status(f"Ping sweeping {prefix}.0/24 (passive fping)…", "info")
            if cmd_exists("fping"):
                _, ping_out = run_cmd(
                    f"fping -a -g {prefix}.0/24 2>/dev/null", timeout=30
                )
                live = [l.strip() for l in ping_out.splitlines() if l.strip()]
            else:
                # Fallback: parallel ping
                _, ping_out = run_cmd(
                    f"for i in $(seq 1 254); do (ping -c1 -W1 {prefix}.$i &>/dev/null && echo {prefix}.$i) & done; wait",
                    timeout=60
                )
                live = [l.strip() for l in ping_out.splitlines() if l.strip()]

            results["ping_sweep"] = live
            print_status(f"Ping sweep: {len(live)} responding host(s).", "info")
            if live and verbose:
                for ip in live:
                    print(f"     {C.GREEN}↳ {ip}{C.RESET}")


def _ssh_discovery(results, verbose):
    print_status("Checking SSH service reachability on discovered hosts…", "info")
    hosts_to_check = []

    # Use ARP hosts if available
    arp_hosts = results.get("arp_hosts", [])
    hosts_to_check = [h[0] for h in arp_hosts]

    if not hosts_to_check:
        print_status("No hosts in ARP cache to probe.", "miss")
        results["ssh_hosts"] = []
        return

    ssh_open = []
    for ip in hosts_to_check[:30]:  # Cap to avoid long waits
        rc, _ = run_cmd(f"nc -z -w2 {ip} 22 2>/dev/null", timeout=4)
        if rc == 0:
            # Grab banner
            _, banner = run_cmd(f"nc -w2 {ip} 22 2>/dev/null | head -1", timeout=4)
            ssh_open.append((ip, banner[:60] if banner else "SSH open"))

    results["ssh_hosts"] = ssh_open

    if ssh_open:
        print_finding(
            f"SSH Services Reachable ({len(ssh_open)} hosts)",
            "\n".join(f"  {h[0]}  {h[1]}" for h in ssh_open),
            "medium"
        )
    else:
        print_status("No reachable SSH services detected.", "miss")


def _share_enum(results, verbose):
    print_status("Enumerating NFS and SMB/CIFS shares…", "info")
    nfs_shares  = []
    smb_shares  = []

    # NFS: showmount
    if cmd_exists("showmount"):
        _, nfs_out = run_cmd("showmount -e localhost 2>/dev/null")
        for line in nfs_out.splitlines():
            if line.strip() and not line.startswith("Export"):
                nfs_shares.append(line.strip())

    # SMB: smbclient
    if cmd_exists("smbclient"):
        _, smb_out = run_cmd("smbclient -L localhost -N 2>/dev/null", timeout=10)
        for line in smb_out.splitlines():
            if "Disk" in line or "IPC" in line:
                smb_shares.append(line.strip())

    # Check /proc/mounts for existing NFS mounts
    mounts = read_file("/proc/mounts") or ""
    nfs_mounts = [l for l in mounts.splitlines() if " nfs" in l or " cifs" in l]

    results["nfs_shares"]  = nfs_shares
    results["smb_shares"]  = smb_shares
    results["nfs_mounts"]  = nfs_mounts

    if nfs_shares:
        print_finding(f"NFS Exports ({len(nfs_shares)})",
                      "\n".join(f"  {s}" for s in nfs_shares), "medium")
    if smb_shares:
        print_finding(f"SMB Shares ({len(smb_shares)})",
                      "\n".join(f"  {s}" for s in smb_shares), "medium")
    if nfs_mounts:
        print_finding(f"Active NFS/CIFS Mounts ({len(nfs_mounts)})",
                      "\n".join(f"  {m}" for m in nfs_mounts), "medium")

    if not nfs_shares and not smb_shares and not nfs_mounts:
        print_status("No network shares found.", "miss")


def _host_trusts(results, verbose):
    print_status("Checking host trust relationships…", "info")
    trust_files = []
    findings = []

    # .rhosts (legacy rsh trust)
    rhosts_paths = ["/etc/hosts.equiv"]
    _, passwd_homes = run_cmd("awk -F: '{print $6}' /etc/passwd 2>/dev/null")
    for home in passwd_homes.splitlines():
        rhosts_paths.append(os.path.join(home.strip(), ".rhosts"))

    for path in rhosts_paths:
        if os.path.isfile(path) and is_readable(path):
            content = read_file(path) or ""
            if content.strip():
                findings.append((path, content.strip()[:200]))

    # known_hosts (lateral movement reuse)
    _, user_homes = run_cmd("awk -F: '$3>=1000{print $6}' /etc/passwd 2>/dev/null")
    known_hosts_list = []
    for home in user_homes.splitlines():
        kh = os.path.join(home.strip(), ".ssh", "known_hosts")
        if os.path.isfile(kh) and is_readable(kh):
            content = read_file(kh) or ""
            entries = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
            known_hosts_list.append((kh, entries))

    results["trust_files"]   = findings
    results["known_hosts"]   = known_hosts_list

    if findings:
        print_finding(
            f"Trust Files Found ({len(findings)})",
            "\n".join(f"  {f[0]}" for f in findings),
            "high"
        )
    if known_hosts_list:
        print_status(f"known_hosts files: {len(known_hosts_list)} (lateral targets)", "info")
        if verbose:
            print_table(["File", "Entries"], [(k[0], str(k[1])) for k in known_hosts_list])
    if not findings and not known_hosts_list:
        print_status("No trust relationships found.", "miss")


def _etc_hosts(results, verbose):
    print_status("Parsing /etc/hosts for internal hostnames…", "info")
    content = read_file("/etc/hosts") or ""
    internal_hosts = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            names = parts[1:]
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private and not addr.is_loopback:
                    internal_hosts.append((ip, " ".join(names)))
            except ValueError:
                continue

    results["internal_hosts"] = internal_hosts

    if internal_hosts:
        print_status(f"Internal hostnames in /etc/hosts: {len(internal_hosts)}", "info")
        print_table(["IP", "Hostname(s)"], internal_hosts)
    else:
        print_status("No internal hosts in /etc/hosts.", "miss")


def _pivot_candidates(results, verbose):
    print_status("Identifying pivot / tunnel candidates…", "info")
    candidates = []

    # Check for proxy env vars
    for var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SOCKS_PROXY"]:
        val = os.environ.get(var, "")
        if val:
            candidates.append(("Proxy env var", f"{var}={val}"))

    # Check for SSH agent socket
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if sock and os.path.exists(sock):
        candidates.append(("SSH Agent Socket", sock))

    # Check for running proxy tools
    for tool in ["squid", "tinyproxy", "proxychains", "chisel", "ligolo", "socat", "stunnel"]:
        _, running = run_cmd(f"pgrep -x {tool} 2>/dev/null")
        if running.strip():
            candidates.append(("Running tunnel tool", f"{tool} (PID: {running.strip()})"))

    # Check if IP forwarding is enabled
    ipfwd = read_file("/proc/sys/net/ipv4/ip_forward") or "0"
    if ipfwd.strip() == "1":
        candidates.append(("IP Forwarding", "ENABLED — host can route traffic"))

    results["pivot_candidates"] = candidates

    if candidates:
        print_finding(
            f"Pivot / Tunnel Candidates ({len(candidates)})",
            "\n".join(f"  [{c[0]}] {c[1]}" for c in candidates),
            "medium"
        )
    else:
        print_status("No obvious pivot candidates detected.", "miss")
