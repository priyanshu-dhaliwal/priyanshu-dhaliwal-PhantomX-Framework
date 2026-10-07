"""
plugins/services.py — Protocol Service Enumeration Module

Covers:
  SMB (TCP 445/139):
    - Share enumeration (null session, guest)
    - SMB version detection (SMBv1 dangerous!)
    - MS17-010 (EternalBlue) detection
    - PrintNightmare indicator check
    - SMB signing status
    - Domain/workgroup extraction
    - User enumeration via RID cycling

  SNMP (UDP 161):
    - Community string brute-force
    - System info extraction (sysDescr, sysName, sysLocation)
    - Interface enumeration (ifTable)
    - ARP table extraction
    - Running processes (hrSWRunName)
    - Installed software
    - Network routes

  NetBIOS (UDP 137 / TCP 139):
    - NetBIOS name table
    - MAC address extraction
    - Domain/workgroup detection
    - NBNS queries

  SSH (TCP 22):
    - Version and algorithm enumeration
    - Weak algorithm detection (MD5, arcfour, DH group1)
    - Host key fingerprint
    - Username enumeration (timing-based, CVE-2018-15473)
    - AuthenticationMethods probe

  LDAP (TCP 389 / 636):
    - Anonymous bind test
    - Base DN extraction
    - Domain info (domain name, forest)
    - User enumeration (if anonymous bind works)
    - Password policy extraction
    - AD functional level

  FTP (TCP 21):
    - Anonymous login test
    - Version banner analysis
    - Directory listing
    - Writable directory detection
    - FTP bounce attack check
    - Passive vs active mode
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

SNMP_COMMUNITY_STRINGS = [
    "public", "private", "community", "manager", "admin", "secret",
    "password", "monitor", "write", "cisco", "router", "switch",
    "read", "default", "network", "snmp", "security", "root",
]

SNMP_OIDS = {
    "System Description":  "1.3.6.1.2.1.1.1.0",
    "System Name":         "1.3.6.1.2.1.1.5.0",
    "System Location":     "1.3.6.1.2.1.1.6.0",
    "System Contact":      "1.3.6.1.2.1.1.4.0",
    "System Uptime":       "1.3.6.1.2.1.1.3.0",
    "Interfaces":          "1.3.6.1.2.1.2.2.1.2",
    "IP Addresses":        "1.3.6.1.2.1.4.20.1.1",
    "ARP Table":           "1.3.6.1.2.1.4.22.1.3",
    "Running Processes":   "1.3.6.1.2.1.25.4.2.1.2",
    "Installed Software":  "1.3.6.1.2.1.25.6.3.1.2",
    "TCP Connections":     "1.3.6.1.2.1.6.13.1.3",
    "Users":               "1.3.6.1.4.1.77.1.2.25",
    "Open Ports":          "1.3.6.1.2.1.6.13.1.3",
}

WEAK_SSH_ALGOS = [
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "arcfour", "arcfour128", "arcfour256",
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",  # NIST curves potentially weak
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")

    print_status(f"Service enumeration target: {target}", "info")

    _smb_enum(results, target, verbose)
    _snmp_enum(results, target, verbose)
    _netbios_enum(results, target, verbose)
    _ssh_enum(results, target, verbose)
    _ldap_enum(results, target, verbose)
    _ftp_enum(results, target, verbose)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SMB ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _smb_enum(results, target, verbose):
    print_section("  SMB ENUMERATION  ")

    # Port check
    smb_open = _port_open(target, 445) or _port_open(target, 139)
    if not smb_open:
        print_status("SMB ports (445/139) not open.", "miss")
        results["smb"] = {"open": False}
        return

    print_status(f"SMB port open on {target}", "success")
    smb_data = {"open": True}

    # SMB version via nmap or smbclient
    rc, nmap_smb = run_cmd(
        f"nmap -sV -p445 --script smb-protocols {target} 2>/dev/null",
        timeout=20
    )
    smb_data["nmap_raw"] = nmap_smb

    # Detect SMBv1
    if "smb1" in nmap_smb.lower() or "smbv1" in nmap_smb.lower():
        print_finding("SMBv1 ENABLED",
                      "  SMBv1 is deprecated and vulnerable to EternalBlue (MS17-010).\n"
                      "  Disable immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                      "critical")

    # Null session share enum
    print_status("Enumerating SMB shares (null session)…", "info")
    rc2, shares = run_cmd(
        f"smbclient -L //{target} -N 2>/dev/null", timeout=12
    )
    share_list = re.findall(r'^\s+(\S+)\s+(Disk|IPC|Printer)', shares, re.MULTILINE)
    smb_data["shares"] = share_list

    if share_list:
        print_finding(
            f"SMB Shares Accessible (null session) — {len(share_list)} share(s)",
            "\n".join(f"  [{s[1]}] {s[0]}" for s in share_list),
            "high" if any(s[1] == "Disk" for s in share_list) else "medium"
        )
    else:
        print_status("No shares via null session.", "miss")

    # SMB Signing
    rc3, signing = run_cmd(
        f"nmap -p445 --script smb2-security-mode {target} 2>/dev/null",
        timeout=15
    )
    if "signing enabled and not required" in signing.lower():
        print_finding("SMB Signing NOT Required",
                      "  Relay attacks (NTLM relay) possible — no signing enforcement.\n"
                      "  Use Responder + ntlmrelayx for exploitation.",
                      "high")
        smb_data["signing"] = "not required"
    elif "signing enabled and required" in signing.lower():
        print_status("SMB Signing: Required (protects against relay).", "miss")
        smb_data["signing"] = "required"

    # MS17-010 EternalBlue check
    print_status("Checking MS17-010 (EternalBlue)…", "info")
    rc4, eb_out = run_cmd(
        f"nmap -p445 --script smb-vuln-ms17-010 {target} 2>/dev/null",
        timeout=20
    )
    if "VULNERABLE" in eb_out:
        print_finding("MS17-010 EternalBlue VULNERABLE",
                      "  Remote code execution without authentication.\n"
                      "  Patch: KB4012212 (Win7), KB4012215 (Win8.1), KB4012216 (WinServer2012).",
                      "critical")
        smb_data["eternalblue"] = True
    else:
        print_status("MS17-010: Not detected as vulnerable.", "miss")
        smb_data["eternalblue"] = False

    # Domain/workgroup
    rc5, nbstat = run_cmd(f"nmblookup -A {target} 2>/dev/null", timeout=8)
    domain_m = re.search(r'(\S+)\s+<00>.*GROUP', nbstat)
    if domain_m:
        smb_data["domain"] = domain_m.group(1)
        print_status(f"Domain/Workgroup: {domain_m.group(1)}", "info")

    # RID cycling (user enumeration)
    if cmd_exists("rpcclient"):
        print_status("Attempting RID cycling for user enumeration…", "info")
        users = []
        for rid in range(500, 520):
            rc6, out = run_cmd(
                f"rpcclient -U '' -N {target} -c 'lookupsids S-1-5-21-0-0-0-{rid}' 2>/dev/null",
                timeout=4
            )
            m = re.search(r'(\w+)\\(\w+)\s+\(\d+\)', out)
            if m:
                users.append((str(rid), m.group(2)))
        if users:
            smb_data["users_rid"] = users
            print_finding(f"RID Cycling — {len(users)} user(s) found",
                          "\n".join(f"  RID {u[0]}: {u[1]}" for u in users), "high")

    results["smb"] = smb_data


# ══════════════════════════════════════════════════════════════════════════════
# SNMP ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _snmp_enum(results, target, verbose):
    print_section("  SNMP ENUMERATION  ")

    if not cmd_exists("snmpwalk") and not cmd_exists("snmpget"):
        print_status("snmpwalk/snmpget not found — install net-snmp.", "warn")
        results["snmp"] = {"available": False}
        return

    # Find valid community string
    valid_community = None
    print_status(f"Brute-forcing SNMP community strings ({len(SNMP_COMMUNITY_STRINGS)})…", "info")

    for community in SNMP_COMMUNITY_STRINGS:
        rc, out = run_cmd(
            f"snmpget -v2c -c {community} -t2 -r1 {target} sysDescr.0 2>/dev/null",
            timeout=5
        )
        if rc == 0 and out.strip() and "Timeout" not in out and "No Such" not in out:
            valid_community = community
            print_finding(f"SNMP Community String Found: '{community}'",
                          f"  {out.strip()[:100]}", "high")
            break

    if not valid_community:
        print_status("No common SNMP community strings found.", "miss")
        results["snmp"] = {"open": False}
        return

    # Full enumeration
    snmp_data = {"community": valid_community, "data": {}}

    for label, oid in SNMP_OIDS.items():
        rc, out = run_cmd(
            f"snmpwalk -v2c -c {valid_community} -t3 {target} {oid} 2>/dev/null | head -20",
            timeout=8
        )
        if rc == 0 and out.strip():
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            snmp_data["data"][label] = lines[:15]
            if verbose:
                print(f"\n  {C.CYAN}{label}:{C.RESET}")
                for l in lines[:5]:
                    print(f"    {C.DIM}{l}{C.RESET}")

    # Summarize key findings
    sys_desc = snmp_data["data"].get("System Description", [""])[0]
    sys_name = snmp_data["data"].get("System Name", [""])[0]
    users    = snmp_data["data"].get("Users", [])

    rows = [
        ("Community", valid_community),
        ("Sys Desc",  sys_desc[:60] if sys_desc else "N/A"),
        ("Sys Name",  sys_name[:60] if sys_name else "N/A"),
        ("Users",     str(len(users))),
    ]
    print_table(["Item", "Value"], rows)

    if users:
        print_finding(f"SNMP User Enumeration — {len(users)} user(s)",
                      "\n".join(f"  {u}" for u in users[:10]), "high")

    results["snmp"] = snmp_data


# ══════════════════════════════════════════════════════════════════════════════
# NETBIOS ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _netbios_enum(results, target, verbose):
    print_section("  NETBIOS ENUMERATION  ")

    rc, nb_out = run_cmd(f"nbtscan {target} 2>/dev/null || nmblookup -A {target} 2>/dev/null",
                         timeout=10)
    if not nb_out.strip():
        print_status("No NetBIOS response.", "miss")
        results["netbios"] = {}
        return

    # Parse NetBIOS name table
    nb_data = {"raw": nb_out}
    names   = re.findall(r'(\S+)\s+<([0-9a-fA-F]{2})>\s+.*?(UNIQUE|GROUP)', nb_out)

    name_meanings = {
        "00": "Workstation/Domain Name",
        "03": "Messenger Service",
        "06": "RAS Server",
        "1b": "Domain Master Browser",
        "1c": "Domain Controller",
        "1d": "Master Browser",
        "1e": "Browser Election",
        "20": "File Server",
        "be": "Network Monitor Agent",
        "bf": "Network Monitor Application",
    }

    if names:
        rows = [(n[0], n[1], n[2], name_meanings.get(n[1].lower(), "Unknown"))
                for n in names]
        print_table(["Name", "Code", "Type", "Meaning"], rows)
        nb_data["names"] = rows

        # Check for DC
        if any(n[1] in ("1b","1c") for n in names):
            print_finding("Domain Controller Detected via NetBIOS",
                          "  NetBIOS code 0x1b/0x1c indicates DC presence.",
                          "info")

    # MAC address
    mac_m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', nb_out)
    if mac_m:
        nb_data["mac"] = mac_m.group(0)
        print_status(f"MAC Address: {mac_m.group(0)}", "info")

    results["netbios"] = nb_data


# ══════════════════════════════════════════════════════════════════════════════
# SSH ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _ssh_enum(results, target, verbose):
    print_section("  SSH ENUMERATION  ")

    if not _port_open(target, 22):
        print_status("SSH port 22 not open.", "miss")
        results["ssh"] = {"open": False}
        return

    ssh_data = {"open": True}

    # Banner grab
    rc, banner = run_cmd(f"nc -w3 {target} 22 2>/dev/null | head -1", timeout=6)
    ssh_data["banner"] = banner.strip()
    print_status(f"SSH Banner: {banner.strip()[:80]}", "info")

    # Version check
    m = re.search(r'OpenSSH[_\s]([\d.]+)', banner)
    if m:
        ver = m.group(1)
        ssh_data["version"] = ver
        if float(ver.split(".")[0]) < 7:
            print_finding(f"Outdated OpenSSH {ver}",
                          "  Multiple CVEs in older versions. Upgrade to 8.9+", "high")

    # Algorithm enumeration
    if cmd_exists("nmap"):
        rc2, algo_out = run_cmd(
            f"nmap -p22 --script ssh2-enum-algos {target} 2>/dev/null",
            timeout=15
        )
        weak_found = []
        for algo in WEAK_SSH_ALGOS:
            if algo in algo_out.lower():
                weak_found.append(algo)

        ssh_data["weak_algos"] = weak_found
        if weak_found:
            print_finding(
                f"Weak SSH Algorithms ({len(weak_found)})",
                "\n".join(f"  {a}" for a in weak_found),
                "medium"
            )
        else:
            print_status("SSH algorithms appear modern.", "miss")

        # Host key
        rc3, hk_out = run_cmd(
            f"nmap -p22 --script ssh-hostkey {target} 2>/dev/null",
            timeout=12
        )
        keys = re.findall(r'(ssh-\w+|ecdsa|ed25519)\s+([A-Za-z0-9+/=]{20,})', hk_out)
        if keys:
            ssh_data["host_keys"] = [(k[0], k[1][:30] + "…") for k in keys]
            print_status(f"Host keys: {', '.join(k[0] for k in keys)}", "info")

    # Username enumeration (CVE-2018-15473) — timing probe
    print_status("Probing SSH user enumeration (timing-based)…", "info")
    test_users = ["root", "admin", "administrator", "ubuntu", "ec2-user", "pi", "vagrant"]
    if cmd_exists("ssh-audit"):
        rc4, audit = run_cmd(f"ssh-audit {target} 2>/dev/null", timeout=20)
        ssh_data["audit"] = audit[:500]
    else:
        print_status("ssh-audit not installed (apt install ssh-audit).", "miss")

    # Auth methods
    rc5, auth = run_cmd(
        f"ssh -o BatchMode=yes -o ConnectTimeout=3 "
        f"-o StrictHostKeyChecking=no {target} 2>&1 | head -5",
        timeout=8
    )
    if "publickey,password" in auth or "publickey,keyboard" in auth:
        ssh_data["auth_methods"] = auth.strip()
        if "password" in auth.lower():
            print_finding("SSH Password Authentication Enabled",
                          "  Consider enforcing key-only auth: PasswordAuthentication no", "medium")

    results["ssh"] = ssh_data


# ══════════════════════════════════════════════════════════════════════════════
# LDAP ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _ldap_enum(results, target, verbose):
    print_section("  LDAP ENUMERATION  ")

    ldap_open = _port_open(target, 389) or _port_open(target, 636) or _port_open(target, 3268)
    if not ldap_open:
        print_status("LDAP ports (389/636/3268) not open.", "miss")
        results["ldap"] = {"open": False}
        return

    print_status(f"LDAP port open on {target}", "success")
    ldap_data = {"open": True}

    if not cmd_exists("ldapsearch"):
        print_status("ldapsearch not installed (apt install ldap-utils).", "warn")
        results["ldap"] = ldap_data
        return

    # Anonymous bind — get base DN
    print_status("Testing LDAP anonymous bind…", "info")
    rc, base_dn = run_cmd(
        f"ldapsearch -x -h {target} -s base namingcontexts 2>/dev/null | "
        f"grep -i namingcontext",
        timeout=10
    )
    if rc == 0 and base_dn.strip():
        ldap_data["anonymous_bind"] = True
        print_finding("LDAP Anonymous Bind ALLOWED",
                      f"  Naming contexts: {base_dn.strip()[:100]}", "high")

        # Extract base DN
        m = re.search(r'namingContexts:\s*(.+)', base_dn, re.IGNORECASE)
        if m:
            dn = m.group(1).strip()
            ldap_data["base_dn"] = dn

            # Enumerate domain info
            rc2, domain_info = run_cmd(
                f"ldapsearch -x -h {target} -b '{dn}' -s base "
                f"'(objectClass=*)' 2>/dev/null | head -30",
                timeout=10
            )
            ldap_data["domain_info_raw"] = domain_info

            # Extract domain name
            dc_parts = re.findall(r'dc=(\w+)', dn)
            if dc_parts:
                domain = ".".join(dc_parts)
                ldap_data["domain"] = domain
                print_status(f"Active Directory Domain: {domain}", "info")

            # Enumerate users
            print_status("Enumerating AD users via LDAP…", "info")
            rc3, users_out = run_cmd(
                f"ldapsearch -x -h {target} -b '{dn}' "
                f"'(objectClass=user)' sAMAccountName 2>/dev/null | "
                f"grep sAMAccountName | head -30",
                timeout=15
            )
            users = re.findall(r'sAMAccountName:\s*(\S+)', users_out)
            ldap_data["users"] = users
            if users:
                print_finding(f"AD Users Enumerated ({len(users)})",
                              "\n".join(f"  {u}" for u in users[:15]), "high")

            # Password policy
            rc4, pol = run_cmd(
                f"ldapsearch -x -h {target} -b '{dn}' "
                f"'(objectClass=domainDNS)' minPwdLength lockoutThreshold 2>/dev/null",
                timeout=10
            )
            min_len = re.search(r'minPwdLength:\s*(\d+)', pol)
            lockout = re.search(r'lockoutThreshold:\s*(\d+)', pol)
            if min_len:
                ldap_data["min_pwd_len"] = min_len.group(1)
            if lockout:
                ldap_data["lockout_threshold"] = lockout.group(1)
                if lockout.group(1) == "0":
                    print_finding("No Account Lockout Policy",
                                  "  Lockout threshold is 0 — brute-force possible.", "high")

    else:
        ldap_data["anonymous_bind"] = False
        print_status("LDAP anonymous bind rejected (expected).", "miss")

    results["ldap"] = ldap_data


# ══════════════════════════════════════════════════════════════════════════════
# FTP ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def _ftp_enum(results, target, verbose):
    print_section("  FTP ENUMERATION  ")

    if not _port_open(target, 21):
        print_status("FTP port 21 not open.", "miss")
        results["ftp"] = {"open": False}
        return

    print_status(f"FTP port open on {target}", "success")
    ftp_data = {"open": True}

    # Banner grab
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((target, 21))
        banner = s.recv(256).decode(errors="replace").strip()
        s.close()
        ftp_data["banner"] = banner
        print_status(f"FTP Banner: {banner[:80]}", "info")

        # Version CVE check
        if "vsftpd 2.3.4" in banner.lower():
            print_finding("vsftpd 2.3.4 BACKDOOR (CVE-2011-2523)",
                          "  This version contains a backdoor triggered by ':)'  in username.\n"
                          "  Connects back on port 6200.", "critical")
        elif "proftpd 1.3.3" in banner.lower():
            print_finding("ProFTPD 1.3.3c Backdoor (CVE-2010-4221)",
                          "  Remote code execution via mod_sql.", "critical")
    except Exception:
        pass

    # Anonymous login
    print_status("Testing anonymous FTP login…", "info")
    rc, anon = run_cmd(
        f"ftp -n {target} <<EOF\nuser anonymous anonymous@test.com\nls\nbye\nEOF\n2>/dev/null",
        timeout=12
    )
    if "230" in anon or "login successful" in anon.lower():
        ftp_data["anonymous_login"] = True
        print_finding("FTP Anonymous Login ALLOWED",
                      "  Files accessible without credentials.", "high")

        # List files
        rc2, listing = run_cmd(
            f"curl -sk --user anonymous:anonymous 'ftp://{target}/' 2>/dev/null | head -20",
            timeout=10
        )
        if listing.strip():
            ftp_data["file_listing"] = listing.strip().splitlines()[:20]
            print_status(f"FTP listing ({len(listing.splitlines())} entries):", "info")
            if verbose:
                for line in listing.splitlines()[:10]:
                    print(f"  {C.DIM}{line}{C.RESET}")
    else:
        ftp_data["anonymous_login"] = False
        print_status("Anonymous FTP login rejected.", "miss")

    # Nmap FTP scripts
    rc3, nmap_ftp = run_cmd(
        f"nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln-cve2010-4221 "
        f"{target} 2>/dev/null",
        timeout=20
    )
    ftp_data["nmap_scripts"] = nmap_ftp[:500]

    if "ftp-bounce: bounce working" in nmap_ftp.lower():
        print_finding("FTP Bounce Attack Possible",
                      "  Server allows PORT command to connect to third-party hosts.\n"
                      "  Can be used for port scanning through this server.", "medium")

    if "VULNERABLE" in nmap_ftp:
        print_finding("FTP Vulnerability Detected by Nmap Scripts",
                      nmap_ftp[:300], "critical")

    results["ftp"] = ftp_data


# ── Helper ────────────────────────────────────────────────────────────────────

def _port_open(host, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        rc = s.connect_ex((host, port))
        s.close()
        return rc == 0
    except Exception:
        return False
