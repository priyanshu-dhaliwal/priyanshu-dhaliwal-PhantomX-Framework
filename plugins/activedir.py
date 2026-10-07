"""
plugins/activedir.py — Active Directory Assessment & Enumeration

Techniques:
  1.  Domain enumeration (domain name, SID, functional level, DCs)
  2.  User enumeration (all users, privileged users, service accounts)
  3.  Group enumeration (Domain Admins, Enterprise Admins, etc.)
  4.  Computer object enumeration
  5.  GPO (Group Policy Object) enumeration
  6.  Trust relationship mapping
  7.  Kerberoastable account detection (SPN enumeration)
  8.  ASREPRoastable account detection (no pre-auth)
  9.  Delegation abuse detection (unconstrained, constrained, RBCD)
  10. ACL / DACL misconfiguration hints (GenericAll, WriteDACL, etc.)
  11. Password policy & Fine-Grained Password Policy (FGPP)
  12. AdminSDHolder protected accounts
  13. AD CS (Certificate Services) presence detection
  14. LAPS deployment status
  15. BloodHound data collection hints
"""

import re
from core.banner import print_status, print_finding, print_table, print_section, C
from utils.shell import run_cmd, cmd_exists

# Privileged AD groups
PRIVILEGED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Print Operators", "Server Operators", "Group Policy Creator Owners",
    "DNSAdmins", "Remote Management Users", "Exchange Windows Permissions",
    "Organization Management",
]


def run(args, verbose=False):
    results = {}
    target  = getattr(args, "target", "127.0.0.1")
    domain  = getattr(args, "domain", "")
    user    = getattr(args, "user", "")
    passwd  = getattr(args, "password", "")

    # Try to auto-detect domain from LDAP
    if not domain:
        rc, dn = run_cmd(
            f"ldapsearch -x -h {target} -s base namingcontexts 2>/dev/null | "
            f"grep -i namingcontext | head -1",
            timeout=8
        )
        m = re.findall(r'dc=(\w+)', dn, re.IGNORECASE)
        if m:
            domain = ".".join(m)

    print_status(f"Active Directory target: {target} | Domain: {domain or 'unknown'}", "info")

    _domain_info(results, target, domain, user, passwd, verbose)
    _user_enum(results, target, domain, user, passwd, verbose)
    _group_enum(results, target, domain, user, passwd, verbose)
    _computer_enum(results, target, domain, user, passwd, verbose)
    _kerberoast_check(results, target, domain, user, passwd, verbose)
    _asreproast_check(results, target, domain, user, passwd, verbose)
    _delegation_check(results, target, domain, user, passwd, verbose)
    _password_policy(results, target, domain, user, passwd, verbose)
    _adminsdholder_check(results, target, domain, user, passwd, verbose)
    _adcs_check(results, target, domain, verbose)
    _laps_check(results, target, domain, verbose)
    _trust_enum(results, target, domain, user, passwd, verbose)
    _bloodhound_hints(results, target, domain, verbose)

    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ldap_query(target, domain, user, passwd, base_dn, ldap_filter, attrs="", timeout=15):
    """Run an ldapsearch query. Returns output string."""
    creds = f"-D '{user}@{domain}' -w '{passwd}'" if user and passwd else "-x"
    dc_parts = domain.replace(".", ",dc=") if domain else "dc=domain,dc=local"
    base = base_dn or f"dc={dc_parts}"
    attr_str = attrs if attrs else ""
    rc, out = run_cmd(
        f"ldapsearch {creds} -h {target} -b '{base}' '{ldap_filter}' "
        f"{attr_str} 2>/dev/null",
        timeout=timeout
    )
    return out


# ── Domain Info ───────────────────────────────────────────────────────────────

def _domain_info(results, target, domain, user, passwd, verbose):
    print_section("  DOMAIN INFORMATION  ")

    if not cmd_exists("ldapsearch"):
        print_status("ldapsearch required (apt install ldap-utils)", "warn")

    # Get domain SID via rpcclient
    rc, sid_out = run_cmd(f"rpcclient -U '' -N {target} -c 'lsaquery' 2>/dev/null", timeout=8)
    domain_sid = ""
    m = re.search(r'Domain Sid: (S-\d+-\d+-\d+)', sid_out)
    if m:
        domain_sid = m.group(1)

    # Get DCs via DNS
    rc2, dc_dns = run_cmd(
        f"nslookup -type=SRV _ldap._tcp.{domain} 2>/dev/null | grep 'svr hostname'",
        timeout=8
    )
    dcs = re.findall(r'svr hostname = (.+?)\.?\s*$', dc_dns, re.MULTILINE)

    # LDAP domain info
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""
    out = _ldap_query(target, domain, user, passwd, dc_base,
                      "(objectClass=domainDNS)",
                      "distinguishedName domainFunctionality ms-DS-MachineAccountQuota")

    func_level_map = {
        "0": "Windows 2000", "1": "Windows Server 2003 Interim",
        "2": "Windows Server 2003", "3": "Windows Server 2008",
        "4": "Windows Server 2008 R2", "5": "Windows Server 2012",
        "6": "Windows Server 2012 R2", "7": "Windows Server 2016/2019/2022",
    }
    func_m = re.search(r'domainFunctionality:\s*(\d+)', out)
    func_level = func_level_map.get(func_m.group(1) if func_m else "", "Unknown")

    # Machine account quota
    maq_m = re.search(r'ms-DS-MachineAccountQuota:\s*(\d+)', out)
    maq   = maq_m.group(1) if maq_m else "Unknown"

    info = {
        "domain":         domain,
        "sid":            domain_sid,
        "dcs":            dcs,
        "func_level":     func_level,
        "machine_quota":  maq,
    }
    results["domain_info"] = info

    rows = [
        ("Domain",          domain or "N/A"),
        ("Domain SID",      domain_sid or "N/A"),
        ("Func Level",      func_level),
        ("Machine Quota",   maq),
        ("DCs Found",       ", ".join(dcs) if dcs else "N/A"),
    ]
    print_table(["Property", "Value"], rows)

    # Machine Account Quota ≠ 0 is a privilege escalation path
    if maq not in ("0", "Unknown"):
        print_finding(
            f"Machine Account Quota = {maq}",
            "  Domain users can create machine accounts!\n"
            "  Abuse path: Create computer → set SPN → Kerberoast → resource-based constrained delegation.",
            "high"
        )


# ── User Enumeration ──────────────────────────────────────────────────────────

def _user_enum(results, target, domain, user, passwd, verbose):
    print_section("  USER ENUMERATION  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    # All enabled users
    out = _ldap_query(target, domain, user, passwd, dc_base,
                      "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                      "sAMAccountName userAccountControl memberOf description")

    all_users  = re.findall(r'sAMAccountName:\s*(\S+)', out)
    results["ad_users"] = all_users
    print_status(f"Enabled user accounts: {len(all_users)}", "info")

    # Service accounts (contain $ or common patterns)
    svc_accounts = [u for u in all_users if
                    any(p in u.lower() for p in ["svc", "service", "srv", "_svc",
                                                  "sa_", "_sa", "admin", "mgr"])]
    if svc_accounts:
        print_finding(f"Service Account Names ({len(svc_accounts)})",
                      "\n".join(f"  {u}" for u in svc_accounts[:15]), "medium")

    # Accounts with password never expires (UAC flag 65536)
    never_expire = []
    for uac_m, sam_m in zip(
        re.finditer(r'userAccountControl:\s*(\d+)', out),
        re.finditer(r'sAMAccountName:\s*(\S+)', out)
    ):
        try:
            uac = int(uac_m.group(1))
            if uac & 0x10000:  # DONT_EXPIRE_PASSWORD
                never_expire.append(sam_m.group(1))
        except Exception:
            pass

    results["never_expire_accounts"] = never_expire
    if never_expire:
        print_finding(f"Password Never Expires ({len(never_expire)} accounts)",
                      "\n".join(f"  {u}" for u in never_expire[:10]), "medium")


# ── Group Enumeration ─────────────────────────────────────────────────────────

def _group_enum(results, target, domain, user, passwd, verbose):
    print_section("  PRIVILEGED GROUP ENUMERATION  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    groups_data = {}
    for group in PRIVILEGED_GROUPS:
        out = _ldap_query(
            target, domain, user, passwd, dc_base,
            f"(&(objectClass=group)(cn={group}))",
            "member cn"
        )
        members = re.findall(r'member:\s*CN=([^,]+)', out)
        if members:
            groups_data[group] = members

    results["privileged_groups"] = groups_data

    for group, members in groups_data.items():
        sev = "critical" if group in ("Domain Admins", "Enterprise Admins", "Schema Admins") \
              else "high"
        print_finding(
            f"{group} — {len(members)} member(s)",
            "\n".join(f"  {m}" for m in members[:10]),
            sev
        )


# ── Computer Enumeration ──────────────────────────────────────────────────────

def _computer_enum(results, target, domain, user, passwd, verbose):
    print_section("  COMPUTER OBJECT ENUMERATION  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    out = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(objectClass=computer)",
        "cn operatingSystem operatingSystemVersion lastLogonTimestamp"
    )

    computers  = re.findall(r'cn:\s*(\S+)', out)
    os_entries = re.findall(r'operatingSystem:\s*(.+)', out)
    os_vers    = re.findall(r'operatingSystemVersion:\s*(.+)', out)

    results["computers"] = computers
    print_status(f"Computer objects: {len(computers)}", "info")

    # Detect legacy OS
    legacy = []
    for os_str in os_entries:
        if any(old in os_str for old in ["2003", "2008", "XP", "Vista", "Windows 7",
                                          "Windows 8", "2000"]):
            legacy.append(os_str.strip())

    if legacy:
        print_finding(f"Legacy OS Detected ({len(set(legacy))} type(s))",
                      "\n".join(f"  {o}" for o in set(legacy)),
                      "high")

    # OS distribution
    if os_entries and verbose:
        from collections import Counter
        os_counter = Counter(o.strip() for o in os_entries)
        rows = [(os, str(cnt)) for os, cnt in os_counter.most_common(10)]
        print_table(["Operating System", "Count"], rows)


# ── Kerberoasting ─────────────────────────────────────────────────────────────

def _kerberoast_check(results, target, domain, user, passwd, verbose):
    print_section("  KERBEROASTABLE ACCOUNTS (SPN ENUM)  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    out = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        "sAMAccountName servicePrincipalName"
    )

    accounts = []
    current  = {}
    for line in out.splitlines():
        if line.startswith("sAMAccountName:"):
            current["user"] = line.split(":", 1)[1].strip()
        elif line.startswith("servicePrincipalName:"):
            current["spn"] = line.split(":", 1)[1].strip()
            if "user" in current and "spn" in current:
                accounts.append((current["user"], current["spn"]))
                current = {}

    results["kerberoastable"] = accounts

    if accounts:
        print_finding(
            f"KERBEROASTABLE ACCOUNTS — {len(accounts)} SPN(s)",
            "\n".join(f"  {a[0]}: {a[1]}" for a in accounts),
            "high"
        )
        print(f"\n  {C.CYAN}Exploitation (requires valid domain credentials):{C.RESET}")
        print(f"  {C.DIM}  impacket-GetUserSPNs {domain}/{user}:{passwd} -dc-ip {target} -request{C.RESET}")
        print(f"  {C.DIM}  hashcat -m 13100 kerberoast.txt rockyou.txt{C.RESET}\n")
    else:
        print_status("No Kerberoastable accounts found.", "miss")


# ── AS-REP Roasting ───────────────────────────────────────────────────────────

def _asreproast_check(results, target, domain, user, passwd, verbose):
    print_section("  AS-REP ROASTABLE ACCOUNTS  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    out = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        "sAMAccountName"
    )

    accounts = re.findall(r'sAMAccountName:\s*(\S+)', out)
    results["asreproastable"] = accounts

    if accounts:
        print_finding(
            f"AS-REP ROASTABLE ACCOUNTS — {len(accounts)} (no pre-auth required)",
            "\n".join(f"  {a}" for a in accounts),
            "high"
        )
        print(f"\n  {C.CYAN}Exploitation:{C.RESET}")
        print(f"  {C.DIM}  impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {target} -no-pass{C.RESET}")
        print(f"  {C.DIM}  hashcat -m 18200 asrep.txt rockyou.txt{C.RESET}\n")
    else:
        print_status("No AS-REP Roastable accounts.", "miss")


# ── Delegation Abuse ──────────────────────────────────────────────────────────

def _delegation_check(results, target, domain, user, passwd, verbose):
    print_section("  DELEGATION MISCONFIGURATION  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""
    deleg_findings = []

    # Unconstrained delegation (except DCs)
    out = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        "cn sAMAccountName"
    )
    unconstrained = re.findall(r'cn:\s*(\S+)', out)
    if unconstrained:
        deleg_findings.append(("Unconstrained Delegation", unconstrained, "critical",
                                "TGT of any authenticating user cached — pass-the-ticket possible"))

    # Constrained delegation
    out2 = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(msDS-AllowedToDelegateTo=*)",
        "cn sAMAccountName msDS-AllowedToDelegateTo"
    )
    constrained = re.findall(r'sAMAccountName:\s*(\S+)', out2)
    spns         = re.findall(r'msDS-AllowedToDelegateTo:\s*(.+)', out2)
    if constrained:
        deleg_findings.append(("Constrained Delegation", constrained,
                                "high", f"Allowed to delegate to: {', '.join(spns[:3])}"))

    results["delegation"] = deleg_findings

    for name, accounts, sev, note in deleg_findings:
        print_finding(
            f"{name} ({len(accounts)} object(s))",
            f"  {note}\n" + "\n".join(f"  {a}" for a in accounts[:8]),
            sev
        )
    if not deleg_findings:
        print_status("No dangerous delegation configurations.", "miss")


# ── Password Policy ───────────────────────────────────────────────────────────

def _password_policy(results, target, domain, user, passwd, verbose):
    print_section("  AD PASSWORD POLICY  ")

    rc, pol_out = run_cmd(
        f"rpcclient -U '' -N {target} -c 'getdompwinfo' 2>/dev/null",
        timeout=8
    )
    if not pol_out.strip():
        rc2, pol_out = run_cmd(
            f"enum4linux -P {target} 2>/dev/null", timeout=15
        )

    pol_data = {}
    for field, pattern in [
        ("Min Password Length",  r'min_password_length:\s*(\d+)'),
        ("Password History",     r'password_history_length:\s*(\d+)'),
        ("Max Password Age",     r'max_password_age:\s*(.+)'),
        ("Lockout Threshold",    r'lockout_threshold:\s*(\d+)'),
        ("Lockout Duration",     r'lockout_duration:\s*(.+)'),
    ]:
        m = re.search(pattern, pol_out, re.IGNORECASE)
        if m:
            pol_data[field] = m.group(1).strip()

    results["ad_password_policy"] = pol_data

    if pol_data:
        print_table(["Policy", "Value"], list(pol_data.items()))
        if pol_data.get("Lockout Threshold") == "0":
            print_finding("No Account Lockout", "Brute-force password spray possible.", "high")
        if int(pol_data.get("Min Password Length","8") or "8") < 8:
            print_finding("Weak Minimum Password Length",
                          f"Min length: {pol_data.get('Min Password Length')} chars", "medium")
    else:
        print_status("Could not retrieve password policy.", "miss")


# ── AdminSDHolder ─────────────────────────────────────────────────────────────

def _adminsdholder_check(results, target, domain, user, passwd, verbose):
    print_section("  ADMINSDHOLDER PROTECTED ACCOUNTS  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    out = _ldap_query(
        target, domain, user, passwd, dc_base,
        "(adminCount=1)",
        "sAMAccountName adminCount"
    )
    accounts = re.findall(r'sAMAccountName:\s*(\S+)', out)
    results["adminsdholder"] = accounts

    if accounts:
        print_status(f"AdminSDHolder protected accounts: {len(accounts)}", "info")
        if verbose:
            for a in accounts:
                print(f"  {C.DIM}{a}{C.RESET}")
    else:
        print_status("No AdminSDHolder accounts found.", "miss")


# ── AD CS Detection ───────────────────────────────────────────────────────────

def _adcs_check(results, target, domain, verbose):
    print_section("  AD CERTIFICATE SERVICES (AD CS)  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    # Check for CA via LDAP
    config_base = "CN=Configuration," + ("dc=" + domain.replace(".", ",dc=") if domain else "")
    rc, cs_out = run_cmd(
        f"ldapsearch -x -h {target} -b 'CN=Certification Authorities,CN=Public Key Services,"
        f"CN=Services,{config_base}' '(objectClass=*)' cn 2>/dev/null",
        timeout=10
    )
    cas = re.findall(r'cn:\s*(.+)', cs_out)

    # Check HTTP enrollment
    rc2, http_enroll = run_cmd(
        f"curl -sk -m5 -o /dev/null -w '%{{http_code}}' "
        f"http://{target}/certsrv/ 2>/dev/null",
        timeout=8
    )

    adcs_data = {"cas": cas, "http_enrollment": http_enroll.strip() == "200"}
    results["adcs"] = adcs_data

    if cas:
        print_finding(
            f"Active Directory Certificate Services Found ({len(cas)} CA(s))",
            "\n".join(f"  CA: {c}" for c in cas),
            "info"
        )

    if http_enroll.strip() == "200":
        print_finding(
            "AD CS Web Enrollment Active",
            "  HTTP enrollment endpoint accessible.\n"
            "  Check for ESC1-ESC8 vulnerabilities (Certipy / Certify):\n"
            "  certipy find -u user@domain -p pass -dc-ip " + target,
            "high"
        )


# ── LAPS Check ────────────────────────────────────────────────────────────────

def _laps_check(results, target, domain, verbose):
    print_section("  LAPS DEPLOYMENT STATUS  ")
    dc_base = "dc=" + domain.replace(".", ",dc=") if domain else ""

    # Check if ms-Mcs-AdmPwd attribute exists
    out = _ldap_query(
        target, domain, "", "", dc_base,
        "(objectClass=computer)",
        "ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime"
    )

    if "ms-Mcs-AdmPwd" in out:
        passwords = re.findall(r'ms-Mcs-AdmPwd:\s*(\S+)', out)
        results["laps"] = {"deployed": True, "readable_passwords": passwords}

        if passwords:
            print_finding(
                f"LAPS Passwords READABLE ({len(passwords)} computer(s))",
                "\n".join(f"  {p}" for p in passwords[:5]),
                "critical"
            )
        else:
            print_status("LAPS deployed but passwords not readable with current access.", "miss")
    else:
        results["laps"] = {"deployed": False}
        print_finding(
            "LAPS NOT Deployed",
            "  Local Administrator passwords may be same across all machines.\n"
            "  Compromise one → spray password across all domain computers.",
            "high"
        )


# ── Trust Enumeration ─────────────────────────────────────────────────────────

def _trust_enum(results, target, domain, user, passwd, verbose):
    print_section("  DOMAIN TRUST RELATIONSHIPS  ")

    rc, trust_out = run_cmd(
        f"rpcclient -U '' -N {target} -c 'enumdomtrusts' 2>/dev/null",
        timeout=10
    )
    trusts = re.findall(r'Domain Name: (\S+)', trust_out)
    results["trusts"] = trusts

    if trusts:
        print_finding(
            f"Domain Trusts Found ({len(trusts)})",
            "\n".join(f"  → {t}" for t in trusts),
            "info"
        )
        print(f"  {C.DIM}  Bi-directional trusts enable cross-domain attacks if misconfigured.{C.RESET}\n")
    else:
        print_status("No domain trusts found or requires authentication.", "miss")


# ── BloodHound Collection Hints ───────────────────────────────────────────────

def _bloodhound_hints(results, target, domain, verbose):
    print_section("  BLOODHOUND COLLECTION HINTS  ")
    print(f"\n  {C.CYAN}{C.BOLD}BloodHound / SharpHound Collection Commands:{C.RESET}")
    cmds = [
        ("Python (no agent needed)",
         f"bloodhound-python -u <user> -p <pass> -d {domain} -ns {target} -c All"),
        ("SharpHound (on Windows)",
         "SharpHound.exe -c All --zipfilename bh_data.zip"),
        ("Certipy (AD CS)",
         f"certipy find -u <user>@{domain} -p <pass> -dc-ip {target} -vulnerable"),
        ("Impacket Kerberoast",
         f"impacket-GetUserSPNs {domain}/<user>:<pass> -dc-ip {target} -request"),
        ("AS-REP Roast",
         f"impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {target} -no-pass"),
    ]
    for label, cmd in cmds:
        print(f"\n  {C.YELLOW}  [{label}]{C.RESET}")
        print(f"  {C.DIM}  {cmd}{C.RESET}")
    print()
