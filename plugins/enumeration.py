"""
plugins/enumeration.py — System & Network Enumeration Module

Checks:
  1. OS & kernel details
  2. Current user, UID, groups
  3. All local users and their shells
  4. Network interfaces, routes, open ports
  5. Running processes (root-owned)
  6. Installed services (systemctl)
  7. Interesting environment variables
  8. Writable directories in common paths
  9. Mounted filesystems
"""

import os
import re

from core.banner import print_status, print_finding, print_table, C
from utils.shell import run_cmd, read_file, is_writable, cmd_exists


def run(args, verbose=False):
    results = {}

    _os_info(results, verbose)
    _user_info(results, verbose)
    _local_users(results, verbose)
    _network_info(results, verbose)
    _open_ports(results, verbose)
    _processes(results, verbose)
    _services(results, verbose)
    _env_vars(results, verbose)
    _filesystems(results, verbose)

    return results


def _os_info(results, verbose):
    print_status("Gathering OS & kernel information…", "info")
    _, uname  = run_cmd("uname -a")
    _, distro = run_cmd("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    _, arch   = run_cmd("uname -m")
    _, uptime = run_cmd("uptime -p 2>/dev/null || uptime")

    results["os"] = {
        "uname":  uname,
        "distro": distro,
        "arch":   arch,
        "uptime": uptime
    }

    rows = [
        ("OS",       distro),
        ("Kernel",   uname),
        ("Arch",     arch),
        ("Uptime",   uptime),
    ]
    print_table(["Field", "Value"], rows)


def _user_info(results, verbose):
    print_status("Current user context…", "info")
    _, whoami = run_cmd("whoami")
    _, uid    = run_cmd("id")
    _, hn     = run_cmd("hostname")

    results["current_user"] = {"whoami": whoami, "id": uid, "hostname": hn}

    if "root" in whoami:
        print_finding("Running as ROOT", uid, "critical")
    else:
        print_table(["Field", "Value"], [("User", whoami), ("ID string", uid), ("Hostname", hn)])


def _local_users(results, verbose):
    print_status("Enumerating local user accounts…", "info")
    passwd = read_file("/etc/passwd") or ""
    users = []
    shell_users = []

    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        uname, _, uid, gid, _, home, shell = parts[:7]
        users.append((uname, uid, gid, home, shell))
        if shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""):
            shell_users.append((uname, uid, shell))

    results["all_users"] = users
    results["shell_users"] = shell_users

    print_status(f"Total accounts: {len(users)}  |  Shell-enabled: {len(shell_users)}", "info")
    if shell_users:
        print_table(["Username", "UID", "Shell"], shell_users)


def _network_info(results, verbose):
    print_status("Gathering network information…", "info")
    _, ifaces = run_cmd("ip -o addr show 2>/dev/null || ifconfig 2>/dev/null")
    _, routes = run_cmd("ip route 2>/dev/null || route -n 2>/dev/null")
    _, arp    = run_cmd("arp -a 2>/dev/null || ip neigh 2>/dev/null")
    _, dns    = run_cmd("cat /etc/resolv.conf 2>/dev/null")

    results["network"] = {
        "interfaces": ifaces,
        "routes":     routes,
        "arp_cache":  arp,
        "dns":        dns
    }

    # Parse IP addresses
    ips = re.findall(r'inet\s+([\d.]+)', ifaces)
    ips = [ip for ip in ips if not ip.startswith("127.")]
    print_status(f"Non-loopback IPs: {', '.join(ips) if ips else 'None'}", "info")

    if verbose:
        print(f"\n{C.DIM}--- Interfaces ---\n{ifaces}\n{C.RESET}")
        print(f"{C.DIM}--- Routes ---\n{routes}\n{C.RESET}")


def _open_ports(results, verbose):
    print_status("Scanning listening ports…", "info")
    _, ss_out = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    
    # Parse listening ports
    ports = []
    for line in ss_out.splitlines():
        m = re.search(r'[:\s]([\d.]+):(\d+)\s', line)
        if m:
            addr, port = m.group(1), m.group(2)
            ports.append((port, addr, line.split()[-1] if line.split() else ""))

    # Deduplicate
    seen = set()
    unique_ports = []
    for p in ports:
        if p[0] not in seen:
            seen.add(p[0])
            unique_ports.append(p)

    results["open_ports"] = unique_ports
    print_status(f"Listening ports: {', '.join(p[0] for p in unique_ports[:15])}", "info")
    if verbose and unique_ports:
        print_table(["Port", "Address", "Process"], unique_ports[:20])


def _processes(results, verbose):
    print_status("Enumerating running processes…", "info")
    _, ps_out = run_cmd("ps aux --no-headers 2>/dev/null || ps aux 2>/dev/null")

    root_procs = []
    interesting_procs = []
    keywords = ["cron", "mysql", "apache", "nginx", "ssh", "ftp", "python",
                "ruby", "node", "php", "java", "vault", "postgres", "redis",
                "mongo", "docker", "containerd", "kubelet"]

    for line in ps_out.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        user, pid, cmd = parts[0], parts[1], parts[10]

        if user == "root" and verbose:
            root_procs.append((pid, cmd[:80]))

        for kw in keywords:
            if kw in cmd.lower():
                interesting_procs.append((user, pid, cmd[:80]))
                break

    results["interesting_processes"] = interesting_procs

    if interesting_procs:
        print_status(f"Notable processes found: {len(interesting_procs)}", "info")
        print_table(["User", "PID", "Command"], interesting_procs[:15])
    else:
        print_status("No especially notable processes.", "miss")


def _services(results, verbose):
    print_status("Enumerating systemd services…", "info")
    if not cmd_exists("systemctl"):
        results["services"] = []
        print_status("systemctl not available.", "miss")
        return

    _, svc_out = run_cmd("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null")
    services = []
    for line in svc_out.splitlines():
        parts = line.split()
        if parts:
            services.append(parts[0])

    results["services"] = services
    print_status(f"Running services: {len(services)}", "info")
    if verbose:
        for s in services:
            print(f"     {C.DIM}{s}{C.RESET}")


def _env_vars(results, verbose):
    print_status("Checking environment variables for secrets…", "info")
    sensitive_patterns = [
        "password", "passwd", "secret", "api_key", "apikey", "token",
        "aws_access", "aws_secret", "private_key", "credentials",
        "database_url", "db_pass", "mysql_pass", "postgres_password"
    ]
    env_vars = dict(os.environ)
    findings = {}

    for key, val in env_vars.items():
        for pat in sensitive_patterns:
            if pat in key.lower() or pat in val.lower():
                findings[key] = val[:80] + ("…" if len(val) > 80 else "")
                break

    results["sensitive_env"] = findings

    if findings:
        print_finding(
            f"Sensitive Environment Variables ({len(findings)} found)",
            "\n".join(f"  {k} = {v}" for k, v in findings.items()),
            "high"
        )
    else:
        print_status("No sensitive environment variables found.", "miss")


def _filesystems(results, verbose):
    print_status("Enumerating mounted filesystems…", "info")
    _, mounts = run_cmd("mount 2>/dev/null | grep -v 'proc\|sysfs\|devpts\|cgroup\|tmpfs' || cat /proc/mounts")
    results["mounts"] = mounts

    # Check for interesting mounts
    interesting = [l for l in mounts.splitlines()
                   if any(kw in l for kw in ["nfs", "smb", "cifs", "fuse", "ext4", "xfs"])]

    if interesting and verbose:
        print_status("Interesting mounts:", "info")
        for m in interesting:
            print(f"     {C.DIM}{m}{C.RESET}")
    else:
        print_status(f"Filesystems enumerated ({len(mounts.splitlines())} entries).", "miss")
