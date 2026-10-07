#!/usr/bin/env python3
"""
PhantomX v6.0 — Advanced Security Assessment Framework
Run with NO arguments → interactive guided wizard asks for target.
[For Authorized Penetration Testing Only]
"""
import argparse, os, sys, types
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine  import PluginEngine
from core.banner  import print_banner, print_status, print_section, C
from utils.report import ReportGenerator

ALL_MODULES = [
    "enum","privesc","persist","loot","lateral","network","audit",
    "container","webapp","vulnscan","fuzzer","cvecheck","recon",
    "services","activedir","evasion","postexploit","apitesting",
    "passattack","wireless","dnsrecon","traffic",
]

NEEDS_TARGET = {
    "network","webapp","vulnscan","fuzzer","cvecheck","apitesting",
    "passattack","services","activedir","evasion","postexploit",
    "recon","dnsrecon","traffic",
}


# ── Parser ────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="phantomx",
        description="PhantomX v6.0  —  22-Module Red Team Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Run with NO arguments → interactive wizard asks for target + options
  python3 main.py

Or specify a module directly (omit --target to be prompted):
  python3 main.py all         --target 10.10.10.5
  python3 main.py privesc
  python3 main.py vulnscan    --target 10.10.10.5 --port 443
  python3 main.py activedir   --target 10.10.10.5 --domain corp.local
  python3 main.py ai          --subcommand chat
  python3 tui.py              (interactive TUI — asks target on startup)
  python3 gui.py              (web GUI at http://127.0.0.1:7331)

[!] Authorized penetration testing only.
""")

    p.add_argument("--verbose",     "-v", action="store_true")
    p.add_argument("--output",      "-o", choices=["json","html","txt"], default=None)
    p.add_argument("--no-color",    action="store_true")
    p.add_argument("--interactive", "-i", action="store_true",
                   help="Force interactive wizard")
    p.add_argument("--version",     action="version", version="PhantomX v6.0")

    sub = p.add_subparsers(dest="module", title="Modules", metavar="<module>")

    def mk(name, hlp, **extras):
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("--target",     default="",
                        help="Target IP / hostname (prompted if omitted)")
        sp.add_argument("--domain",     default="")
        sp.add_argument("--port",       default=80, type=int)
        sp.add_argument("--all-checks", action="store_true", default=True)
        for flag, kw in extras.items():
            sp.add_argument(f"--{flag.replace('_','-')}", **kw)
        return sp

    # all
    sp = sub.add_parser("all", help="Run all 22 modules sequentially")
    sp.add_argument("--target", default="",
                    help="Target IP / hostname (prompted if omitted)")
    sp.add_argument("--domain", default="")
    sp.add_argument("--port",   default=80, type=int)
    sp.add_argument("--skip",   nargs="+", choices=ALL_MODULES, default=[])

    # local modules
    mk("enum",       "System & network enumeration")
    mk("privesc",    "Privilege escalation discovery")
    mk("audit",      "Security hardening & account audit")
    mk("persist",    "Persistence mechanism analysis",
       list=dict(action="store_true"))
    mk("loot",       "Credential & sensitive data harvesting",
       shadow=dict(action="store_true"),
       ssh=dict(action="store_true"),
       cloud=dict(action="store_true"))
    mk("lateral",    "Lateral movement preparation",
       arp_scan=dict(action="store_true"))
    mk("container",  "Container & cloud escape detection",
       docker=dict(action="store_true"),
       k8s=dict(action="store_true"),
       cloud=dict(action="store_true"))
    mk("postexploit","Post-exploitation & lateral movement guide",
       local=dict(action="store_true"))

    # network/web modules that need a target
    mk("network",    "Network port scan & service fingerprint",
       snmp=dict(action="store_true"))
    mk("webapp",     "Web application security scanner")
    mk("vulnscan",   "OWASP CWE Top 25 + full vulnerability scan",
       cwe_ref=dict(action="store_true"))
    mk("fuzzer",     "Advanced parameter & header fuzzer",
       deep=dict(action="store_true"))
    mk("cvecheck",   "CVE banner matching (300+ CVE rules)",
       local=dict(action="store_true"))
    mk("apitesting", "OWASP API Top 10 + JWT + GraphQL testing",
       jwt=dict(action="store_true"),
       graphql=dict(action="store_true"))
    mk("passattack", "Default creds, lockout-aware spray, hash cracking",
       spray=dict(action="store_true"),
       delay=dict(default=1.0, type=float))
    mk("services",   "SMB, SNMP, NetBIOS, SSH, LDAP, FTP enumeration",
       smb=dict(action="store_true"),
       snmp=dict(action="store_true"),
       ssh=dict(action="store_true"),
       ldap=dict(action="store_true"),
       ftp=dict(action="store_true"))
    mk("activedir",  "Active Directory enumeration & assessment",
       user=dict(default=""),
       password=dict(default=""))
    mk("evasion",    "Firewall evasion testing & pivot/tunnel guide",
       fragment=dict(action="store_true"),
       egress=dict(action="store_true"))
    mk("recon",      "Passive & active reconnaissance (OSINT, subdomain, WAF)",
       passive_only=dict(action="store_true"))
    mk("dnsrecon",   "Deep DNS security assessment (AXFR, DNSSEC, takeover)",
       ns=dict(default=""))
    mk("traffic",    "Network traffic analysis (LLMNR, ARP, cleartext creds)",
       interface=dict(default=""),
       duration=dict(default=15, type=int))
    mk("wireless",   "Wireless security assessment (WPA2, WPS, rogue AP)",
       interface=dict(default="wlan0"))

    # AI
    sp = sub.add_parser("ai", help="AI-powered analysis, chat, MITRE mapping")
    sp.add_argument("--subcommand", default="analyse",
                    choices=["analyse","chat","report","mitre","chain","remediate"])
    sp.add_argument("--all-checks", action="store_true", default=True)

    # Utility
    sc = sub.add_parser("score",  help="CVSS-like risk scoring of all findings")
    sc.add_argument("--top",    type=int, default=10)
    sc.add_argument("--export", default=None)

    sub.add_parser("tui",  help="Launch interactive terminal UI")
    sub.add_parser("help", help="Open HTML command reference in browser")

    rp = sub.add_parser("report", help="Generate HTML/JSON/TXT report from last scan")
    rp.add_argument("--format", choices=["json","html","txt"], default="html")
    rp.add_argument("--open",   action="store_true")

    return p


# ── Helpers ───────────────────────────────────────────────────────────────────
def _ensure_target(args, module: str):
    """Ask for target if module needs one and none supplied."""
    if getattr(args, "target", "") or module not in NEEDS_TARGET:
        return
    from utils.input_helper import ask_target_simple
    args.target = ask_target_simple(module)

def _ensure_domain(args, module: str):
    """Ask for domain if module could use one and none supplied."""
    if getattr(args, "domain", ""):
        return
    if module in ("activedir", "recon", "dnsrecon"):
        from utils.input_helper import ask_domain_simple
        args.domain = ask_domain_simple()

def _blank_args(config: dict):
    """Build a SimpleNamespace from wizard config dict."""
    return types.SimpleNamespace(
        target=config.get("target","127.0.0.1"),
        domain=config.get("domain",""),
        port=config.get("port",80),
        verbose=config.get("verbose",False),
        output=config.get("output","html"),
        all_checks=True, arp_scan=False, spray=False, delay=1.0,
        shadow=False, ssh=False, cloud=False, local=False, list=False,
        user="", password="", interface="eth0", duration=15,
        snmp=False, smb=False, ldap=False, ftp=False,
        docker=False, k8s=False, deep=False, fragment=False,
        egress=False, passive_only=False, ns="",
        jwt=False, graphql=False, cwe_ref=False,
    )


# ── Interactive wizard ────────────────────────────────────────────────────────
def run_interactive():
    """Full wizard — ask for config then run selected modules."""
    from utils.input_helper import ask_target
    cfg  = ask_target()
    args = _blank_args(cfg)

    mods = cfg["modules"]
    if mods == ["all"]:
        mods = ALL_MODULES

    engine  = PluginEngine(verbose=args.verbose)
    results = {}

    print_section("  STARTING SCAN  ")
    print_status(f"Target   : {C.BOLD}{args.target}{C.RESET}", "info")
    print_status(f"Domain   : {args.domain or '(not set)'}", "info")
    print_status(f"Port     : {args.port}", "info")
    print_status(f"Modules  : {len(mods)}", "info")
    print()

    for mod in mods:
        print_status(f"Running module: {C.BOLD}{mod.upper()}{C.RESET}", "section")
        try:
            results[mod] = engine.run(mod, args)
        except Exception as e:
            print_status(f"{mod} error: {e}", "error")

    if cfg.get("output"):
        gen = ReportGenerator(results=results)
        out = gen.generate(cfg["output"])
        print_status(f"Report saved  →  {out}", "success")

    print_section("  SCAN COMPLETE  ")
    print_status(f"Modules completed: {len(results)}", "success")
    print_status("Next: python3 main.py score", "info")
    print_status("      python3 main.py ai --subcommand analyse", "info")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    if getattr(args, "no_color", False):
        os.environ["NO_COLOR"] = "1"

    print_banner()

    # No module OR --interactive → show full wizard
    if not args.module or getattr(args, "interactive", False):
        run_interactive()
        return

    engine  = PluginEngine(verbose=getattr(args,"verbose",False))
    results = {}

    try:
        # ── Utility ───────────────────────────────────────────────────────────
        if args.module == "score":
            from core.scoring import RiskScorer
            sc = RiskScorer()
            if sc.load():
                sc.score(); sc.print_report()
                if getattr(args,"export",None):
                    print_status(f"JSON → {sc.export_json(args.export)}", "success")
            else:
                print_status("No session data. Run modules first.", "warn")
            return

        elif args.module == "tui":
            import tui as t; t.main(); return

        elif args.module == "help":
            hp = os.path.join(os.path.dirname(__file__), "dashboard","help.html")
            if os.path.exists(hp):
                os.system(f"xdg-open '{hp}' 2>/dev/null || open '{hp}' 2>/dev/null")
                print_status(f"Help page → {hp}", "info")
            else:
                print_status("Run: python3 main.py --help", "info")
            return

        elif args.module == "report":
            gen = ReportGenerator(); gen.load_last_run()
            out = gen.generate(args.format)
            print_status(f"Report → {out}", "success")
            if args.open:
                os.system(f"xdg-open '{out}' 2>/dev/null")
            return

        # ── Scan modules ──────────────────────────────────────────────────────
        elif args.module == "all":
            # Ask for target if not given — network modules need it
            if not getattr(args,"target",""):
                from utils.input_helper import ask_target_simple
                print_status("Network modules require a target IP/hostname.", "warn")
                args.target = ask_target_simple("all")
            skip = getattr(args,"skip",[]) or []
            for mod in ALL_MODULES:
                if mod not in skip:
                    print_status(f"Running: {mod.upper()}", "section")
                    results[mod] = engine.run(mod, args)

        else:
            # Ask for target/domain if missing
            _ensure_target(args, args.module)
            _ensure_domain(args, args.module)
            results[args.module] = engine.run(args.module, args)

        # Auto-save
        if getattr(args,"output",None):
            gen = ReportGenerator(results=results)
            print_status(f"Report → {gen.generate(args.output)}", "success")

    except KeyboardInterrupt:
        print_status("\nAborted (Ctrl+C).", "warn"); sys.exit(0)
    except PermissionError as e:
        print_status(f"Permission denied: {e}", "error")
    except Exception as e:
        print_status(f"Error: {e}", "error")
        if getattr(args,"verbose",False):
            import traceback; traceback.print_exc()


if __name__ == "__main__":
    main()
