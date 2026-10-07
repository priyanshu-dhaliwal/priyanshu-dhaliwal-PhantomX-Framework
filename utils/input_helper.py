"""
utils/input_helper.py — Interactive Target & Scan Input System

Called automatically by main.py, tui.py, and gui.py whenever
a target is needed but not yet supplied. Provides:

  ask_target()         — Full 5-step guided wizard (target → domain →
                         port → scan profile → output format)
  ask_target_simple()  — One-line target prompt for a specific module
  ask_domain_simple()  — One-line domain prompt
  validate_ip_or_host()— Returns True if value is a valid IP/hostname
  resolve_host()       — Resolves hostname → IP string
"""

import os, re, sys, socket
from core.banner import print_status, C

# ── Colour helpers ────────────────────────────────────────────────────────────
def _sep(char="─", n=58):
    print(f"  {C.MAGENTA}{char*n}{C.RESET}")

def _hdr(text):
    _sep("═")
    print(f"  {C.RED}{C.BOLD}  {text}{C.RESET}")
    _sep("═")

def _step(n, total, title):
    print(f"\n  {C.YELLOW}{C.BOLD}Step {n} / {total}  —  {title}{C.RESET}")

# ── Scan profiles ─────────────────────────────────────────────────────────────
PROFILES = {
    "1": {"name": "Quick Recon",
          "mods": ["enum","network"],
          "desc": "Fast overview — OS info + port scan  (2-3 min)"},
    "2": {"name": "Web Application",
          "mods": ["recon","webapp","vulnscan","apitesting","fuzzer","cvecheck"],
          "desc": "Full web/API assessment               (10-15 min)"},
    "3": {"name": "Internal Network",
          "mods": ["enum","network","services","lateral","evasion"],
          "desc": "Internal host + protocol scan         (10 min)"},
    "4": {"name": "Active Directory",
          "mods": ["services","activedir","postexploit"],
          "desc": "AD enum + post-exploitation guide     (8 min)"},
    "5": {"name": "Privilege Escalation",
          "mods": ["enum","privesc","persist","loot","audit"],
          "desc": "Local priv-esc + credential harvest   (5-8 min)"},
    "6": {"name": "Full Assessment",
          "mods": ["all"],
          "desc": "All 22 modules — complete pipeline    (25-40 min)"},
    "7": {"name": "Custom",
          "mods": [],
          "desc": "Choose individual modules manually"},
}

ALL_MODS = [
    "enum","privesc","persist","loot","lateral","network","audit",
    "container","webapp","vulnscan","fuzzer","cvecheck","recon",
    "services","activedir","evasion","postexploit","apitesting",
    "passattack","wireless","dnsrecon","traffic",
]

# ── Low-level I/O ─────────────────────────────────────────────────────────────
def _prompt(label: str, default: str = "") -> str:
    dflt = f" [{C.DIM}{default}{C.RESET}{C.CYAN}]" if default else ""
    try:
        val = input(f"  {C.CYAN}{label}{dflt}: {C.RESET}").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print(); return default

def _confirm(q: str, yes: bool = True) -> bool:
    opts = f"[{C.GREEN}Y{C.RESET}/n]" if yes else f"[y/{C.RED}N{C.RESET}]"
    try:
        a = input(f"  {C.YELLOW}{q} {opts}: {C.RESET}").strip().lower()
        return yes if not a else a in ("y","yes")
    except (EOFError, KeyboardInterrupt):
        print(); return yes

# ── Validation ────────────────────────────────────────────────────────────────
def validate_ip_or_host(v: str) -> bool:
    if not v: return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return all(0 <= int(p) <= 255 for p in v.split("."))
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$', v))

def resolve_host(host: str) -> str:
    try: return socket.gethostbyname(host)
    except Exception: return host

# ── Full wizard ───────────────────────────────────────────────────────────────
def ask_target() -> dict:
    """
    Interactive 5-step wizard. Returns config dict with keys:
    target, domain, port, modules, output, verbose
    """
    _hdr("PhantomX  —  Scan Configuration Wizard")
    print(f"\n  {C.DIM}Press Enter to use the default shown in [brackets].{C.RESET}")
    print(f"  {C.RED}[!] Only scan systems you OWN or have WRITTEN permission to test.{C.RESET}\n")

    cfg = {"target":"","domain":"","port":80,"modules":[],"output":"html","verbose":False}

    # ── Step 1: Target ────────────────────────────────────────────────────────
    _step(1, 5, "Target")
    print(f"  {C.DIM}Enter the IP address or hostname you are authorised to scan.{C.RESET}\n")
    while True:
        raw = _prompt("Target IP / hostname", "127.0.0.1")
        if validate_ip_or_host(raw):
            cfg["target"] = raw
            ip = resolve_host(raw)
            if ip != raw:
                print_status(f"Resolved: {raw} → {ip}", "info")
                cfg["resolved_ip"] = ip
            print_status(f"Target accepted: {C.BOLD}{raw}{C.RESET}", "success")
            break
        print_status(f"'{raw}' is not a valid IP or hostname. "
                     f"Example: 10.10.10.5  or  target.local", "warn")
    print()

    # ── Step 2: Domain ────────────────────────────────────────────────────────
    _step(2, 5, "Domain  (optional)")
    print(f"  {C.DIM}For Active Directory / DNS modules.{C.RESET}")
    print(f"  {C.DIM}Leave blank if not needed.{C.RESET}\n")
    d = _prompt("Domain name  e.g. corp.local", "")
    cfg["domain"] = d
    print_status(f"Domain: {d}", "success") if d else print_status("Domain skipped.", "info")
    print()

    # ── Step 3: Port ──────────────────────────────────────────────────────────
    _step(3, 5, "Web Port")
    print(f"  {C.DIM}HTTP/HTTPS port for web modules. Common: 80, 443, 8080, 8443.{C.RESET}\n")
    while True:
        ps = _prompt("Web port", "80")
        try:
            port = int(ps)
            if 1 <= port <= 65535:
                cfg["port"] = port
                print_status(f"Port: {port}", "success"); break
            print_status("Port must be between 1 and 65535.", "warn")
        except ValueError:
            print_status("Please enter a valid integer.", "warn")
    print()

    # ── Step 4: Scan profile ──────────────────────────────────────────────────
    _step(4, 5, "Scan Profile")
    print(f"  {C.DIM}Choose a pre-built profile or customise your own.{C.RESET}\n")
    for k, p in PROFILES.items():
        print(f"  {C.CYAN}[{k}]{C.RESET}  {p['name']:<24} {C.DIM}{p['desc']}{C.RESET}")
    print()
    while True:
        c = _prompt("Profile number", "1")
        if c in PROFILES:
            p = PROFILES[c]
            cfg["modules"] = list(p["mods"])
            if c == "7":
                print(f"\n  {C.DIM}Available modules:{C.RESET}")
                for i, m in enumerate(ALL_MODS):
                    print(f"  {C.GREEN}{m:<14}{C.RESET}", end="\n" if (i+1)%5==0 else "")
                if len(ALL_MODS)%5: print()
                raw = _prompt("\nModules (comma-separated)", "enum,privesc,loot")
                cfg["modules"] = [m.strip() for m in raw.split(",") if m.strip() in ALL_MODS] or ["enum"]
            n = 22 if cfg["modules"]==["all"] else len(cfg["modules"])
            print_status(f"Profile: {p['name']}  ({n} module(s))", "success"); break
        print_status("Enter a number from 1–7.", "warn")
    print()

    # ── Step 5: Output & options ──────────────────────────────────────────────
    _step(5, 5, "Output & Options")
    print(f"  {C.CYAN}[1]{C.RESET}  HTML  — Dark-theme visual report  {C.GREEN}(recommended){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET}  JSON  — Machine-readable data")
    print(f"  {C.CYAN}[3]{C.RESET}  TXT   — Plain text log")
    print(f"  {C.CYAN}[4]{C.RESET}  None  — No file saved\n")
    fmap = {"1":"html","2":"json","3":"txt","4":None}
    while True:
        c = _prompt("Output format", "1")
        if c in fmap: cfg["output"] = fmap[c]; break
        print_status("Enter 1–4.", "warn")
    print()
    cfg["verbose"] = _confirm("Enable verbose output?", yes=False)
    print()

    # ── Summary + confirm ─────────────────────────────────────────────────────
    _print_summary(cfg)
    if not _confirm("Start scan with these settings?", yes=True):
        print_status("Scan cancelled.", "warn"); sys.exit(0)
    print()
    return cfg


# ── Quick prompts ─────────────────────────────────────────────────────────────
def ask_target_simple(module: str = "") -> str:
    """One-line target prompt used when a module needs --target."""
    print()
    _sep()
    msg = f"Module '{module}' requires a target." if module else "A target is required."
    print(f"  {C.YELLOW}[?]  {msg}{C.RESET}")
    print(f"  {C.DIM}     Enter the IP or hostname you are authorised to scan.{C.RESET}")
    _sep()
    print()
    while True:
        raw = _prompt("Target IP / hostname", "127.0.0.1")
        if validate_ip_or_host(raw):
            print_status(f"Target set: {raw}", "success"); print(); return raw
        print_status(f"'{raw}' is not valid. Example: 10.10.10.5  or  target.local", "warn")

def ask_domain_simple() -> str:
    """One-line domain prompt (optional)."""
    print(f"\n  {C.CYAN}[?]  Domain name for AD/DNS modules (Enter to skip):{C.RESET}")
    v = _prompt("Domain", "")
    if v: print_status(f"Domain: {v}", "success")
    return v


# ── Summary ───────────────────────────────────────────────────────────────────
def _print_summary(cfg: dict):
    print(); _sep("═")
    print(f"  {C.BOLD}  SCAN CONFIGURATION SUMMARY{C.RESET}")
    _sep("═")
    mods = cfg.get("modules", [])
    md   = "All 22 modules" if mods==["all"] else ", ".join(mods[:5])+("  …" if len(mods)>5 else "")
    rows = [
        ("Target",  cfg.get("target","?"),                         C.CYAN),
        ("Domain",  cfg.get("domain","(not set)") or "(not set)", C.CYAN),
        ("Port",    str(cfg.get("port",80)),                       C.CYAN),
        ("Modules", md,                                            C.GREEN),
        ("Output",  cfg.get("output") or "none",                   C.YELLOW),
        ("Verbose", "Yes" if cfg.get("verbose") else "No",        C.DIM),
    ]
    for lbl, val, col in rows:
        print(f"  {C.DIM}{lbl:<10}{C.RESET}  {col}{val}{C.RESET}")
    _sep("═")
    print(f"\n  {C.RED}[!] Confirm authorisation to scan:  "
          f"{C.BOLD}{cfg.get('target','?')}{C.RESET}\n")
