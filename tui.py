#!/usr/bin/env python3
"""
tui.py — PhantomX 3-Panel Interactive TUI
Startup screen asks for target + domain before entering main menu.
"""
import curses, os, re, sys, threading, subprocess, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent
PX   = [sys.executable, str(ROOT / "main.py")]

MODULES = [
    ("ALL MODULES",  "all",         "Run all 22 modules"),
    ("──────────",   None,          ""),
    ("Enumerate",    "enum",        "OS, users, network, processes"),
    ("Priv-Esc",     "privesc",     "SUID, sudo, cron, kernel CVEs"),
    ("Persistence",  "persist",     "Crontab, SSH, systemd"),
    ("Loot",         "loot",        "Creds, keys, cloud, browser"),
    ("Lateral Move", "lateral",     "ARP, SSH, shares"),
    ("Network",      "network",     "Port scan, banners, firewall"),
    ("Audit",        "audit",       "Password policy, SSH, logging"),
    ("Container",    "container",   "Docker / K8s escape"),
    ("Web App",      "webapp",      "Headers, CORS, SSL, paths"),
    ("Vuln Scan",    "vulnscan",    "OWASP CWE Top 25"),
    ("Fuzzer",       "fuzzer",      "Parameter, header, encoding"),
    ("CVE Check",    "cvecheck",    "300+ CVE banner matching"),
    ("Recon",        "recon",       "OSINT, subdomain, WAF/CDN"),
    ("Services",     "services",    "SMB, SNMP, SSH, LDAP, FTP"),
    ("Active Dir",   "activedir",   "AD enum, Kerberoast"),
    ("Evasion",      "evasion",     "Firewall evasion, pivot guide"),
    ("Post-Exploit", "postexploit", "Post-exploitation techniques"),
    ("API Testing",  "apitesting",  "OWASP API Top 10 + JWT"),
    ("Pass Attack",  "passattack",  "Default creds, spray, hashes"),
    ("Wireless",     "wireless",    "WPA2, WPS, rogue AP"),
    ("DNS Recon",    "dnsrecon",    "AXFR, DNSSEC, takeover"),
    ("Traffic",      "traffic",     "LLMNR, ARP, cleartext creds"),
    ("──────────",   None,          ""),
    ("Risk Score",   "score",       "CVSS-like risk scoring"),
    ("Report HTML",  "rhtml",       "Generate HTML report"),
    ("Report JSON",  "rjson",       "Generate JSON report"),
    ("Help Page",    "helppage",    "Open HTML command reference"),
    ("Exit",         "exit",        "Quit PhantomX"),
]

NEEDS_TARGET = {
    "network","webapp","vulnscan","fuzzer","cvecheck","apitesting",
    "passattack","services","activedir","evasion","postexploit",
    "recon","dnsrecon","traffic","all",
}

# Colour pair numbers
CB=1; CT=2; CN=3; CS=4; CR=5; CG=6; CY=7; CD=8; CC=9; CX=10


class TUI:
    def __init__(self, scr):
        self.scr      = scr
        self.sel      = 0
        self.log      = []
        self.status   = "Ready  |  t=target  d=domain  Enter=run  h=help  q=quit"
        self.running  = False
        self.target   = ""
        self.domain   = ""
        self.history  = []
        self.mstates  = {}
        self.counts   = dict(critical=0, high=0, medium=0, low=0, total=0)
        self._init_colors()
        self._skip_sep()

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(CB, curses.COLOR_RED,    -1)
        curses.init_pair(CT, curses.COLOR_MAGENTA,-1)
        curses.init_pair(CN, curses.COLOR_WHITE,  -1)
        curses.init_pair(CS, curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(CR, curses.COLOR_RED,    -1)
        curses.init_pair(CG, curses.COLOR_GREEN,  -1)
        curses.init_pair(CY, curses.COLOR_YELLOW, -1)
        curses.init_pair(CD, curses.COLOR_WHITE,  -1)
        curses.init_pair(CC, curses.COLOR_CYAN,   -1)
        curses.init_pair(CX, curses.COLOR_BLACK,  curses.COLOR_WHITE)

    def _skip_sep(self):
        while self.sel < len(MODULES) and MODULES[self.sel][1] is None:
            self.sel += 1

    # ── Safe write ────────────────────────────────────────────────────────────
    def _put(self, y, x, txt, attr=0):
        H, W = self.scr.getmaxyx()
        if y < 0 or y >= H or x < 0 or x >= W:
            return
        try:
            self.scr.addstr(y, x, txt[:max(0, W-x)], attr)
        except curses.error:
            pass

    # ═════════════════════════════════════════════════════════════════════════
    # STARTUP WIZARD — asks target + domain before main menu
    # ═════════════════════════════════════════════════════════════════════════
    def startup_wizard(self):
        H, W = self.scr.getmaxyx()
        self.scr.erase()

        # ── Header ────────────────────────────────────────────────────────────
        hdr = "  ⚔  PhantomX v6.0  —  Configure Scan Target"
        self._put(0, 0, " "*W, curses.color_pair(CB)|curses.A_BOLD)
        self._put(0, 0, hdr[:W], curses.color_pair(CB)|curses.A_BOLD)

        # ── Body lines ────────────────────────────────────────────────────────
        body = [
            (2,  "  Welcome to PhantomX — Advanced Security Assessment Framework",
             curses.color_pair(CN)|curses.A_BOLD),
            (4,  "  Configure your scan target before entering the main menu.",
             curses.color_pair(CD)|curses.A_DIM),
            (5,  "  Press Enter to accept the default shown in  [ ].  Press Ctrl-C to quit.",
             curses.color_pair(CD)|curses.A_DIM),
            (7,  "  ─"*(W//3),
             curses.color_pair(CT)|curses.A_DIM),
            (9,  "  [!]  Only scan systems you OWN or have WRITTEN permission to test.",
             curses.color_pair(CY)|curses.A_BOLD),
            (10, "       Unauthorized use is illegal and unethical.",
             curses.color_pair(CY)),
            (12, "  ─"*(W//3),
             curses.color_pair(CT)|curses.A_DIM),
        ]
        for row, text, attr in body:
            self._put(row, 0, text[:W], attr)

        # ── Collect target ────────────────────────────────────────────────────
        row = 14
        self._put(row, 2,
                  "  TARGET  —  IP address or hostname of your authorised scan target",
                  curses.color_pair(CC)|curses.A_BOLD)
        self._put(row+1, 2,
                  "  Examples:   10.10.10.5     192.168.1.1     target.local",
                  curses.color_pair(CD)|curses.A_DIM)
        self.scr.refresh()
        self.target = self._getstr(row+3, "  Target IP / hostname", "127.0.0.1")
        if not self.target:
            self.target = "127.0.0.1"

        # ── Collect domain ────────────────────────────────────────────────────
        row2 = row + 5
        self._put(row2, 2,
                  "  ─"*(W//3),
                  curses.color_pair(CT)|curses.A_DIM)
        self._put(row2+1, 2,
                  "  DOMAIN  —  For Active Directory / DNS modules  (leave blank to skip)",
                  curses.color_pair(CC)|curses.A_BOLD)
        self._put(row2+2, 2,
                  "  Examples:   corp.local     domain.internal     (or press Enter to skip)",
                  curses.color_pair(CD)|curses.A_DIM)
        self.scr.refresh()
        self.domain = self._getstr(row2+4, "  Domain name  (optional)", "")

        # ── Confirmation ──────────────────────────────────────────────────────
        row3 = row2 + 6
        self._put(row3, 2, "  ─"*(W//3), curses.color_pair(CT)|curses.A_DIM)
        self._put(row3+1, 2,
                  f"  ✓  Target : {self.target}",
                  curses.color_pair(CG)|curses.A_BOLD)
        if self.domain:
            self._put(row3+2, 2,
                      f"  ✓  Domain : {self.domain}",
                      curses.color_pair(CG)|curses.A_BOLD)
            row3 += 1
        self._put(row3+2, 2,
                  "  Press any key to enter the main menu  ...",
                  curses.color_pair(CY)|curses.A_BOLD)
        self.scr.refresh()
        self.scr.timeout(-1)
        self.scr.getch()

        # Set status line
        self.status = (f"Target: {self.target}" +
                       (f"  |  Domain: {self.domain}" if self.domain else ""))

    def _getstr(self, row, label, default):
        """Render a labelled input on the wizard screen, return user value."""
        H, W = self.scr.getmaxyx()
        dflt_disp = f"  [{default}]" if default else "  [blank to skip]"
        prompt    = f"{label}{dflt_disp}: "
        self._put(row, 2, prompt, curses.color_pair(CC)|curses.A_BOLD)
        col = 2 + len(prompt)
        self.scr.refresh()
        curses.echo()
        curses.curs_set(1)
        try:
            raw = self.scr.getstr(row, col, 60).decode("utf-8").strip()
            val = raw if raw else default
        except Exception:
            val = default
        finally:
            curses.noecho()
            curses.curs_set(0)
        # Show accepted value in green
        self._put(row, col, (val or "(none)").ljust(60), curses.color_pair(CG))
        self.scr.refresh()
        return val

    # ═════════════════════════════════════════════════════════════════════════
    # MAIN LOOP
    # ═════════════════════════════════════════════════════════════════════════
    def loop(self):
        curses.curs_set(0)
        self.scr.keypad(True)
        self.scr.timeout(200)

        # Always show target wizard first
        self.startup_wizard()

        while True:
            try:
                self._draw()
            except curses.error:
                pass

            k = self.scr.getch()
            if k == curses.KEY_RESIZE:
                self.scr.clear(); continue
            if   k in (ord("q"), ord("Q"), 27):            break
            elif k in (curses.KEY_UP,    ord("k")):         self._move(-1)
            elif k in (curses.KEY_DOWN,  ord("j")):         self._move(1)
            elif k in (curses.KEY_ENTER, 10, 13,
                       curses.KEY_RIGHT):                   self._go()
            elif k in (ord("t"), ord("T")):                 self._change("target")
            elif k in (ord("d"), ord("D")):                 self._change("domain")
            elif k in (ord("c"), ord("C")):
                self.log = []
                self.counts = dict(critical=0,high=0,medium=0,low=0,total=0)
                self.status = "Log cleared."
            elif k in (ord("h"), ord("H")):                 self._help()
            elif k in (ord("s"), ord("S")):                 self._score()
            elif k in (ord("r"), ord("R")):
                self._exec("report","--format","html")

    def _move(self, d):
        self.sel = (self.sel + d) % len(MODULES)
        self._skip_sep()

    def _go(self):
        label, cmd, _ = MODULES[self.sel]
        if not cmd:             return
        if cmd == "exit":       raise SystemExit(0)
        if cmd == "helppage":
            hp = str(ROOT/"dashboard"/"help.html")
            subprocess.Popen(
                f"xdg-open '{hp}' 2>/dev/null || firefox '{hp}' 2>/dev/null",
                shell=True)
            return
        if cmd == "score":      self._score(); return
        if cmd == "rhtml":      self._exec("report","--format","html"); return
        if cmd == "rjson":      self._exec("report","--format","json"); return

        # Ask for target inline if needed and not set
        if cmd in NEEDS_TARGET and not self.target:
            self._change("target")
            if not self.target:
                self.status = f"'{cmd}' needs a target — press 't' to set one."
                return

        extra = []
        if cmd in NEEDS_TARGET and self.target:
            extra += ["--target", self.target]
        if cmd in ("activedir","recon","dnsrecon") and self.domain:
            extra += ["--domain", self.domain]
        self._exec(cmd, *extra)

    def _exec(self, *argv):
        if self.running:
            self.status = "A module is already running — please wait."; return
        self.running  = True
        cmd           = argv[0]
        self.mstates[cmd] = "run"
        ts = datetime.now().strftime("%H:%M:%S")
        self.log += ["", f"  [{ts}]  ── Starting: {' '.join(argv)} ──"]

        def work():
            try:
                proc = subprocess.Popen(
                    PX + list(argv),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                for line in proc.stdout:
                    cl = re.sub(r"\033\[[0-9;]*[mK]", "", line.rstrip())
                    self.log.append(cl)
                    ll = cl.lower()
                    if   "critical" in ll: self.counts["critical"]+=1; self.counts["total"]+=1
                    elif "high"     in ll: self.counts["high"]+=1;     self.counts["total"]+=1
                    elif "medium"   in ll: self.counts["medium"]+=1;   self.counts["total"]+=1
                    elif "low"      in ll: self.counts["low"]+=1;      self.counts["total"]+=1
                    if len(self.log) > 1000: self.log = self.log[-800:]
                proc.wait()
                ok  = proc.returncode == 0
                ts2 = datetime.now().strftime("%H:%M:%S")
                self.mstates[cmd] = "ok" if ok else "err"
                self.log.append(f"  [{ts2}]  ── Done: {cmd}  rc={proc.returncode} ──")
                self.history.insert(0, (ts2, cmd, "ok" if ok else "err"))
                self.history = self.history[:25]
                self.status  = f"Done: {cmd}  |  findings: {self.counts['total']}"
            except Exception as e:
                self.log.append(f"  ERROR: {e}")
                self.mstates[cmd] = "err"
                self.status = f"Error: {e}"
            finally:
                self.running = False

        threading.Thread(target=work, daemon=True).start()
        self.status = f"Running {cmd}  |  target: {self.target or 'localhost'}..."

    # ═════════════════════════════════════════════════════════════════════════
    # DRAW
    # ═════════════════════════════════════════════════════════════════════════
    def _draw(self):
        H, W = self.scr.getmaxyx()
        self.scr.erase()
        mw = min(30, W//4)
        sw = min(26, W//5)
        lw = max(10, W - mw - sw - 4)
        lc, sc = mw+2, mw+2+lw+2
        self._draw_header(W)
        self._draw_menu(H, mw)
        self._draw_vline(H, mw+1)
        self._draw_log(H, lc, lw)
        self._draw_vline(H, sc-1)
        self._draw_sidebar(H, sc, sw)
        self._draw_statusbar(H, W)
        self.scr.refresh()

    def _draw_header(self, W):
        tgt = self.target or "NOT SET — press t"
        hdr = f"  [*] PHANTOMX v6.0  |  Target: {tgt}  |  Domain: {self.domain or 'none'}  |  Findings: {self.counts['total']}"
        self._put(0, 0, " "*W, curses.color_pair(CB)|curses.A_BOLD)
        self._put(0, 0, hdr[:W], curses.color_pair(CB)|curses.A_BOLD)

    def _draw_menu(self, H, mw):
        self._put(1, 0, "─"*mw, curses.color_pair(CD)|curses.A_DIM)
        self._put(2, 1, " MODULES", curses.color_pair(CT)|curses.A_BOLD)
        self._put(3, 0, "─"*mw, curses.color_pair(CD)|curses.A_DIM)
        vis = max(0, self.sel - (H-8)//2)
        row = 4
        for i in range(vis, len(MODULES)):
            if row >= H-2: break
            label, cmd, _ = MODULES[i]
            if cmd is None:
                self._put(row, 1, "─"*(mw-2), curses.color_pair(CD)|curses.A_DIM)
                row += 1; continue
            st     = self.mstates.get(cmd,"")
            ico    = {"ok":"[+]","err":"[-]","run":"[~]"}.get(st,"   ")
            no_tgt = cmd in NEEDS_TARGET and not self.target
            line   = f"{ico} {label}" + (" [?]" if no_tgt else "")
            if i == self.sel:
                self._put(row, 0, " "*mw, curses.color_pair(CS))
                self._put(row, 0, line[:mw], curses.color_pair(CS)|curses.A_BOLD)
            else:
                attr = (curses.color_pair(CR)|curses.A_BOLD if cmd=="all" else
                        curses.color_pair(CD)|curses.A_DIM  if cmd in("exit","helppage") else
                        curses.color_pair(CC)               if cmd in("score","rhtml","rjson") else
                        curses.color_pair(CY)               if no_tgt else
                        curses.color_pair(CN))
                self._put(row, 0, line[:mw], attr)
            row += 1

    def _draw_vline(self, H, col):
        for r in range(1, H-2):
            self._put(r, col, "│", curses.color_pair(CD)|curses.A_DIM)

    def _draw_log(self, H, col, width):
        self._put(1, col, "─"*width, curses.color_pair(CD)|curses.A_DIM)
        self._put(2, col, " OUTPUT LOG",  curses.color_pair(CT)|curses.A_BOLD)
        self._put(3, col, "─"*width, curses.color_pair(CD)|curses.A_DIM)
        for i, line in enumerate(self.log[-(H-6):]):
            r = 4+i
            if r >= H-2: break
            ll   = line.lower()
            attr = curses.color_pair(CD)|curses.A_DIM
            if   "[+]" in line or "success" in ll: attr = curses.color_pair(CG)
            elif "critical" in ll or "error" in ll: attr = curses.color_pair(CR)|curses.A_BOLD
            elif "high" in ll or "[!]" in line:    attr = curses.color_pair(CY)
            elif "[*]" in line or "scan" in ll:    attr = curses.color_pair(CC)
            elif "──" in line or "Starting" in line or "Done" in line:
                attr = curses.color_pair(CT)
            self._put(r, col, line[:width], attr)
        if self.running:
            sp = "/-\\|"
            self._put(H-3, col+width-2,
                      sp[int(time.time()*4)%4],
                      curses.color_pair(CY)|curses.A_BOLD)

    def _draw_sidebar(self, H, col, width):
        self._put(1, col, "─"*width, curses.color_pair(CD)|curses.A_DIM)
        self._put(2, col, " STATS",  curses.color_pair(CT)|curses.A_BOLD)
        self._put(3, col, "─"*width, curses.color_pair(CD)|curses.A_DIM)
        row = 4
        for lbl, key, attr in [
            ("CRITICAL","critical",curses.color_pair(CR)|curses.A_BOLD),
            ("HIGH",    "high",    curses.color_pair(CR)),
            ("MEDIUM",  "medium",  curses.color_pair(CY)),
            ("LOW",     "low",     curses.color_pair(CC)),
            ("TOTAL",   "total",   curses.color_pair(CN)|curses.A_BOLD),
        ]:
            self._put(row, col, f"  {lbl:<8} {self.counts[key]:>4}", attr); row+=1
        row+=1
        self._put(row, col,"─"*width,curses.color_pair(CD)|curses.A_DIM); row+=1
        self._put(row, col," HISTORY",curses.color_pair(CD)|curses.A_DIM); row+=1
        for ts, mod, st in self.history[-(H-row-4):]:
            if row >= H-4: break
            self._put(row, col,
                      f"  {'[+]' if st=='ok' else '[-]'} {ts} {mod[:9]}",
                      curses.color_pair(CG if st=='ok' else CR))
            row+=1
        self._put(H-3, col, f"  {datetime.now().strftime('%H:%M:%S')}",
                  curses.color_pair(CD)|curses.A_DIM)
        tgt  = (self.target or "NOT SET")[:width-3]
        self._put(H-2, col, f"  {tgt}",
                  curses.color_pair(CG if self.target else CR)|curses.A_BOLD)

    def _draw_statusbar(self, H, W):
        self._put(H-1, 0, " "*W, curses.color_pair(CX))
        self._put(H-1, 0, f"  {self.status}"[:W//2], curses.color_pair(CX))
        keys = " [t]Target [d]Domain [s]Score [c]Clear [h]Help [q]Quit"
        self._put(H-1, max(0,W-len(keys)-1), keys[:W//2+5], curses.color_pair(CX))

    # ═════════════════════════════════════════════════════════════════════════
    # INLINE PROMPTS  (used during main loop to update target/domain)
    # ═════════════════════════════════════════════════════════════════════════
    def _change(self, field: str):
        H, W = self.scr.getmaxyx()
        if field == "target":
            label   = f"  Enter new Target IP / hostname  [{self.target or '127.0.0.1'}]: "
            default = self.target or "127.0.0.1"
        else:
            label   = f"  Enter Domain name  [{self.domain or 'blank=skip'}]: "
            default = self.domain

        self._put(H-1, 0, " "*W, curses.color_pair(CC)|curses.A_BOLD)
        self._put(H-1, 0, label, curses.color_pair(CC)|curses.A_BOLD)
        curses.echo(); curses.curs_set(1)
        try:
            val = self.scr.getstr(H-1, len(label), 60).decode("utf-8").strip()
            val = val or default
        except Exception:
            val = default
        finally:
            curses.noecho(); curses.curs_set(0)

        if field == "target":
            self.target = val
            self.status = f"Target set → {self.target}"
        else:
            self.domain = val
            self.status = f"Domain set → {self.domain}" if self.domain else "Domain cleared."

    # ═════════════════════════════════════════════════════════════════════════
    # OVERLAYS
    # ═════════════════════════════════════════════════════════════════════════
    def _overlay(self, title, lines, title_attr=None):
        H, W  = self.scr.getmaxyx()
        bh    = min(len(lines)+6, H-4)
        bw    = min(max((len(l) for l in lines), default=40)+6, W-8)
        win   = curses.newwin(bh, bw, max(0,(H-bh)//2), max(0,(W-bw)//2))
        win.bkgd(" ", curses.color_pair(CN))
        win.border()
        ta = title_attr or (curses.color_pair(CC)|curses.A_BOLD)
        try: win.addstr(0, 2, f" {title} ", ta)
        except curses.error: pass
        for i, line in enumerate(lines[:bh-4]):
            attr = curses.color_pair(CD)|curses.A_DIM
            if "Critical" in line: attr = curses.color_pair(CR)|curses.A_BOLD
            elif "High"    in line: attr = curses.color_pair(CR)
            elif "Overall" in line: attr = curses.color_pair(CY)|curses.A_BOLD
            elif line.strip().startswith("->"): attr = curses.color_pair(CG)
            try: win.addstr(i+2, 2, line[:bw-4], attr)
            except curses.error: pass
        try: win.addstr(bh-1, 2, " Press any key ", curses.color_pair(CY))
        except curses.error: pass
        win.refresh(); win.getch()

    def _help(self):
        self._overlay("KEY BINDINGS", [
            " Navigation",
            " ─────────────────────────────────",
            " ↑ / k       Move up",
            " ↓ / j       Move down",
            " Enter / →   Run selected module",
            " q / Esc     Quit",
            "",
            " Actions",
            " ─────────────────────────────────",
            " t           Set target IP / hostname",
            " d           Set domain name",
            " c           Clear output log",
            " s           Risk score summary",
            " r           Generate HTML report",
            " h           This help screen",
            "",
            " Modules marked [?] need a target.",
            " Press 't' to set it before running.",
            "",
            " [!] Authorized testing only",
        ])

    def _score(self):
        sf = ROOT/"reports"/".last_session.json"
        lines = []
        if sf.exists():
            try:
                sys.path.insert(0, str(ROOT))
                from core.scoring import RiskScorer
                sc = RiskScorer()
                if sc.load():
                    sc.score()
                    ov  = sc.get_overall_risk()
                    cnt = {}
                    for f in sc.scored_findings:
                        cnt[f["severity"]] = cnt.get(f["severity"],0)+1
                    lines = [
                        f"  Overall Risk : {ov:.1f} / 10.0","",
                        f"  Critical : {cnt.get('critical',0)}",
                        f"  High     : {cnt.get('high',0)}",
                        f"  Medium   : {cnt.get('medium',0)}",
                        f"  Low      : {cnt.get('low',0)}","",
                        "  Top Findings:",
                    ]
                    for f in sc.scored_findings[:5]:
                        lines.append(
                            f"  [{f['score']:.1f}] {f['severity'].upper():<8} {f['key'][:28]}")
                    lines += ["","  Remediations:"]
                    for f in sc.scored_findings[:3]:
                        lines.append(f"  -> {f['remediation'][:50]}")
                else:
                    lines = ["  No session data.","  Run some modules first."]
            except Exception as e:
                lines = [f"  Error: {e}"]
        else:
            lines = ["  No session data. Run modules first."]
        self._overlay("RISK SCORE SUMMARY", lines,
                      curses.color_pair(CR)|curses.A_BOLD)


def main():
    def _run(scr):
        t = TUI(scr)
        try:    t.loop()
        except SystemExit: pass
        except Exception:  pass
    try:
        curses.wrapper(_run)
    except KeyboardInterrupt:
        pass
    print("\n  PhantomX TUI closed.\n")


if __name__ == "__main__":
    main()
