"""
core/banner.py — ASCII banner & terminal color helpers
"""

import os
import sys
from datetime import datetime

# ── ANSI color codes ──────────────────────────────────────────────────────────
NO_COLOR = os.environ.get("NO_COLOR", "")

class C:
    """Terminal color constants."""
    RED     = "\033[91m"  if not NO_COLOR else ""
    GREEN   = "\033[92m"  if not NO_COLOR else ""
    YELLOW  = "\033[93m"  if not NO_COLOR else ""
    BLUE    = "\033[94m"  if not NO_COLOR else ""
    MAGENTA = "\033[95m"  if not NO_COLOR else ""
    CYAN    = "\033[96m"  if not NO_COLOR else ""
    WHITE   = "\033[97m"  if not NO_COLOR else ""
    BOLD    = "\033[1m"   if not NO_COLOR else ""
    DIM     = "\033[2m"   if not NO_COLOR else ""
    RESET   = "\033[0m"   if not NO_COLOR else ""
    UNDER   = "\033[4m"   if not NO_COLOR else ""


BANNER = fr"""
{C.RED}{C.BOLD}
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗  ██╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║╚██╗██╔╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║ ╚███╔╝ 
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║ ██╔██╗ 
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
{C.RESET}{C.CYAN}
          Advanced Post-Exploitation Framework  |  Red Team Edition
          ─────────────────────────────────────────────────────────
          {C.DIM}[!] FOR AUTHORIZED PENETRATION TESTING ONLY{C.RESET}{C.CYAN}
          {C.DIM}    Unauthorized use is illegal and unethical.{C.RESET}
"""

STATUS_ICONS = {
    "success": (C.GREEN,   "[+]"),
    "error":   (C.RED,     "[-]"),
    "warn":    (C.YELLOW,  "[!]"),
    "info":    (C.CYAN,    "[*]"),
    "section": (C.MAGENTA, "[>]"),
    "found":   (C.GREEN,   "[✓]"),
    "miss":    (C.DIM,     "[·]"),
    "critical":(C.RED + C.BOLD, "[!!!]"),
}


def print_banner():
    print(BANNER)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  {C.DIM}Session started: {now}{C.RESET}")
    print(f"  {C.DIM}User: {os.getenv('USER','unknown')}  |  Host: {os.uname().nodename}{C.RESET}\n")
    print(f"  {C.YELLOW}{'─' * 66}{C.RESET}\n")


def print_status(message: str, level: str = "info"):
    color, icon = STATUS_ICONS.get(level, (C.WHITE, "[*]"))
    print(f"  {color}{icon}{C.RESET} {message}")


def print_section(title: str):
    width = 60
    line = "─" * width
    print(f"\n  {C.MAGENTA}{C.BOLD}┌{line}┐")
    padded = title.center(width)
    print(f"  │{padded}│")
    print(f"  └{line}┘{C.RESET}\n")


def print_table(headers: list, rows: list, color=C.CYAN):
    """Print a simple ASCII table."""
    if not rows:
        print_status("No results found.", "miss")
        return

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    sep = "  +" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    fmt = "  |" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"

    print(sep)
    print(f"{color}" + fmt.format(*headers) + f"{C.RESET}")
    print(sep)
    for row in rows:
        padded = [str(row[i]) if i < len(row) else "" for i in range(len(headers))]
        print(fmt.format(*padded))
    print(sep + "\n")


def print_finding(title: str, detail: str, severity: str = "info"):
    """Print a single finding with severity badge."""
    sev_colors = {
        "critical": C.RED + C.BOLD,
        "high":     C.RED,
        "medium":   C.YELLOW,
        "low":      C.CYAN,
        "info":     C.DIM,
    }
    sc = sev_colors.get(severity, C.WHITE)
    badge = f"[{severity.upper()}]"
    print(f"  {sc}{badge}{C.RESET}  {C.BOLD}{title}{C.RESET}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"           {C.DIM}{line}{C.RESET}")
    print()
