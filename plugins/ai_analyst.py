"""
plugins/ai_analyst.py — AI-Powered Security Analysis Plugin

Provides AI-driven analysis of PhantomX scan results using
the Anthropic Claude API.

Sub-commands (via main.py 'ai' module):
  analyse    — AI analysis of top findings with risk narrative
  chat       — Interactive Q&A about your scan results  
  report     — Generate full AI-written report narrative
  mitre      — Map findings to MITRE ATT&CK framework
  chain      — Identify most likely attack chain
  remediate  — Generate prioritised remediation plan
"""

import sys
from core.banner import print_status, print_finding, print_section, print_table, C
from core.scoring import RiskScorer
from core.ai_engine import AIEngine


def run(args, verbose=False):
    results = {}
    sub     = getattr(args, "subcommand", "analyse")

    engine = AIEngine()

    # Load session data
    has_session = engine.load_session()
    if not has_session and sub not in ("chat",):
        print_status("No scan session found. Run some modules first.", "warn")
        print_status("Example: python3 main.py privesc --output json", "info")

    # Load scored findings
    scorer = RiskScorer()
    findings = []
    if scorer.load():
        scorer.score()
        findings = scorer.scored_findings

    print_status(f"AI Engine initialised — {len(findings)} scored findings loaded.", "info")
    print_status(f"Calling Anthropic Claude API…", "info")
    print()

    try:
        if sub == "analyse":
            _run_analyse(engine, findings, verbose)

        elif sub == "chat":
            _run_chat(engine, verbose)

        elif sub == "report":
            _run_report(engine, verbose)

        elif sub == "mitre":
            _run_mitre(engine, findings, verbose)

        elif sub == "chain":
            _run_chain(engine, verbose)

        elif sub == "remediate":
            _run_remediate(engine, findings, verbose)

        else:
            print_status(f"Unknown AI sub-command: {sub}", "error")

    except RuntimeError as e:
        if "API error" in str(e) or "API call failed" in str(e):
            print_status(f"AI API Error: {e}", "error")
            print_status("Check your API key and internet connection.", "warn")
        else:
            raise

    return results


# ── Sub-command handlers ──────────────────────────────────────────────────────

def _run_analyse(engine, findings, verbose):
    print_section("  AI FINDING ANALYSIS  ")
    print_status("Sending findings to Claude for analysis…", "info")
    print()

    response = engine.analyse_findings(findings)
    _print_ai_response(response)


def _run_chat(engine, verbose):
    print_section("  AI SECURITY CHAT  ")
    print_status("Interactive Q&A about your scan results.", "info")
    print_status("Type 'quit' or 'exit' to leave, 'reset' to clear history.", "info")
    print()

    while True:
        try:
            user_input = input(
                f"  {C.CYAN}You{C.RESET} › "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            break
        if user_input.lower() == "reset":
            engine.reset_chat()
            print_status("Conversation history cleared.", "info")
            continue

        print()
        print_status("Claude is thinking…", "info")
        print()

        try:
            response = engine.chat(user_input)
            _print_ai_response(response)
        except RuntimeError as e:
            print_status(f"Error: {e}", "error")
        print()

    print_status("Chat session ended.", "info")


def _run_report(engine, verbose):
    print_section("  AI REPORT NARRATIVE  ")
    print_status("Generating executive summary narrative…", "info")
    print()

    response = engine.generate_report_narrative()
    _print_ai_response(response)

    # Save to file
    from pathlib import Path
    import datetime
    out_dir = Path(__file__).parent.parent / "reports"
    out_dir.mkdir(exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"ai_report_{ts}.md"
    path.write_text(f"# PhantomX AI Security Report\n\n{response}\n")
    print()
    print_status(f"Report saved → {path}", "success")


def _run_mitre(engine, findings, verbose):
    print_section("  MITRE ATT&CK MAPPING  ")
    print_status("Mapping findings to MITRE ATT&CK framework…", "info")
    print()

    mapped = engine.mitre_mapping(findings)
    if not mapped:
        print_status("No MITRE mappings for current findings.", "miss")
        return

    rows = [
        (m["technique"], m["name"][:45], m.get("severity","?").upper(),
         m.get("finding","")[:30])
        for m in mapped
    ]
    print_table(["Technique", "Name", "Severity", "Finding"], rows)
    print()

    # AI explanation of the MITRE profile
    technique_list = "\n".join(
        f"- {m['technique']}: {m['name']}" for m in mapped[:8]
    )
    prompt = (
        f"Summarise this MITRE ATT&CK technique profile for a "
        f"security assessment report:\n\n{technique_list}\n\n"
        "In 3-4 sentences, describe what adversary capabilities "
        "this target is vulnerable to."
    )
    response = engine._call([{"role": "user", "content": prompt}])
    print_status("AI MITRE Summary:", "info")
    _print_ai_response(response)


def _run_chain(engine, verbose):
    print_section("  AI ATTACK CHAIN ANALYSIS  ")
    print_status("Analysing most likely adversary attack path…", "info")
    print()

    response = engine.suggest_attack_chain()
    _print_ai_response(response)


def _run_remediate(engine, findings, verbose):
    print_section("  AI REMEDIATION PLAN  ")
    print_status("Generating prioritised remediation roadmap…", "info")
    print()

    response = engine.generate_remediation_plan(findings)
    _print_ai_response(response)

    # Save to file
    from pathlib import Path
    import datetime
    out_dir = Path(__file__).parent.parent / "reports"
    out_dir.mkdir(exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"ai_remediation_{ts}.md"
    path.write_text(
        f"# PhantomX AI Remediation Plan\n\n{response}\n"
    )
    print()
    print_status(f"Plan saved → {path}", "success")


# ── Output formatter ──────────────────────────────────────────────────────────

def _print_ai_response(text: str):
    """Print AI response with basic markdown-like formatting."""
    for line in text.splitlines():
        # Headers
        if line.startswith("## "):
            print(f"\n  {C.CYAN}{C.BOLD}{line[3:]}{C.RESET}")
            print(f"  {C.CYAN}{'─' * min(60, len(line))}{C.RESET}")
        elif line.startswith("# "):
            print(f"\n  {C.MAGENTA}{C.BOLD}{line[2:]}{C.RESET}\n")
        # Numbered list
        elif line.strip() and line.strip()[0].isdigit() and ". " in line:
            print(f"  {C.YELLOW}{line.strip()}{C.RESET}")
        # Bullet
        elif line.strip().startswith("- ") or line.strip().startswith("* "):
            print(f"  {C.DIM}•{C.RESET} {line.strip()[2:]}")
        # Bold-ish (lines with ALL CAPS words)
        elif line.strip().isupper() and line.strip():
            print(f"  {C.BOLD}{line}{C.RESET}")
        else:
            print(f"  {line}")
