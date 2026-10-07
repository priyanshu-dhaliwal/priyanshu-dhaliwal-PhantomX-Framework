"""
core/ai_engine.py — PhantomX AI Integration Module

Integrates with Anthropic Claude API to provide:
  1. Intelligent finding analysis — explains what each finding means
  2. Risk narrative generation — writes executive summary in plain English
  3. Remediation advisor — context-aware fix recommendations
  4. Threat modelling — maps findings to MITRE ATT&CK techniques
  5. Chat interface — ask questions about your scan results
  6. Automated report narrative — turns raw JSON into readable prose
  7. False positive assessment — estimates likelihood of each finding
  8. Attack chain analysis — identifies multi-step exploitation paths
"""

import json
import os
import re
from pathlib import Path
from typing import Generator

SESSION_FILE = Path(__file__).parent.parent / "reports" / ".last_session.json"

# MITRE ATT&CK technique mapping for common findings
MITRE_MAP = {
    "suid_interesting":    ("T1548.001", "Abuse Elevation Control Mechanism: Setuid/Setgid"),
    "sudo_findings":       ("T1548.003", "Abuse Elevation Control Mechanism: Sudo"),
    "cron_writable":       ("T1053.003", "Scheduled Task/Job: Cron"),
    "ssh_keys":            ("T1552.004", "Unsecured Credentials: Private Keys"),
    "shadow":              ("T1003.008", "OS Credential Dumping: /etc/shadow"),
    "cloud_creds":         ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata"),
    "history_cred_hits":   ("T1552.003", "Unsecured Credentials: Bash History"),
    "kerberoastable":      ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    "asreproastable":      ("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
    "delegation":          ("T1134.001", "Access Token Manipulation: Token Impersonation"),
    "docker_socket":       ("T1611",     "Escape to Host"),
    "cloud_metadata":      ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata"),
    "llmnr_nbtns":         ("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning"),
    "sqli":                ("T1190",     "Exploit Public-Facing Application"),
    "xss":                 ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "ssrf":                ("T1090",     "Proxy"),
    "default_creds":       ("T1078.001", "Valid Accounts: Default Accounts"),
    "laps":                ("T1552.002", "Unsecured Credentials: Credentials in Registry"),
    "open_ports":          ("T1046",     "Network Service Discovery"),
    "zone_transfers":      ("T1018",     "Remote System Discovery"),
    "profile_injections":  ("T1546.004", "Event Triggered Execution: Unix Shell Configuration"),
}

AI_SYSTEM_PROMPT = """You are PhantomX AI — an expert cybersecurity analyst assistant 
embedded in the PhantomX Red Team Assessment Framework.

Your role:
- Analyse penetration test findings from authorized security assessments
- Explain vulnerabilities in clear, technical language
- Suggest specific, actionable remediation steps
- Map findings to MITRE ATT&CK techniques
- Identify attack chains and exploitation paths
- Write professional security report sections

Always:
- Be precise and technical
- Prioritise findings by exploitability and impact
- Explain WHY something is dangerous, not just that it is
- Provide concrete fix commands where possible
- Reference relevant CVEs, standards (CIS, NIST, OWASP) where appropriate

Never generate actual exploit code, malware, or attack tooling.
Your output is for defensive awareness and remediation on authorized systems."""


class AIEngine:
    """PhantomX AI Engine — wraps Anthropic API for security analysis."""

    def __init__(self):
        self.session_data = {}
        self.conversation = []   # multi-turn chat history

    def load_session(self) -> bool:
        """Load the last PhantomX scan session."""
        if not SESSION_FILE.exists():
            return False
        try:
            with open(SESSION_FILE) as f:
                self.session_data = json.load(f)
            return True
        except Exception:
            return False

    # ── Core API call ─────────────────────────────────────────────────────────

    def _call(self, messages: list, system: str = None,
              max_tokens: int = 1500, stream: bool = False):
        """
        Call the Anthropic Messages API.
        Returns the response text or streams it.
        """
        import urllib.request
        import urllib.error

        payload = {
            "model":      "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "system":     system or AI_SYSTEM_PROMPT,
            "messages":   messages,
        }
        body = json.dumps(payload).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "Content-Type":      "application/json",
                "anthropic-version": "2023-06-01",
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            raise RuntimeError(f"API error {e.code}: {err_body[:200]}")
        except Exception as e:
            raise RuntimeError(f"API call failed: {e}")

    # ── Public methods ────────────────────────────────────────────────────────

    def analyse_findings(self, findings: list) -> str:
        """
        Given a list of scored findings, return an AI analysis
        explaining the risk, context, and exploitation potential.
        """
        if not findings:
            return "No findings to analyse."

        top = findings[:8]
        findings_text = "\n".join(
            f"- [{f['severity'].upper()}] {f['key']} "
            f"(score {f['score']:.1f}): {f.get('remediation','')}"
            for f in top
        )
        prompt = f"""Analyse these security findings from a penetration test:

{findings_text}

Provide:
1. A 2-sentence executive summary of the overall risk posture
2. The 3 most critical findings and why they are dangerous
3. The most likely attack chain an adversary would use
4. Top 3 immediate remediation actions

Be specific and technical. Format with clear headings."""

        return self._call([{"role": "user", "content": prompt}])

    def generate_report_narrative(self) -> str:
        """
        Generate a professional executive summary narrative
        from the full session data.
        """
        if not self.session_data:
            return "No session data loaded."

        results  = self.session_data.get("results", {})
        hostname = self.session_data.get("hostname", "target")
        user     = self.session_data.get("user", "unknown")

        # Build a concise summary of what was found
        summary_parts = []
        for module, data in results.items():
            if not data:
                continue
            count = _count_items(data)
            if count:
                summary_parts.append(f"{module}: {count} findings")

        summary = "\n".join(summary_parts) or "No significant findings."

        prompt = f"""Write a professional penetration test executive summary for:

Host: {hostname}
Compromised user context: {user}
Scan results summary:
{summary}

Write:
1. Executive Summary (3-4 sentences, non-technical)
2. Key Risk Areas (bullet list)
3. Immediate Actions Required (numbered, prioritised)
4. Overall Risk Rating (Critical/High/Medium/Low) with justification

Use professional security report language suitable for a client briefing."""

        return self._call(
            [{"role": "user", "content": prompt}],
            max_tokens=2000
        )

    def explain_finding(self, finding_key: str, finding_value) -> str:
        """
        Explain a specific finding in plain English with context.
        """
        mitre = MITRE_MAP.get(finding_key.split(".")[-1], ("", ""))
        mitre_str = f"\nMITRE ATT&CK: {mitre[0]} — {mitre[1]}" if mitre[0] else ""

        prompt = f"""Explain this security finding from a penetration test:

Finding: {finding_key}
Value: {str(finding_value)[:500]}
{mitre_str}

Explain:
1. What this finding means technically
2. How an attacker would exploit it (step by step, no actual exploit code)
3. The real-world impact if exploited
4. Specific remediation command or configuration change

Be concise (max 300 words) but technically precise."""

        return self._call([{"role": "user", "content": prompt}])

    def suggest_attack_chain(self) -> str:
        """
        Analyse all findings and suggest the most likely
        attack chain an adversary would follow.
        """
        if not self.session_data:
            return "No session data. Run a scan first."

        results = self.session_data.get("results", {})
        flat    = _flatten_results(results)

        # Build a findings inventory
        inventory = []
        for key, val in flat.items():
            if val and not isinstance(val, (int, float, bool)):
                count = len(val) if isinstance(val, list) else 1
                if count:
                    mitre = MITRE_MAP.get(key.split(".")[-1], ("",""))
                    inventory.append(
                        f"- {key}: {count} item(s)"
                        + (f" [{mitre[0]}]" if mitre[0] else "")
                    )

        if not inventory:
            return "No findings to analyse for attack chains."

        prompt = f"""Given these findings from a security assessment, 
describe the most realistic attack chain an adversary would follow:

{chr(10).join(inventory[:20])}

Structure your response as:
1. Initial Access vector
2. Privilege Escalation path
3. Lateral Movement opportunities  
4. Persistence mechanisms available
5. Data exfiltration targets
6. Detection opportunities (for the blue team)

Map each step to the relevant MITRE ATT&CK technique.
Do not provide actual exploit code — describe the technique conceptually."""

        return self._call(
            [{"role": "user", "content": prompt}],
            max_tokens=2000
        )

    def mitre_mapping(self, findings: list) -> list:
        """
        Return MITRE ATT&CK mappings for the given findings.
        """
        mapped = []
        seen   = set()
        for f in findings:
            key   = f.get("key", "").split(".")[-1]
            mitre = MITRE_MAP.get(key)
            if mitre and mitre[0] not in seen:
                seen.add(mitre[0])
                mapped.append({
                    "finding":    f.get("key"),
                    "severity":   f.get("severity"),
                    "technique":  mitre[0],
                    "name":       mitre[1],
                })
        return mapped

    def chat(self, user_message: str) -> str:
        """
        Multi-turn chat about the scan results.
        Maintains conversation history.
        """
        # Inject session context on first message
        if not self.conversation and self.session_data:
            results  = self.session_data.get("results", {})
            hostname = self.session_data.get("hostname", "unknown")
            ctx = f"""[Session context: scanning host '{hostname}'. 
Modules run: {', '.join(results.keys())}.
Brief findings summary: {_brief_summary(results)}]

User question: {user_message}"""
            self.conversation.append({"role": "user", "content": ctx})
        else:
            self.conversation.append({"role": "user", "content": user_message})

        response = self._call(
            self.conversation[-10:],  # last 10 turns for context window
            max_tokens=1000
        )
        self.conversation.append({"role": "assistant", "content": response})
        return response

    def reset_chat(self):
        """Clear conversation history."""
        self.conversation = []

    def generate_remediation_plan(self, findings: list) -> str:
        """
        Generate a structured, prioritised remediation plan.
        """
        if not findings:
            return "No findings to remediate."

        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]

        prompt = f"""Create a prioritised remediation plan for these security findings:

CRITICAL ({len(critical)} findings):
{chr(10).join(f"- {f['key']}: {f.get('remediation','')}" for f in critical[:5])}

HIGH ({len(high)} findings):
{chr(10).join(f"- {f['key']}: {f.get('remediation','')}" for f in high[:5])}

Format as:
## Immediate Actions (24-48 hours)
## Short-term Actions (1-2 weeks)  
## Long-term Hardening (1-3 months)

For each action include:
- Specific command or configuration change
- Verification step to confirm fix
- Estimated effort (Low/Medium/High)"""

        return self._call(
            [{"role": "user", "content": prompt}],
            max_tokens=2000
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_items(data) -> int:
    if isinstance(data, list): return len(data)
    if isinstance(data, dict):
        return sum(_count_items(v) for v in data.values())
    return 1 if data else 0


def _flatten_results(results: dict, prefix="") -> dict:
    out = {}
    for k, v in results.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_results(v, full))
        else:
            out[full] = v
    return out


def _brief_summary(results: dict) -> str:
    parts = []
    for mod, data in results.items():
        n = _count_items(data)
        if n:
            parts.append(f"{mod}:{n}")
    return ", ".join(parts[:8]) or "none"
