"""
utils/report.py — Report Generator (HTML, JSON, TXT)
"""

import json
import os
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path(__file__).parent.parent / "reports"
SESSION_FILE = REPORT_DIR / ".last_session.json"


class ReportGenerator:
    def __init__(self, results: dict = None):
        self.session = {
            "start_time": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "user": os.getenv("USER", "unknown"),
            "results": results or {}
        }
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def load_last_run(self):
        if SESSION_FILE.exists():
            with open(SESSION_FILE) as f:
                self.session = json.load(f)

    def generate(self, fmt: str = "html") -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            return self._write_json(ts)
        elif fmt == "html":
            return self._write_html(ts)
        else:
            return self._write_txt(ts)

    # ── JSON ─────────────────────────────────────────────────────────────────

    def _write_json(self, ts: str) -> str:
        path = REPORT_DIR / f"phantomx_report_{ts}.json"
        with open(path, "w") as f:
            json.dump(self.session, f, indent=2, default=str)
        return str(path)

    # ── TXT ──────────────────────────────────────────────────────────────────

    def _write_txt(self, ts: str) -> str:
        path = REPORT_DIR / f"phantomx_report_{ts}.txt"
        lines = [
            "=" * 70,
            "  PhantomX Post-Exploitation Report",
            "=" * 70,
            f"  Host     : {self.session.get('hostname','?')}",
            f"  User     : {self.session.get('user','?')}",
            f"  Time     : {self.session.get('start_time','?')}",
            "=" * 70, ""
        ]
        for module, data in self.session.get("results", {}).items():
            lines.append(f"\n[MODULE: {module.upper()}]")
            lines.append(json.dumps(data, indent=2, default=str))
        content = "\n".join(lines)
        path.write_text(content)
        return str(path)

    # ── HTML ─────────────────────────────────────────────────────────────────

    def _write_html(self, ts: str) -> str:
        path = REPORT_DIR / f"phantomx_report_{ts}.html"

        modules_html = ""
        for module, data in self.session.get("results", {}).items():
            findings = self._flatten_findings(data)
            rows = "".join(
                f"<tr><td>{f['key']}</td><td class='val'>{f['val']}</td></tr>"
                for f in findings
            )
            modules_html += f"""
            <div class="module">
              <h2>&#9656; {module.upper()}</h2>
              <table><thead><tr><th>Check</th><th>Value</th></tr></thead>
              <tbody>{rows}</tbody></table>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhantomX Report — {self.session.get('hostname','?')}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #e63946; --green: #3fb950; --yellow: #d29922;
    --text: #c9d1d9; --dim: #8b949e; --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font);
          font-size: 13px; padding: 24px; }}
  header {{ border-bottom: 2px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px; }}
  header h1 {{ color: var(--accent); font-size: 22px; letter-spacing: 2px; }}
  header p  {{ color: var(--dim); margin-top: 6px; }}
  .meta {{ display: flex; gap: 32px; margin-bottom: 24px; }}
  .meta-item span {{ color: var(--dim); font-size: 11px; text-transform: uppercase; }}
  .meta-item p {{ color: var(--text); font-size: 13px; margin-top: 2px; }}
  .module {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 6px; padding: 16px; margin-bottom: 20px; }}
  .module h2 {{ color: var(--accent); font-size: 14px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; color: var(--dim); text-align: left; padding: 8px 12px;
        font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  td.val {{ color: var(--green); word-break: break-all; }}
  tr:hover td {{ background: #1c2128; }}
  footer {{ color: var(--dim); font-size: 11px; margin-top: 32px; text-align: center; }}
</style>
</head>
<body>
<header>
  <h1>&#128296; PhantomX — Post-Exploitation Report</h1>
  <p>Advanced Red Team Toolkit | For Authorized Testing Only</p>
</header>
<div class="meta">
  <div class="meta-item"><span>Hostname</span><p>{self.session.get('hostname','?')}</p></div>
  <div class="meta-item"><span>User</span><p>{self.session.get('user','?')}</p></div>
  <div class="meta-item"><span>Session Start</span><p>{self.session.get('start_time','?')}</p></div>
  <div class="meta-item"><span>Modules Run</span>
    <p>{len(self.session.get('results', {}))}</p></div>
</div>
{modules_html}
<footer>Generated by PhantomX &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &mdash;
Unauthorized use is illegal.</footer>
</body></html>"""

        path.write_text(html)
        return str(path)

    def _flatten_findings(self, data, prefix="") -> list:
        out = []
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    out.extend(self._flatten_findings(v, key))
                else:
                    out.append({"key": key, "val": str(v)[:200]})
        elif isinstance(data, list):
            for i, item in enumerate(data[:50]):
                key = f"{prefix}[{i}]"
                if isinstance(item, (list, tuple)):
                    out.append({"key": key, "val": str(item)[:200]})
                elif isinstance(item, dict):
                    out.extend(self._flatten_findings(item, key))
                else:
                    out.append({"key": key, "val": str(item)[:200]})
        return out


# ── __init__ stubs ────────────────────────────────────────────────────────────
(Path(__file__).parent / "__init__.py").touch()
