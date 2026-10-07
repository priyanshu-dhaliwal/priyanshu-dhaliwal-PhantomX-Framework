"""
core/engine.py — Plugin engine, dynamic loader, session manager
"""

import importlib
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

from core.banner import print_status, print_section, C

PLUGIN_DIR = Path(__file__).parent.parent / "plugins"
SESSION_FILE = Path(__file__).parent.parent / "reports" / ".last_session.json"

# Map CLI module names → plugin filenames
MODULE_MAP = {
    "enum":    "enumeration",
    "privesc": "privesc",
    "persist": "persistence",
    "loot":    "loot",
    "lateral": "lateral",
    "network":  "network",
    "audit":    "audit",
    "container":"container",
    "webapp":    "webapp",
    "recon":     "recon",
    "services":  "services",
    "activedir": "activedir",
    "evasion":   "evasion",
    "postexploit":"postexploit",
    "apitesting":"apitesting",
    "passattack": "passattack",
    "wireless":   "wireless",
    "dnsrecon":  "dnsrecon",
    "traffic":   "traffic",
    "ai":        "ai_analyst",
    "vulnscan":  "vulnscan",
    "fuzzer":    "fuzzer",
    "cvecheck":  "cvecheck",
}


class PluginEngine:
    """Loads and executes post-exploitation plugin modules."""

    def __init__(self, verbose: bool = False):
        self.verbose  = verbose
        self.session  = {
            "start_time": datetime.now().isoformat(),
            "hostname":   os.uname().nodename,
            "user":       os.getenv("USER", "unknown"),
            "results":    {}
        }
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, module_name: str, args) -> dict:
        """Load and execute a plugin, return its results dict."""
        plugin_key = MODULE_MAP.get(module_name, module_name)
        print_section(f" Module: {module_name.upper()} ")

        try:
            plugin_mod = self._load_plugin(plugin_key)
        except ImportError as exc:
            print_status(f"Failed to load plugin '{plugin_key}': {exc}", "error")
            return {}

        if not hasattr(plugin_mod, "run"):
            print_status(f"Plugin '{plugin_key}' has no run() function.", "error")
            return {}

        start = time.time()
        print_status(f"Starting {module_name} checks…", "info")

        try:
            results = plugin_mod.run(args, verbose=self.verbose)
        except Exception as exc:
            print_status(f"Plugin error: {exc}", "error")
            if self.verbose:
                import traceback; traceback.print_exc()
            results = {"error": str(exc)}

        elapsed = time.time() - start
        count   = self._count_findings(results)
        print_status(
            f"Module {module_name.upper()} completed in {elapsed:.2f}s  "
            f"({count} finding(s))",
            "success" if count else "info"
        )

        self.session["results"][module_name] = results
        self._save_session()
        return results

    # ── Internals ─────────────────────────────────────────────────────────────

    def _load_plugin(self, plugin_key: str):
        """Dynamically import plugins/<plugin_key>.py"""
        plugin_path = PLUGIN_DIR / f"{plugin_key}.py"
        if not plugin_path.exists():
            raise ImportError(f"Plugin file not found: {plugin_path}")

        spec   = importlib.util.spec_from_file_location(plugin_key, plugin_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[plugin_key] = module
        spec.loader.exec_module(module)
        return module

    def _count_findings(self, results: dict) -> int:
        """Count non-empty findings in a results dict."""
        count = 0
        for v in results.values():
            if isinstance(v, list):
                count += len(v)
            elif isinstance(v, dict):
                count += self._count_findings(v)
            elif v:
                count += 1
        return count

    def _save_session(self):
        """Persist session to disk for later report generation."""
        try:
            with open(SESSION_FILE, "w") as f:
                json.dump(self.session, f, indent=2, default=str)
        except Exception:
            pass  # Non-fatal


# ── __init__ stubs ────────────────────────────────────────────────────────────
(PLUGIN_DIR / "__init__.py").touch()
(Path(__file__).parent / "__init__.py").touch()
