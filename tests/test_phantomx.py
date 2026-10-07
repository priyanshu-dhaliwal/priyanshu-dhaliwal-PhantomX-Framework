"""
tests/test_phantomx.py — PhantomX Comprehensive Test Suite

Tests:
  - Core engine: plugin loading, session management, result counting
  - Shell utils: command execution, file permission checks, helpers
  - Report generator: JSON, HTML, TXT output validation
  - Risk scoring: rule matching, overall score calculation
  - Plugin smoke tests: each plugin's run() function returns a dict
  - CLI argument parsing: all subcommands and flags
  - Integration: full pipeline end-to-end with mock data
"""

import ast
import json
import os
import sys
import pathlib
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ══════════════════════════════════════════════════════════════════════════════
# 1. SYNTAX VALIDATION — ALL PYTHON FILES
# ══════════════════════════════════════════════════════════════════════════════

class TestSyntax(unittest.TestCase):
    """Verify every .py file in the project is syntactically valid."""

    def test_all_python_files_parse(self):
        py_files = list(ROOT.rglob("*.py"))
        self.assertGreater(len(py_files), 10,
                           "Expected at least 10 Python files in project")
        errors = []
        for f in py_files:
            try:
                ast.parse(f.read_text(encoding="utf-8"))
            except SyntaxError as e:
                errors.append(f"{f.relative_to(ROOT)}: line {e.lineno}: {e.msg}")
        self.assertEqual(errors, [], f"Syntax errors:\n" + "\n".join(errors))

    def test_plugin_count(self):
        plugins = list((ROOT / "plugins").glob("*.py"))
        plugin_names = [p.stem for p in plugins if p.stem != "__init__"]
        self.assertGreaterEqual(len(plugin_names), 15,
                                f"Expected ≥15 plugins, found {len(plugin_names)}")

    def test_core_files_exist(self):
        required = [
            "main.py", "tui.py", "autorun.sh",
            "core/engine.py", "core/banner.py", "core/scoring.py",
            "utils/shell.py", "utils/report.py",
        ]
        for rel in required:
            self.assertTrue((ROOT / rel).exists(), f"Missing: {rel}")

    def test_plugin_files_exist(self):
        required_plugins = [
            "enumeration", "privesc", "persistence", "loot", "lateral",
            "network", "audit", "container", "webapp", "vulnscan",
            "fuzzer", "cvecheck", "recon", "services", "activedir",
            "evasion", "postexploit", "apitesting", "passattack",
            "wireless", "dnsrecon", "traffic",
        ]
        for name in required_plugins:
            p = ROOT / "plugins" / f"{name}.py"
            self.assertTrue(p.exists(), f"Missing plugin: plugins/{name}.py")


# ══════════════════════════════════════════════════════════════════════════════
# 2. SHELL UTILS
# ══════════════════════════════════════════════════════════════════════════════

class TestShellUtils(unittest.TestCase):

    def setUp(self):
        from utils.shell import run_cmd, cmd_exists, read_file, is_writable, get_uid
        self.run_cmd   = run_cmd
        self.cmd_exists= cmd_exists
        self.read_file = read_file
        self.is_writable=is_writable
        self.get_uid   = get_uid

    def test_run_cmd_success(self):
        rc, out = self.run_cmd("echo hello_phantomx")
        self.assertEqual(rc, 0)
        self.assertIn("hello_phantomx", out)

    def test_run_cmd_failure(self):
        rc, out = self.run_cmd("false")
        self.assertNotEqual(rc, 0)

    def test_run_cmd_timeout(self):
        rc, out = self.run_cmd("sleep 10", timeout=1)
        self.assertEqual(rc, -1)

    def test_run_cmd_nonexistent(self):
        rc, out = self.run_cmd("__nonexistent_cmd_phantomx__")
        # Shell returns 127 for "command not found"; run_cmd may return -1
        # on FileNotFoundError depending on shell availability. Either way
        # the return code must be non-zero.
        self.assertNotEqual(rc, 0)

    def test_cmd_exists_python(self):
        self.assertTrue(self.cmd_exists("python3"))

    def test_cmd_exists_false(self):
        self.assertFalse(self.cmd_exists("__no_such_binary_phantomx__"))

    def test_read_file_existing(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("phantomx_test_content")
            fname = f.name
        try:
            content = self.read_file(fname)
            self.assertEqual(content, "phantomx_test_content")
        finally:
            os.unlink(fname)

    def test_read_file_missing(self):
        result = self.read_file("/tmp/__phantomx_no_such_file__.txt")
        self.assertIsNone(result)

    def test_get_uid_returns_int(self):
        uid = self.get_uid()
        self.assertIsInstance(uid, int)
        self.assertGreaterEqual(uid, 0)

    def test_is_writable_tmp(self):
        self.assertTrue(self.is_writable("/tmp"))

    def test_is_writable_etc(self):
        # /etc should not be writable for non-root
        if os.getuid() != 0:
            self.assertFalse(self.is_writable("/etc/shadow"))


# ══════════════════════════════════════════════════════════════════════════════
# 3. CORE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class TestPluginEngine(unittest.TestCase):

    def setUp(self):
        from core.engine import PluginEngine
        self.PluginEngine = PluginEngine

    def test_engine_instantiation(self):
        engine = self.PluginEngine(verbose=False)
        self.assertIsNotNone(engine)
        self.assertIsInstance(engine.session, dict)

    def test_engine_session_fields(self):
        engine = self.PluginEngine(verbose=False)
        self.assertIn("start_time", engine.session)
        self.assertIn("hostname", engine.session)
        self.assertIn("user", engine.session)
        self.assertIn("results", engine.session)

    def test_count_findings_list(self):
        engine = self.PluginEngine()
        n = engine._count_findings({"findings": [1, 2, 3], "other": []})
        self.assertEqual(n, 3)

    def test_count_findings_nested(self):
        engine = self.PluginEngine()
        n = engine._count_findings({"a": {"b": [1, 2]}, "c": [3]})
        self.assertEqual(n, 3)

    def test_count_findings_empty(self):
        engine = self.PluginEngine()
        self.assertEqual(engine._count_findings({}), 0)

    def test_module_map_complete(self):
        from core.engine import MODULE_MAP
        required = ["enum", "privesc", "persist", "loot", "lateral",
                    "network", "audit", "container", "webapp",
                    "vulnscan", "fuzzer", "cvecheck"]
        for mod in required:
            self.assertIn(mod, MODULE_MAP, f"'{mod}' missing from MODULE_MAP")

    def test_load_plugin_enumeration(self):
        engine = self.PluginEngine()
        plugin = engine._load_plugin("enumeration")
        self.assertTrue(hasattr(plugin, "run"), "Plugin missing run() function")

    def test_load_plugin_privesc(self):
        engine = self.PluginEngine()
        plugin = engine._load_plugin("privesc")
        self.assertTrue(hasattr(plugin, "run"))

    def test_load_plugin_nonexistent_raises(self):
        engine = self.PluginEngine()
        with self.assertRaises(ImportError):
            engine._load_plugin("__nonexistent_plugin__")

    def test_session_saved_after_run(self):
        engine = self.PluginEngine()
        with patch.object(engine, "_load_plugin") as mock_load:
            mock_plugin = MagicMock()
            mock_plugin.run = MagicMock(return_value={"test": ["a", "b"]})
            mock_load.return_value = mock_plugin
            args = MagicMock()
            args.verbose = False
            engine.run("enum", args)
            self.assertIn("enum", engine.session["results"])


# ══════════════════════════════════════════════════════════════════════════════
# 4. RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskScorer(unittest.TestCase):

    def setUp(self):
        from core.scoring import RiskScorer
        self.RiskScorer = RiskScorer

    def _make_session(self, results):
        return {
            "start_time": "2024-01-01T00:00:00",
            "hostname":   "test-host",
            "user":       "root",
            "results":    results
        }

    def test_scorer_loads_session(self):
        scorer = self.RiskScorer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._make_session({}), f)
            fname = f.name
        try:
            scorer.session_file = fname
            self.assertTrue(scorer.load())
        finally:
            os.unlink(fname)

    def test_score_with_critical_findings(self):
        scorer = self.RiskScorer()
        scorer.session = self._make_session({
            "privesc": {
                "sudo_findings": [["NOPASSWD ALL", "critical", "Full sudo"]],
                "suid_interesting": ["/usr/bin/python3"],
            }
        })
        scorer.score()
        self.assertGreater(len(scorer.scored_findings), 0)
        severities = [f["severity"] for f in scorer.scored_findings]
        self.assertIn("critical", severities)

    def test_overall_risk_high_for_critical(self):
        scorer = self.RiskScorer()
        scorer.session = self._make_session({
            "loot": {"shadow": {"readable": True, "hash_count": 3}},
        })
        scorer.score()
        overall = scorer.get_overall_risk()
        self.assertGreater(overall, 0)
        self.assertLessEqual(overall, 10)

    def test_overall_risk_zero_empty(self):
        scorer = self.RiskScorer()
        scorer.session = self._make_session({})
        scorer.score()
        self.assertEqual(scorer.get_overall_risk(), 0.0)

    def test_export_json(self):
        scorer = self.RiskScorer()
        scorer.session = self._make_session({
            "privesc": {"sudo_findings": [["NOPASSWD", "high", "sudo"]]}
        })
        scorer.score()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        try:
            scorer.export_json(fname)
            with open(fname) as f:
                data = json.load(f)
            self.assertIn("overall_risk", data)
            self.assertIn("findings", data)
            self.assertIn("finding_counts", data)
        finally:
            os.unlink(fname)

    def test_score_contains_required_fields(self):
        scorer = self.RiskScorer()
        scorer.session = self._make_session({
            "network": {"open_ports": [[445, "SMB", "EternalBlue"]]}
        })
        scorer.score()
        for finding in scorer.scored_findings:
            self.assertIn("score",       finding)
            self.assertIn("severity",    finding)
            self.assertIn("remediation", finding)
            self.assertIn("module",      finding)


# ══════════════════════════════════════════════════════════════════════════════
# 5. REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        from utils.report import ReportGenerator
        self.ReportGenerator = ReportGenerator
        self.sample_results = {
            "privesc": {
                "suid_interesting": ["/usr/bin/python3"],
                "kernel_version":   "5.15.0",
            },
            "loot": {
                "shadow": {"readable": False},
                "ssh_keys": [],
            }
        }

    def test_json_report_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = self.ReportGenerator(results=self.sample_results)
            gen.session["results"] = self.sample_results
            with patch("utils.report.REPORT_DIR", pathlib.Path(tmpdir)):
                out = gen._write_json("20240101_120000")
            with open(out) as f:
                data = json.load(f)
            self.assertIn("results", data)

    def test_txt_report_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = self.ReportGenerator(results=self.sample_results)
            with patch("utils.report.REPORT_DIR", pathlib.Path(tmpdir)):
                out = gen._write_txt("20240101_120000")
            content = pathlib.Path(out).read_text()
            self.assertIn("PhantomX", content)

    def test_html_report_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = self.ReportGenerator(results=self.sample_results)
            with patch("utils.report.REPORT_DIR", pathlib.Path(tmpdir)):
                out = gen._write_html("20240101_120000")
            content = pathlib.Path(out).read_text()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("PhantomX", content)

    def test_flatten_findings_list(self):
        gen = self.ReportGenerator()
        flat = gen._flatten_findings({"items": ["a", "b", "c"]})
        self.assertEqual(len(flat), 3)

    def test_flatten_findings_nested(self):
        gen = self.ReportGenerator()
        flat = gen._flatten_findings({"outer": {"inner": ["x", "y"]}})
        self.assertGreater(len(flat), 0)


# ══════════════════════════════════════════════════════════════════════════════
# 6. CLI ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIParsing(unittest.TestCase):

    def setUp(self):
        # Import builder without running main
        import importlib.util
        spec = importlib.util.spec_from_file_location("main", ROOT / "main.py")
        self.main_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.main_mod)

    def test_parser_builds(self):
        parser = self.main_mod.build_parser()
        self.assertIsNotNone(parser)

    def test_all_module_subparsers(self):
        parser = self.main_mod.build_parser()
        modules = ["enum", "privesc", "persist", "loot", "lateral",
                   "network", "audit", "container", "webapp",
                   "vulnscan", "fuzzer", "cvecheck", "recon",
                   "services", "activedir", "evasion", "postexploit",
                   "apitesting", "passattack", "wireless", "dnsrecon",
                   "traffic", "score", "report", "tui", "all"]
        for mod in modules:
            args = parser.parse_args([mod])
            self.assertEqual(args.module, mod, f"Subparser '{mod}' not registered")

    def test_verbose_flag(self):
        parser = self.main_mod.build_parser()
        # --verbose is a global flag declared before subcommands,
        # so it must come BEFORE the subcommand name in argv.
        args = parser.parse_args(["--verbose", "enum"])
        self.assertTrue(args.verbose)

    def test_output_flag(self):
        parser = self.main_mod.build_parser()
        # --output is a global flag, so it must come BEFORE the subcommand name.
        for fmt in ["json", "html", "txt"]:
            args = parser.parse_args(["--output", fmt, "privesc"])
            self.assertEqual(args.output, fmt)

    def test_network_target_flag(self):
        parser = self.main_mod.build_parser()
        args = parser.parse_args(["network", "--target", "10.10.10.5"])
        self.assertEqual(args.target, "10.10.10.5")

    def test_all_skip_flag(self):
        parser = self.main_mod.build_parser()
        args = parser.parse_args(["all", "--skip", "lateral", "network"])
        self.assertIn("lateral", args.skip)

    def test_score_export_flag(self):
        parser = self.main_mod.build_parser()
        args = parser.parse_args(["score", "--export", "/tmp/out.json"])
        self.assertEqual(args.export, "/tmp/out.json")


# ══════════════════════════════════════════════════════════════════════════════
# 7. PLUGIN SMOKE TESTS — run() returns dict
# ══════════════════════════════════════════════════════════════════════════════

class TestPluginSmoke(unittest.TestCase):
    """
    For each plugin, verify run() can be called with mocked system calls
    and returns a dict without crashing.
    """

    def _make_args(self, **kwargs):
        args = MagicMock()
        args.target   = "127.0.0.1"
        args.domain   = ""
        args.port     = 80
        args.verbose  = False
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def _run_plugin(self, plugin_name, args=None):
        from core.engine import PluginEngine
        engine = PluginEngine()
        plugin = engine._load_plugin(plugin_name)
        if args is None:
            args = self._make_args()
        # Run with all external calls mocked
        with patch("utils.shell.run_cmd", return_value=(0, "")), \
             patch("utils.shell.cmd_exists", return_value=False), \
             patch("utils.shell.read_file",  return_value=None), \
             patch("utils.shell.is_readable", return_value=False), \
             patch("utils.shell.is_writable", return_value=False), \
             patch("socket.socket"), \
             patch("socket.gethostbyname", side_effect=Exception("mocked")), \
             patch("socket.gethostbyaddr", side_effect=Exception("mocked")):
            result = plugin.run(args, verbose=False)
        return result

    def test_enumeration_returns_dict(self):
        r = self._run_plugin("enumeration")
        self.assertIsInstance(r, dict)

    def test_privesc_returns_dict(self):
        r = self._run_plugin("privesc")
        self.assertIsInstance(r, dict)

    def test_persistence_returns_dict(self):
        r = self._run_plugin("persistence")
        self.assertIsInstance(r, dict)

    def test_loot_returns_dict(self):
        r = self._run_plugin("loot")
        self.assertIsInstance(r, dict)

    def test_lateral_returns_dict(self):
        r = self._run_plugin("lateral")
        self.assertIsInstance(r, dict)

    def test_audit_returns_dict(self):
        r = self._run_plugin("audit")
        self.assertIsInstance(r, dict)

    def test_container_returns_dict(self):
        r = self._run_plugin("container")
        self.assertIsInstance(r, dict)

    def test_network_returns_dict(self):
        r = self._run_plugin("network")
        self.assertIsInstance(r, dict)

    def test_webapp_returns_dict(self):
        r = self._run_plugin("webapp")
        self.assertIsInstance(r, dict)

    def test_passattack_returns_dict(self):
        r = self._run_plugin("passattack")
        self.assertIsInstance(r, dict)

    def test_evasion_returns_dict(self):
        r = self._run_plugin("evasion")
        self.assertIsInstance(r, dict)

    def test_postexploit_returns_dict(self):
        r = self._run_plugin("postexploit")
        self.assertIsInstance(r, dict)

    def test_plugin_result_is_serialisable(self):
        """All plugin results must be JSON-serialisable for reporting."""
        r = self._run_plugin("enumeration")
        try:
            json.dumps(r, default=str)
        except (TypeError, ValueError) as e:
            self.fail(f"Plugin result not JSON-serialisable: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 8. BANNER / OUTPUT UTILS
# ══════════════════════════════════════════════════════════════════════════════

class TestBanner(unittest.TestCase):

    def test_print_status_does_not_raise(self):
        from core.banner import print_status
        try:
            print_status("test message", "info")
            print_status("test warn",    "warn")
            print_status("test error",   "error")
            print_status("test success", "success")
        except Exception as e:
            self.fail(f"print_status raised: {e}")

    def test_print_finding_does_not_raise(self):
        from core.banner import print_finding
        try:
            print_finding("Test Finding", "detail here", "high")
            print_finding("Critical",     "bad thing",   "critical")
        except Exception as e:
            self.fail(f"print_finding raised: {e}")

    def test_print_table_does_not_raise(self):
        from core.banner import print_table
        try:
            print_table(["Col A", "Col B"], [("val1", "val2"), ("val3", "val4")])
        except Exception as e:
            self.fail(f"print_table raised: {e}")

    def test_print_table_empty(self):
        from core.banner import print_table
        try:
            print_table(["Col A", "Col B"], [])
        except Exception as e:
            self.fail(f"print_table with empty rows raised: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 9. INTEGRATION — FULL PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):

    def test_full_session_roundtrip(self):
        """Engine runs plugin → saves session → report generator loads → HTML produced."""
        from core.engine import PluginEngine
        from utils.report import ReportGenerator

        engine = PluginEngine()

        with patch("utils.shell.run_cmd",    return_value=(0, "")), \
             patch("utils.shell.cmd_exists", return_value=False), \
             patch("utils.shell.read_file",  return_value=None), \
             patch("utils.shell.is_readable",return_value=False), \
             patch("utils.shell.is_writable",return_value=False), \
             patch("socket.socket"), \
             patch("socket.gethostbyname", side_effect=Exception), \
             patch("socket.gethostbyaddr", side_effect=Exception):

            args = MagicMock()
            args.target = "127.0.0.1"; args.domain = ""; args.port = 80
            result = engine.run("enum", args)

        self.assertIsInstance(result, dict)
        self.assertIn("enum", engine.session["results"])

        # Generate report
        gen = ReportGenerator(results=engine.session["results"])
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("utils.report.REPORT_DIR", pathlib.Path(tmpdir)):
                html_path = gen._write_html("test_ts")
            html = pathlib.Path(html_path).read_text()
        self.assertIn("PhantomX", html)

    def test_scoring_pipeline_no_crash(self):
        """Score a realistic session without crashing."""
        from core.scoring import RiskScorer
        scorer = RiskScorer()
        scorer.session = {
            "start_time": "2024-01-01T00:00:00",
            "hostname": "test", "user": "test",
            "results": {
                "privesc": {
                    "suid_interesting": ["/usr/bin/python3", "/usr/bin/vim"],
                    "sudo_findings": [["NOPASSWD ALL", "critical", ""]],
                    "dangerous_groups": ["docker"],
                    "kernel_version": "5.15.0",
                    "kernel_cves": ["CVE-2022-0847 (DirtyPipe)"],
                },
                "loot": {
                    "shadow": {"readable": True, "hash_count": 2},
                    "ssh_keys": [["~/.ssh/id_rsa", "PRIVATE", "✓ readable"]],
                },
                "audit": {
                    "ssh_hardening": [["PermitRootLogin", "yes", "critical", "note"]],
                    "world_writable": ["/usr/local/bin/script.sh"],
                }
            }
        }
        findings = scorer.score()
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

        overall = scorer.get_overall_risk()
        self.assertGreater(overall, 0)
        self.assertLessEqual(overall, 10)

        # Export JSON — must not raise
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        try:
            scorer.export_json(fname)
            with open(fname) as f:
                exported = json.load(f)
            self.assertIn("findings", exported)
            self.assertIn("overall_risk", exported)
        finally:
            os.unlink(fname)


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
