#!/usr/bin/env python3
"""
gui.py — PhantomX Unified AI Web GUI  v6.0
Startup dialog asks for target before any scan can run.
  python3 gui.py            →  http://127.0.0.1:7331
  python3 gui.py --port 8080
"""
import argparse, json, os, re, subprocess, sys, threading, webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).parent
PX   = [sys.executable, str(ROOT / "main.py")]

# ── State ─────────────────────────────────────────────────────────────────────
state = {
    "target":  "",
    "domain":  "",
    "running": False,
    "current": "",
    "log":     [],
    "counts":  {"critical":0,"high":0,"medium":0,"low":0,"total":0},
    "history": [],
    "mstates": {},
}

NEEDS_TARGET = {
    "network","webapp","vulnscan","fuzzer","cvecheck","apitesting",
    "passattack","services","activedir","evasion","postexploit",
    "recon","dnsrecon","traffic",
}


def _log(line):
    state["log"].append(line)
    if len(state["log"]) > 1200:
        state["log"] = state["log"][-900:]


def run_module(*argv):
    if state["running"]:
        return {"error": "A module is already running. Please wait."}
    state["running"] = True
    cmd = argv[0]
    state["current"] = cmd
    state["mstates"][cmd] = "run"
    ts = datetime.now().strftime("%H:%M:%S")
    _log(f"[{ts}] ── Starting: {' '.join(argv)} ──")

    def worker():
        try:
            proc = subprocess.Popen(
                PX + list(argv),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
            for line in proc.stdout:
                clean = re.sub(r"\033\[[0-9;]*[mK]", "", line.rstrip())
                _log(clean)
                ll = clean.lower()
                for sev in ("critical","high","medium","low"):
                    if sev in ll:
                        state["counts"][sev] = state["counts"].get(sev,0)+1
                        state["counts"]["total"] = state["counts"].get("total",0)+1
                        break
            proc.wait()
            ok  = proc.returncode == 0
            ts2 = datetime.now().strftime("%H:%M:%S")
            state["mstates"][cmd] = "ok" if ok else "err"
            _log(f"[{ts2}] ── Done: {cmd} (rc={proc.returncode}) ──")
            state["history"].insert(0, {"time":ts2,"module":cmd,
                                        "status":"ok" if ok else "err"})
            state["history"] = state["history"][:25]
        except Exception as e:
            _log(f"ERROR: {e}")
            state["mstates"][cmd] = "err"
        finally:
            state["running"] = False
            state["current"] = ""

    threading.Thread(target=worker, daemon=True).start()
    return {"started": cmd}


def ai_call(endpoint, payload):
    try:
        sys.path.insert(0, str(ROOT))
        from core.ai_engine import AIEngine
        from core.scoring   import RiskScorer
        engine = AIEngine(); engine.load_session()
        scorer = RiskScorer(); findings = []
        if scorer.load(): scorer.score(); findings = scorer.scored_findings
        if endpoint == "analyse":
            return {"result": engine.analyse_findings(findings)}
        elif endpoint == "chat":
            if payload.get("history"): engine.conversation = payload["history"]
            r = engine.chat(payload.get("message",""))
            return {"result": r, "history": engine.conversation}
        elif endpoint == "report":
            return {"result": engine.generate_report_narrative()}
        elif endpoint == "mitre":
            mapped  = engine.mitre_mapping(findings)
            summary = ""
            if mapped:
                tl = "\n".join(f"- {m['technique']}: {m['name']}" for m in mapped[:8])
                summary = engine._call([{"role":"user","content":f"Summarise in 2 sentences:\n{tl}"}],max_tokens=200)
            return {"mapped": mapped, "summary": summary}
        elif endpoint == "chain":
            return {"result": engine.suggest_attack_chain()}
        elif endpoint == "remediate":
            return {"result": engine.generate_remediation_plan(findings)}
        else:
            return {"error": f"Unknown endpoint: {endpoint}"}
    except RuntimeError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"AI error: {e}"}


# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)

        pages = {
            "/":            "index.html",
            "/index.html":  "index.html",
            "/comparison":  "comparison.html",
            "/architecture":"architecture.html",
            "/help":        "help.html",
        }
        if path in pages:
            p = ROOT / "dashboard" / pages[path]
            self._html(p.read_text() if p.exists() else "<h1>Page not found</h1>")

        elif path == "/api/state":
            self._json({**state, "log": []})

        elif path == "/api/log":
            offset = int(params.get("offset",["0"])[0])
            self._json({"lines": state["log"][offset:],
                        "total": len(state["log"])})

        elif path == "/api/run":
            mod   = params.get("module",[""])[0]
            extra = params.get("extra", [""])[0]
            if not mod:
                self._json({"error":"No module specified"},400); return
            # Block network modules if no target set
            if mod in NEEDS_TARGET and not state["target"]:
                self._json({
                    "error": (f"Module '{mod}' requires a target IP or hostname. "
                              f"Set it in the Target field and click Apply."),
                    "needs_target": True
                }, 400); return
            args = [mod]
            if extra: args += extra.split()
            if mod in NEEDS_TARGET and state["target"]:
                args += ["--target", state["target"]]
            if mod in ("activedir","recon","dnsrecon") and state["domain"]:
                args += ["--domain", state["domain"]]
            self._json(run_module(*args))

        elif path == "/api/set":
            k = params.get("key",  [""])[0]
            v = params.get("value",[""])[0]
            if k in ("target","domain"):
                state[k] = v
                self._json({"ok":True, k:v})
            else:
                self._json({"error":"Unknown key"},400)

        elif path == "/api/clear":
            state["log"]    = []
            state["counts"] = {"critical":0,"high":0,"medium":0,"low":0,"total":0}
            self._json({"ok":True})

        elif path == "/api/score":
            try:
                sys.path.insert(0, str(ROOT))
                from core.scoring import RiskScorer
                sc = RiskScorer()
                if sc.load():
                    sc.score()
                    self._json({
                        "overall":  sc.get_overall_risk(),
                        "findings": sc.scored_findings[:20],
                        "counts": {s: len([f for f in sc.scored_findings
                                           if f["severity"]==s])
                                   for s in ("critical","high","medium","low")}
                    })
                else:
                    self._json({"error":"No session data. Run modules first."})
            except Exception as e:
                self._json({"error":str(e)})

        elif path == "/api/report":
            fmt = params.get("format",["html"])[0]
            try:
                r = subprocess.run(PX+["report","--format",fmt],
                                   capture_output=True,text=True,timeout=30)
                m = re.search(r"→\s*(\S+)", r.stdout)
                self._json({"ok":True,"path":m.group(1) if m else "generated"})
            except Exception as e:
                self._json({"error":str(e)})

        else:
            self._send(404, b"Not found","text/plain")

    def do_POST(self):
        path   = urlparse(self.path).path
        length = int(self.headers.get("Content-Length",0))
        body   = json.loads(self.rfile.read(length) or b"{}") if length else {}
        if path.startswith("/api/ai/"):
            self._json(ai_call(path[8:], body))
        else:
            self._send(404,b"Not found","text/plain")

    def _json(self, data, status=200):
        b = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers(); self.wfile.write(b)

    def _html(self, content):
        b = content.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _send(self, status, body, ct):
        self.send_response(status)
        self.send_header("Content-Type",ct)
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)


GUI_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>PhantomX — AI Security Platform</title>\n<style>\n@import url(\'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@700;800&display=swap\');\n:root{\n  --bg0:#060810;--bg1:#0c0f1a;--bg2:#111420;--bg3:#181c2e;\n  --bdr:#1e2338;--acc:#e63946;--grn:#06d6a0;--yel:#ffd166;\n  --blu:#118ab2;--pur:#7b2fff;--org:#ff7f50;--ai:#a855f7;\n  --text:#cdd6f4;--dim:#6c7086;--mid:#a6adc8;\n  --mono:\'JetBrains Mono\',monospace;--sans:\'Syne\',sans-serif;\n}\n*{box-sizing:border-box;margin:0;padding:0;}\nhtml,body{height:100%;overflow:hidden;}\nbody{background:var(--bg0);color:var(--text);font-family:var(--mono);font-size:13px;}\nbody::before{content:\'\';position:fixed;inset:0;\n  background-image:linear-gradient(rgba(30,35,56,.3)1px,transparent 1px),\n  linear-gradient(90deg,rgba(30,35,56,.3)1px,transparent 1px);\n  background-size:40px 40px;pointer-events:none;z-index:0;}\n.shell{display:flex;flex-direction:column;height:100vh;position:relative;z-index:1;}\n/* ── Top bar ── */\n.topbar{background:var(--bg1);border-bottom:1px solid var(--bdr);\n  display:flex;align-items:center;gap:10px;padding:8px 16px;\n  flex-shrink:0;z-index:20;flex-wrap:wrap;}\n.logo{font-family:var(--sans);font-size:18px;font-weight:800;\n  color:var(--acc);letter-spacing:3px;white-space:nowrap;}\n.logo em{color:var(--text);font-style:normal;}\n.nav-row{display:flex;gap:2px;}\n.nb{background:none;border:none;color:var(--dim);font-family:var(--mono);\n  font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;\n  padding:5px 10px;border-radius:3px;cursor:pointer;transition:all .15s;}\n.nb:hover{color:var(--text);background:var(--bg2);}\n.nb.on{color:var(--acc);background:rgba(230,57,70,.1);border:1px solid rgba(230,57,70,.2);}\n.nb.ai{color:var(--ai);}\n.nb.ai.on{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.3);}\n.trow{display:flex;gap:6px;align-items:center;margin-left:auto;flex-wrap:wrap;}\n.tlbl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;white-space:nowrap;}\n.ti{background:var(--bg2);border:1px solid var(--bdr);color:var(--text);\n  font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:3px;\n  width:160px;outline:none;transition:border-color .2s;}\n.ti:focus{border-color:var(--pur);}\n.ti.ok{border-color:rgba(6,214,160,.5);color:var(--grn);}\n.ti.bad{border-color:rgba(230,57,70,.5);}\n.btn{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.5px;\n  padding:5px 12px;border-radius:3px;border:1px solid;cursor:pointer;transition:all .15s;}\n.btn-r{background:var(--acc);color:#fff;border-color:var(--acc);}\n.btn-r:hover{background:#c0303a;}\n.btn-g{background:none;color:var(--mid);border-color:var(--bdr);}\n.btn-g:hover{border-color:var(--mid);color:var(--text);}\n.btn-a{background:rgba(168,85,247,.15);color:var(--ai);border-color:rgba(168,85,247,.4);}\n.btn-a:hover{background:rgba(168,85,247,.25);}\n.spin{width:14px;height:14px;border:2px solid var(--bdr);border-top-color:var(--yel);\n  border-radius:50%;animation:spin .6s linear infinite;display:none;flex-shrink:0;}\n@keyframes spin{to{transform:rotate(360deg);}}\n.dot{width:7px;height:7px;border-radius:50%;background:var(--grn);\n  animation:pulse 2s infinite;flex-shrink:0;display:none;}\n@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(6,214,160,.4);}50%{opacity:.6;box-shadow:0 0 0 5px transparent;}}\n/* ── Pages ── */\n.pages{flex:1;overflow:hidden;position:relative;}\n.page{position:absolute;inset:0;display:none;overflow:hidden;}\n.page.on{display:flex;}\n/* ── Scan layout ── */\n.sl{display:grid;grid-template-columns:200px 1fr 200px;width:100%;height:100%;}\n.sb{background:var(--bg1);border-right:1px solid var(--bdr);\n  display:flex;flex-direction:column;overflow:hidden;}\n.sbr{border-right:none;border-left:1px solid var(--bdr);}\n.phd{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;\n  color:var(--dim);padding:10px 12px 8px;border-bottom:1px solid var(--bdr);flex-shrink:0;}\n.qg{padding:8px;display:grid;grid-template-columns:1fr 1fr;gap:5px;\n  flex-shrink:0;border-bottom:1px solid var(--bdr);}\n.qb{background:var(--bg2);border:1px solid var(--bdr);color:var(--mid);\n  font-family:var(--mono);font-size:10px;font-weight:600;padding:5px;\n  cursor:pointer;border-radius:3px;text-align:center;transition:all .15s;}\n.qb:hover{border-color:var(--pur);color:var(--pur);}\n.qball{grid-column:span 2;border-color:rgba(230,57,70,.4);color:var(--acc);}\n.qball:hover{background:rgba(230,57,70,.08);}\n.ml{overflow-y:auto;flex:1;}\n.mi{display:flex;align-items:center;gap:7px;padding:6px 10px;\n  cursor:pointer;border-bottom:1px solid rgba(30,35,56,.4);transition:background .1s;}\n.mi:hover{background:var(--bg2);}\n.mi.sep{pointer-events:none;opacity:.2;font-size:9px;padding:3px 10px;}\n.mn{font-size:11px;font-weight:600;color:var(--text);flex:1;\n  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}\n.ms{font-size:10px;font-weight:700;flex-shrink:0;}\n.ok{color:var(--grn);}.er{color:var(--acc);}\n.ru{color:var(--yel);animation:blink .8s infinite;}\n@keyframes blink{0%,100%{opacity:1;}50%{opacity:.2;}}\n/* ── Log ── */\n.lc{background:var(--bg0);display:flex;flex-direction:column;overflow:hidden;}\n.lb{padding:7px 12px;border-bottom:1px solid var(--bdr);display:flex;gap:8px;\n  align-items:center;background:var(--bg1);flex-shrink:0;}\n.lt{font-family:var(--sans);font-size:13px;font-weight:800;\n  color:var(--text);letter-spacing:1px;flex:1;}\n.lo{flex:1;overflow-y:auto;padding:10px 14px;font-size:12px;}\n.ll{padding:1px 0;word-break:break-all;}\n.lC{color:var(--acc);font-weight:700;}.lH{color:var(--org);}\n.lM{color:var(--yel);}.lO{color:var(--grn);}\n.lI{color:#89b4fa;}.lS{color:var(--pur);font-weight:600;}.lD{color:var(--dim);}\n.emp{text-align:center;color:var(--dim);padding:50px 20px;font-size:13px;}\n.emp .ei{font-size:40px;display:block;margin-bottom:10px;opacity:.3;}\n/* ── Stats ── */\n.stb{padding:12px;overflow-y:auto;flex:1;}\n.sr{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--bdr);}\n.sl2{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;}\n.sv{font-family:var(--sans);font-size:20px;font-weight:800;}\n.sC{color:var(--acc);}.sH{color:var(--org);}.sM{color:var(--yel);}\n.sL{color:var(--blu);}.sT{color:var(--text);}\n.scb{margin-top:10px;background:var(--bg2);border:1px solid var(--bdr);\n  border-radius:4px;padding:10px;text-align:center;}\n.sn{font-family:var(--sans);font-size:36px;font-weight:800;color:var(--acc);line-height:1;}\n.ss{font-size:10px;color:var(--dim);margin-top:3px;}\n.str{height:5px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden;}\n.stf{height:5px;background:linear-gradient(90deg,var(--acc),#ff6b6b);border-radius:3px;transition:width .8s;}\n.hi{display:flex;gap:6px;padding:4px 0;border-bottom:1px solid rgba(30,35,56,.4);font-size:10px;}\n.ht{color:var(--dim);min-width:52px;}.hok{color:var(--grn);}.her{color:var(--acc);}\n/* ── AI page ── */\n.ail{display:grid;grid-template-columns:220px 1fr;width:100%;height:100%;}\n.aisb{background:var(--bg1);border-right:1px solid var(--bdr);display:flex;flex-direction:column;}\n.ait{display:flex;flex-direction:column;gap:6px;padding:12px;overflow-y:auto;flex:1;}\n.atb{background:var(--bg2);border:1px solid var(--bdr);color:var(--mid);font-family:var(--mono);\n  font-size:11px;font-weight:600;padding:10px 12px;cursor:pointer;border-radius:4px;\n  text-align:left;transition:all .15s;display:flex;flex-direction:column;gap:3px;}\n.atb:hover{border-color:var(--ai);color:var(--ai);}\n.atb .n{color:var(--text);font-size:12px;}.atb .d{font-size:10px;color:var(--dim);}\n.aim{display:flex;flex-direction:column;background:var(--bg0);}\n.aih{padding:12px 16px;border-bottom:1px solid var(--bdr);background:var(--bg1);flex-shrink:0;}\n.aih h2{font-family:var(--sans);font-size:16px;font-weight:800;color:var(--ai);letter-spacing:2px;}\n.aih p{font-size:11px;color:var(--dim);margin-top:3px;}\n.cms{flex:1;overflow-y:auto;padding:16px;}\n.cm{display:flex;gap:12px;margin-bottom:16px;}\n.cm.u{flex-direction:row-reverse;}\n.av{width:28px;height:28px;border-radius:4px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;}\n.uav{background:rgba(230,57,70,.2);border:1px solid rgba(230,57,70,.3);}\n.aav{background:rgba(168,85,247,.2);border:1px solid rgba(168,85,247,.3);}\n.cb{max-width:80%;background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;padding:10px 14px;font-size:12px;line-height:1.6;}\n.cm.u .cb{background:rgba(230,57,70,.08);border-color:rgba(230,57,70,.2);}\n.cb h3{color:var(--ai);font-size:12px;margin-bottom:4px;}\n.cb code{background:var(--bg3);border:1px solid var(--bdr);padding:1px 5px;border-radius:2px;font-size:11px;}\n.cir{padding:12px 16px;border-top:1px solid var(--bdr);display:flex;gap:8px;background:var(--bg1);flex-shrink:0;}\n.ci{flex:1;background:var(--bg2);border:1px solid var(--bdr);color:var(--text);font-family:var(--mono);font-size:12px;padding:8px 12px;border-radius:4px;outline:none;resize:none;min-height:36px;max-height:100px;}\n.ci:focus{border-color:var(--ai);}\n.cs{background:var(--ai);color:#fff;border:none;font-family:var(--mono);font-size:11px;font-weight:700;padding:8px 16px;border-radius:4px;cursor:pointer;transition:background .15s;}\n.cs:hover{background:#9333ea;}.cs:disabled{opacity:.4;cursor:not-allowed;}\n.ar{flex:1;overflow-y:auto;padding:16px;font-size:12px;line-height:1.7;}\n.ar h2{color:var(--ai);font-family:var(--sans);font-size:15px;font-weight:800;margin:16px 0 6px;letter-spacing:1px;border-bottom:1px solid var(--bdr);padding-bottom:4px;}\n.ar h3{color:var(--yel);font-size:12px;font-weight:700;margin:12px 0 4px;}\n.ar p{color:var(--mid);margin-bottom:8px;}.ar li{color:var(--mid);margin-left:16px;margin-bottom:3px;}\n.ar strong{color:var(--text);}\n.ar code{background:var(--bg3);border:1px solid var(--bdr);padding:1px 6px;border-radius:3px;font-size:11px;color:var(--grn);}\n.thk{display:flex;align-items:center;gap:10px;padding:20px;color:var(--dim);}\n.thk .d span{animation:db 1.2s infinite;opacity:0;}\n.thk .d span:nth-child(2){animation-delay:.2s;}\n.thk .d span:nth-child(3){animation-delay:.4s;}\n@keyframes db{0%,80%,100%{opacity:0;}40%{opacity:1;}}\n.mtt{width:100%;border-collapse:collapse;font-size:11px;margin-top:12px;}\n.mtt th{background:var(--bg2);color:var(--dim);text-align:left;padding:7px 10px;font-size:10px;letter-spacing:1px;text-transform:uppercase;border-bottom:2px solid var(--bdr);}\n.mtt td{padding:6px 10px;border-bottom:1px solid var(--bdr);color:var(--mid);}\n.mtt tr:hover td{background:var(--bg2);}\n.mt{color:var(--blu);font-weight:600;}.mC{color:var(--acc);}.mH{color:var(--org);}.mM{color:var(--yel);}\n/* ── Toast ── */\n.toast{position:fixed;bottom:20px;right:20px;background:var(--bg1);border:1px solid var(--bdr);border-radius:4px;padding:8px 14px;font-size:12px;z-index:999;opacity:0;transition:opacity .25s;pointer-events:none;}\n.toast.show{opacity:1;}.tok{border-color:var(--grn);color:var(--grn);}.terr{border-color:var(--acc);color:var(--acc);}\n/* ── Startup dialog ── */\n.sov{display:flex;position:fixed;inset:0;background:rgba(6,8,16,.97);z-index:400;align-items:center;justify-content:center;}\n.sbox{background:var(--bg1);border:2px solid var(--bdr);border-radius:10px;padding:36px 40px;max-width:500px;width:92%;}\n.slogo{font-family:var(--sans);font-size:30px;font-weight:800;color:var(--acc);letter-spacing:3px;margin-bottom:4px;}\n.slogo em{color:var(--text);font-style:normal;}\n.stag{font-size:12px;color:var(--dim);margin-bottom:26px;line-height:1.7;}\n.flbl{display:block;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--dim);margin:14px 0 5px;}\n.finp{width:100%;background:var(--bg2);border:1px solid var(--bdr);color:var(--text);font-family:var(--mono);font-size:13px;padding:10px 12px;border-radius:4px;outline:none;transition:border-color .2s;}\n.finp:focus{border-color:var(--pur);}\n.serr{color:var(--acc);font-size:11px;min-height:16px;margin:10px 0 4px;}\n.sbtns{display:flex;gap:8px;margin-top:14px;}\n.sbtn{flex:1;background:var(--acc);color:#fff;border:none;font-family:var(--mono);font-size:12px;font-weight:700;padding:12px;border-radius:4px;cursor:pointer;letter-spacing:.5px;transition:background .15s;}\n.sbtn:hover{background:#c0303a;}\n.sskip{background:none;border:1px solid var(--bdr);color:var(--dim);font-family:var(--mono);font-size:11px;padding:12px 16px;border-radius:4px;cursor:pointer;transition:all .15s;}\n.sskip:hover{border-color:var(--mid);color:var(--text);}\n.snote{margin-top:16px;font-size:10px;color:var(--dim);text-align:center;line-height:1.6;border-top:1px solid var(--bdr);padding-top:12px;}\n</style>\n</head>\n<body>\n<div class="shell">\n\n<!-- ── Top bar ── -->\n<div class="topbar">\n  <div class="logo">PHANTOM<em>X</em></div>\n  <div class="nav-row">\n    <button class="nb on" onclick="pg(\'scan\',this)">Scan</button>\n    <button class="nb ai"  onclick="pg(\'ai\',this)">✦ AI</button>\n    <button class="nb" onclick="open(\'/comparison\',\'_blank\')">vs Tools</button>\n    <button class="nb" onclick="open(\'/architecture\',\'_blank\')">Arch</button>\n    <button class="nb" onclick="open(\'/help\',\'_blank\')">Help</button>\n  </div>\n  <div class="trow">\n    <span class="tlbl">Target</span>\n    <input class="ti bad" id="ti" placeholder="Target IP / hostname" autocomplete="off"\n           onchange="updateTargetStyle()">\n    <span class="tlbl">Domain</span>\n    <input class="ti" id="di" placeholder="corp.local  (optional)" style="width:130px" autocomplete="off">\n    <button class="btn btn-r" onclick="applyTarget()">Apply</button>\n    <div class="dot" id="dot"></div>\n    <div class="spin" id="spin"></div>\n    <span id="rl" style="font-size:10px;color:var(--yel)"></span>\n  </div>\n</div>\n\n<!-- ── Pages ── -->\n<div class="pages">\n\n  <!-- SCAN -->\n  <div class="page on" id="pg-scan">\n    <div class="sl">\n      <div class="sb">\n        <div class="phd">Modules</div>\n        <div class="qg">\n          <button class="qb qball" onclick="run(\'all\')">⚡ RUN ALL</button>\n          <button class="qb" onclick="run(\'enum\')">Enum</button>\n          <button class="qb" onclick="run(\'privesc\')">PrivEsc</button>\n          <button class="qb" onclick="run(\'loot\')">Loot</button>\n          <button class="qb" onclick="run(\'vulnscan\')">Vuln</button>\n          <button class="qb" onclick="run(\'services\')">Services</button>\n          <button class="qb" onclick="run(\'activedir\')">AD</button>\n          <button class="qb" onclick="run(\'apitesting\')">API</button>\n        </div>\n        <div class="ml" id="ml"></div>\n      </div>\n\n      <div class="lc">\n        <div class="lb">\n          <span class="lt" id="ltt">OUTPUT LOG</span>\n          <button class="btn btn-g" style="font-size:10px" onclick="clrLog()">Clear</button>\n          <button class="btn btn-g" style="font-size:10px" onclick="genRep(\'html\')">Report</button>\n          <button class="btn btn-a" style="font-size:10px" onclick="pg(\'ai\');qai(\'analyse\')">✦ AI Analyse</button>\n        </div>\n        <div class="lo" id="lo">\n          <div class="emp"><span class="ei">⚔️</span>Select a module and click Run.<br>Output streams here in real time.</div>\n        </div>\n      </div>\n\n      <div class="sb sbr">\n        <div class="phd">Statistics</div>\n        <div class="stb">\n          <div class="sr"><span class="sl2">Critical</span><span class="sv sC" id="cC">0</span></div>\n          <div class="sr"><span class="sl2">High</span>    <span class="sv sH" id="cH">0</span></div>\n          <div class="sr"><span class="sl2">Medium</span>  <span class="sv sM" id="cM">0</span></div>\n          <div class="sr"><span class="sl2">Low</span>     <span class="sv sL" id="cL">0</span></div>\n          <div class="sr" style="border-bottom:2px solid var(--bdr)">\n            <span class="sl2">Total</span><span class="sv sT" id="cT">0</span>\n          </div>\n          <div class="scb" id="scb" style="display:none">\n            <div class="sn" id="sn">0.0</div>\n            <div class="ss">Risk / 10.0</div>\n            <div class="str"><div class="stf" id="sf" style="width:0%"></div></div>\n          </div>\n          <div class="phd" style="margin-top:10px;padding-left:0">History</div>\n          <div id="hl"></div>\n        </div>\n      </div>\n    </div>\n  </div>\n\n  <!-- AI -->\n  <div class="page" id="pg-ai">\n    <div class="ail">\n      <div class="aisb">\n        <div class="phd">✦ AI Tools</div>\n        <div class="ait">\n          <button class="atb" onclick="showAI(\'chat\')">\n            <span class="n">💬 Security Chat</span>\n            <span class="d">Ask anything about your scan results</span>\n          </button>\n          <button class="atb" onclick="qai(\'analyse\')">\n            <span class="n">🔍 Analyse Findings</span>\n            <span class="d">AI risk analysis with context</span>\n          </button>\n          <button class="atb" onclick="qai(\'report\')">\n            <span class="n">📄 Generate Report</span>\n            <span class="d">Executive summary narrative</span>\n          </button>\n          <button class="atb" onclick="qai(\'mitre\')">\n            <span class="n">🎯 MITRE ATT&amp;CK</span>\n            <span class="d">Map findings to techniques</span>\n          </button>\n          <button class="atb" onclick="qai(\'chain\')">\n            <span class="n">⛓️ Attack Chain</span>\n            <span class="d">Most likely adversary path</span>\n          </button>\n          <button class="atb" onclick="qai(\'remediate\')">\n            <span class="n">🔧 Remediation Plan</span>\n            <span class="d">Prioritised fix roadmap</span>\n          </button>\n        </div>\n        <div style="padding:12px;border-top:1px solid var(--bdr);flex-shrink:0">\n          <button class="btn btn-g" style="width:100%;font-size:10px" onclick="rstChat()">Reset Chat</button>\n        </div>\n      </div>\n\n      <div class="aim">\n        <div id="cv" style="display:flex;flex-direction:column;height:100%">\n          <div class="aih">\n            <h2>✦ AI Security Assistant</h2>\n            <p>Run scan modules first, then ask me to analyse findings, map ATT&amp;CK techniques, generate reports, or explain vulnerabilities.</p>\n          </div>\n          <div class="cms" id="cms">\n            <div class="cm">\n              <div class="av aav">✦</div>\n              <div class="cb">Hello! I\'m the PhantomX AI analyst.<br><br>\n                Run some scan modules first, then I can:<br>\n                • Analyse findings and explain risks<br>\n                • Generate an executive summary report<br>\n                • Map findings to MITRE ATT&amp;CK<br>\n                • Identify the most likely attack chain<br>\n                • Create a prioritised remediation plan\n              </div>\n            </div>\n          </div>\n          <div class="cir">\n            <textarea class="ci" id="cinp" rows="1"\n              placeholder="Ask about your scan results..."\n              onkeydown="ck(event)"></textarea>\n            <button class="cs" id="csnd" onclick="sndChat()">Send</button>\n          </div>\n        </div>\n        <div id="rv" style="display:none;flex-direction:column;height:100%">\n          <div class="aih" style="display:flex;align-items:center;gap:12px">\n            <div style="flex:1">\n              <h2 id="rt">AI Analysis</h2>\n              <p  id="rs">Processing...</p>\n            </div>\n            <button class="btn btn-g" style="font-size:10px" onclick="showAI(\'chat\')">← Chat</button>\n          </div>\n          <div class="ar" id="rb"></div>\n        </div>\n      </div>\n    </div>\n  </div>\n\n</div>\n</div>\n\n<!-- ── Startup target dialog ── -->\n<div class="sov" id="sov">\n  <div class="sbox">\n    <div class="slogo">PHANTOM<em>X</em></div>\n    <div class="stag">\n      Advanced Security Assessment Framework v6.0<br>\n      Set your scan target below to begin. You can update it anytime.\n    </div>\n\n    <label class="flbl" for="st">\n      Target IP / Hostname&nbsp;<span style="color:var(--acc)">*</span>\n    </label>\n    <input class="finp" id="st" autocomplete="off"\n           placeholder="e.g.  10.10.10.5   or   target.local"\n           onkeydown="if(event.key===\'Enter\')doStart()">\n\n    <label class="flbl" for="sd">\n      Domain Name&nbsp;<span style="color:var(--dim)">(optional — for Active Directory / DNS)</span>\n    </label>\n    <input class="finp" id="sd" autocomplete="off"\n           placeholder="e.g.  corp.local"\n           onkeydown="if(event.key===\'Enter\')doStart()">\n\n    <div class="serr" id="se"></div>\n\n    <div class="sbtns">\n      <button class="sbtn" onclick="doStart()">▶&nbsp; Start Scanning</button>\n      <button class="sskip" onclick="skipStart()">Skip</button>\n    </div>\n\n    <div class="snote">\n      ⚠️&nbsp; Only scan systems you <strong style="color:var(--text)">own</strong>\n      or have <strong style="color:var(--text)">explicit written permission</strong> to test.<br>\n      Unauthorized scanning is illegal and unethical.\n    </div>\n  </div>\n</div>\n\n<div class="toast" id="tst"></div>\n\n<script>\nconst MODS=[\n  {l:"ALL MODULES",c:"all"},{l:"───",c:null},\n  {l:"Enumerate",c:"enum"},{l:"Priv-Esc",c:"privesc"},\n  {l:"Persistence",c:"persist"},{l:"Loot",c:"loot"},\n  {l:"Lateral",c:"lateral"},{l:"Network",c:"network"},\n  {l:"Audit",c:"audit"},{l:"Container",c:"container"},\n  {l:"Web App",c:"webapp"},{l:"Vuln Scan",c:"vulnscan"},\n  {l:"Fuzzer",c:"fuzzer"},{l:"CVE Check",c:"cvecheck"},\n  {l:"Recon",c:"recon"},{l:"Services",c:"services"},\n  {l:"Active Dir",c:"activedir"},{l:"Evasion",c:"evasion"},\n  {l:"Post-Exploit",c:"postexploit"},{l:"API Testing",c:"apitesting"},\n  {l:"Pass Attack",c:"passattack"},{l:"Wireless",c:"wireless"},\n  {l:"DNS Recon",c:"dnsrecon"},{l:"Traffic",c:"traffic"},\n];\nconst ICO={all:"🔴",enum:"🔍",privesc:"⬆️",persist:"🔒",loot:"💰",lateral:"↔️",\n  network:"🌐",audit:"📋",container:"🐳",webapp:"🕸️",vulnscan:"🎯",\n  fuzzer:"🔧",cvecheck:"🛡️",recon:"🗺️",services:"⚙️",activedir:"🏢",\n  evasion:"👻",postexploit:"💻",apitesting:"🔌",passattack:"🔑",\n  wireless:"📡",dnsrecon:"📡",traffic:"📶"};\nconst NT=new Set(["network","webapp","vulnscan","fuzzer","cvecheck","apitesting",\n  "passattack","services","activedir","evasion","postexploit","recon","dnsrecon","traffic","all"]);\n\nlet logOff=0, chatH=[];\n\n// ── Startup dialog ─────────────────────────────────────────────────────────\nfunction doStart(){\n  const t=document.getElementById("st").value.trim();\n  const d=document.getElementById("sd").value.trim();\n  if(!t){document.getElementById("se").textContent="Target IP or hostname is required.";return;}\n  document.getElementById("ti").value=t;\n  document.getElementById("di").value=d;\n  document.getElementById("ti").classList.add("ok");\n  document.getElementById("ti").classList.remove("bad");\n  fetch(`/api/set?key=target&value=${encodeURIComponent(t)}`);\n  if(d)fetch(`/api/set?key=domain&value=${encodeURIComponent(d)}`);\n  document.getElementById("sov").style.display="none";\n  toast(`Target set: ${t}`,"tok");\n}\nfunction skipStart(){\n  document.getElementById("sov").style.display="none";\n  toast("Tip: Set target using the header field + Apply button.","tok");\n}\n\n// ── Page nav ───────────────────────────────────────────────────────────────\nfunction pg(id,btn){\n  document.querySelectorAll(".page").forEach(p=>p.classList.remove("on"));\n  document.querySelectorAll(".nb").forEach(b=>b.classList.remove("on"));\n  document.getElementById("pg-"+id).classList.add("on");\n  if(btn)btn.classList.add("on");\n}\n\n// ── Module list ────────────────────────────────────────────────────────────\nfunction mkMods(ms){\n  ms=ms||{};\n  document.getElementById("ml").innerHTML=MODS.map(m=>{\n    if(!m.c)return`<div class="mi sep">──────────</div>`;\n    const st=ms[m.c]||"";\n    const sh=st==="ok"?\'<span class="ms ok">[+]</span>\':\n             st==="err"?\'<span class="ms er">[-]</span>\':\n             st==="run"?\'<span class="ms ru">[~]</span>\':"";\n    return`<div class="mi" onclick="run(\'${m.c}\')">\n      <span style="font-size:13px">${ICO[m.c]||"📌"}</span>\n      <span class="mn">${m.l}</span>${sh}</div>`;\n  }).join("");\n}\n\n// ── Run module ─────────────────────────────────────────────────────────────\nfunction run(cmd){\n  const t=document.getElementById("ti").value.trim();\n  if(NT.has(cmd)&&!t){\n    // Inline prompt if no target\n    const ans=window.prompt(\n      `Module \'${cmd}\' needs a target IP / hostname.\\nEnter it now:`,\n      "10.10.10.5"\n    );\n    if(!ans)return;\n    const v=ans.trim();\n    document.getElementById("ti").value=v;\n    document.getElementById("st").value=v;\n    document.getElementById("ti").classList.add("ok");\n    document.getElementById("ti").classList.remove("bad");\n    fetch(`/api/set?key=target&value=${encodeURIComponent(v)}`);\n  }\n  fetch(`/api/run?module=${encodeURIComponent(cmd)}`)\n    .then(r=>r.json())\n    .then(d=>{\n      if(d.error){toast(d.error,"terr");return;}\n      document.getElementById("lo").innerHTML="";\n      logOff=0;\n      toast(`Started: ${cmd}`,"tok");\n    });\n}\n\n// ── Apply target from header ───────────────────────────────────────────────\nfunction applyTarget(){\n  const t=document.getElementById("ti").value.trim();\n  const d=document.getElementById("di").value.trim();\n  if(t){\n    fetch(`/api/set?key=target&value=${encodeURIComponent(t)}`);\n    document.getElementById("st").value=t;\n    updateTargetStyle();\n  }\n  fetch(`/api/set?key=domain&value=${encodeURIComponent(d)}`);\n  toast(t?`Target: ${t}`:"Target cleared",t?"tok":"terr");\n}\nfunction updateTargetStyle(){\n  const inp=document.getElementById("ti");\n  const v=inp.value.trim();\n  inp.classList.toggle("ok",!!v);\n  inp.classList.toggle("bad",!v);\n}\n\n// ── Log polling ────────────────────────────────────────────────────────────\nfunction pollLog(){\n  fetch(`/api/log?offset=${logOff}`).then(r=>r.json()).then(d=>{\n    addLines(d.lines);logOff=d.total;\n  }).catch(()=>{});\n}\nfunction addLines(lines){\n  if(!lines.length)return;\n  const el=document.getElementById("lo");\n  if(el.querySelector(".emp"))el.innerHTML="";\n  const atB=el.scrollTop+el.clientHeight>=el.scrollHeight-40;\n  lines.forEach(l=>{\n    const d=document.createElement("div");\n    d.className="ll "+cls(l);\n    d.textContent=l;\n    el.appendChild(d);\n  });\n  if(atB)el.scrollTop=el.scrollHeight;\n}\nfunction cls(l){\n  const ll=l.toLowerCase();\n  if(ll.includes("critical"))return"lC";\n  if(ll.includes("high"))    return"lH";\n  if(ll.includes("medium"))  return"lM";\n  if(l.includes("[+]")||ll.includes("success")||ll.includes("complete"))return"lO";\n  if(l.includes("[*]")||ll.includes("scanning")||ll.includes("checking"))return"lI";\n  if(l.includes("──")||l.includes("Starting")||l.includes("Done"))return"lS";\n  return"lD";\n}\nfunction pollSt(){\n  fetch("/api/state").then(r=>r.json()).then(st=>{\n    ["critical","high","medium","low","total"].forEach(k=>{\n      const e=document.getElementById("c"+k[0].toUpperCase());\n      if(e)e.textContent=st.counts?.[k]||0;\n    });\n    document.getElementById("cT").textContent=st.counts?.total||0;\n    mkMods(st.mstates);\n    const r=st.running;\n    document.getElementById("spin").style.display=r?"block":"none";\n    document.getElementById("dot").style.display=r?"block":"none";\n    document.getElementById("rl").textContent=r?`▶ ${st.current}`:"";\n    document.getElementById("ltt").textContent=r?`▶ ${(st.current||"").toUpperCase()}`:"OUTPUT LOG";\n    document.getElementById("hl").innerHTML=(st.history||[]).slice(0,15).map(h=>\n      `<div class="hi"><span class="ht">${h.time}</span>\n       <span class="${h.status===\'ok\'?\'hok\':\'her\'}">${h.status===\'ok\'?\'[+]\':\'[-]\'}</span>\n       <span style="color:var(--mid)">${h.module}</span></div>`\n    ).join("");\n  }).catch(()=>{});\n}\n\n// ── Actions ────────────────────────────────────────────────────────────────\nfunction clrLog(){\n  fetch("/api/clear").then(()=>{\n    document.getElementById("lo").innerHTML=\'<div class="emp"><span class="ei">🗑️</span>Cleared.</div>\';\n    logOff=0;\n  });\n}\nfunction genRep(f){\n  fetch(`/api/report?format=${f}`).then(r=>r.json()).then(d=>{\n    if(d.error)toast(d.error,"terr");else toast(`Report: ${d.path}`,"tok");\n  });\n}\n\n// ── AI ─────────────────────────────────────────────────────────────────────\nfunction showAI(m){\n  document.getElementById("cv").style.display=m==="chat"?"flex":"none";\n  document.getElementById("rv").style.display=m==="result"?"flex":"none";\n}\nfunction qai(ep){\n  pg("ai");\n  showAI("result");\n  const T={analyse:"AI Finding Analysis",report:"AI Report",\n           mitre:"MITRE ATT&CK Mapping",chain:"Attack Chain",\n           remediate:"Remediation Plan"};\n  document.getElementById("rt").textContent=T[ep]||"AI Analysis";\n  document.getElementById("rs").textContent="Calling Claude API...";\n  document.getElementById("rb").innerHTML=\n    \'<div class="thk"><span style="font-size:24px">✦</span> Analysing<div class="d"><span>.</span><span>.</span><span>.</span></div></div>\';\n  fetch(`/api/ai/${ep}`,{method:"POST",\n    headers:{"Content-Type":"application/json"},body:"{}"})\n    .then(r=>r.json())\n    .then(d=>{\n      document.getElementById("rs").textContent="Complete";\n      if(d.error){\n        document.getElementById("rb").innerHTML=`<p style="color:var(--acc);padding:20px">Error: ${esc(d.error)}</p>`;\n        return;\n      }\n      if(ep==="mitre"&&d.mapped)rMITRE(d.mapped,d.summary||"");\n      else rMD(d.result||"","rb");\n    })\n    .catch(e=>{\n      document.getElementById("rb").innerHTML=\n        `<p style="color:var(--acc);padding:20px">Error: ${esc(e.message)}</p>`;\n    });\n}\nfunction rMITRE(m,s){\n  const rows=m.map(r=>{\n    const c=r.severity==="critical"?"mC":r.severity==="high"?"mH":"mM";\n    return`<tr><td class="mt">${esc(r.technique)}</td><td>${esc(r.name)}</td>\n      <td class="${c}">${(r.severity||"").toUpperCase()}</td>\n      <td style="color:var(--dim)">${esc((r.finding||"").split(".").pop())}</td></tr>`;\n  }).join("");\n  document.getElementById("rb").innerHTML=\n    (s?`<p style="color:var(--mid);padding:0 0 12px">${esc(s)}</p>`:"")\n    +`<table class="mtt"><thead><tr><th>Technique</th><th>Name</th><th>Severity</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table>`;\n}\nfunction rMD(t,id){\n  document.getElementById(id).innerHTML=esc(t)\n    .replace(/^## (.+)$/gm,"<h2>$1</h2>")\n    .replace(/^### (.+)$/gm,"<h3>$1</h3>")\n    .replace(/\\*\\*(.+?)\\*\\*/g,"<strong>$1</strong>")\n    .replace(/`([^`]+)`/g,"<code>$1</code>")\n    .replace(/^[-*] (.+)$/gm,"<li>$1</li>")\n    .replace(/\\n\\n/g,"</p><p>").replace(/\\n/g,"<br>");\n}\nfunction ck(e){if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sndChat();}}\nfunction sndChat(){\n  const inp=document.getElementById("cinp");\n  const msg=inp.value.trim();\n  if(!msg)return;\n  inp.value="";\n  addMsg(msg,"u");\n  document.getElementById("csnd").disabled=true;\n  const tid="t"+Date.now();\n  addMsg("✦ thinking...","a",tid);\n  fetch("/api/ai/chat",{method:"POST",\n    headers:{"Content-Type":"application/json"},\n    body:JSON.stringify({message:msg,history:chatH})})\n    .then(r=>r.json())\n    .then(d=>{\n      const e=document.getElementById(tid);if(e)e.remove();\n      document.getElementById("csnd").disabled=false;\n      if(d.error){addMsg("Error: "+d.error,"a");return;}\n      chatH=d.history||[];addMsg(d.result||"","a");\n    })\n    .catch(e=>{\n      const el=document.getElementById(tid);if(el)el.remove();\n      document.getElementById("csnd").disabled=false;\n      addMsg("Error: "+e.message,"a");\n    });\n}\nfunction addMsg(text,role,id){\n  const msgs=document.getElementById("cms");\n  const div=document.createElement("div");\n  div.className=`cm${role==="u"?" u":""}`;\n  if(id)div.id=id;\n  const av=`<div class="av ${role==="u"?"uav":"aav"}">${role==="u"?"⚙":"✦"}</div>`;\n  const bub=document.createElement("div");\n  bub.className="cb";\n  if(role==="a"&&text!=="✦ thinking..."){\n    bub.innerHTML=esc(text)\n      .replace(/^## (.+)$/gm,"<h3>$1</h3>")\n      .replace(/\\*\\*(.+?)\\*\\*/g,"<strong>$1</strong>")\n      .replace(/`([^`]+)`/g,"<code>$1</code>")\n      .replace(/^[-*] (.+)$/gm,"<li>$1</li>")\n      .replace(/\\n/g,"<br>");\n  } else {\n    bub.textContent=text;\n    if(text==="✦ thinking...")bub.style.color="var(--dim)";\n  }\n  div.innerHTML=role==="u"\n    ?`<div class="cb" style="background:rgba(230,57,70,.08);border-color:rgba(230,57,70,.2)">${esc(text)}</div>${av}`\n    :av;\n  if(role!=="u")div.appendChild(bub);\n  msgs.appendChild(div);\n  msgs.scrollTop=msgs.scrollHeight;\n}\nfunction rstChat(){\n  chatH=[];\n  document.getElementById("cms").innerHTML=\n    \'<div class="cm"><div class="av aav">✦</div><div class="cb">Conversation reset. How can I help?</div></div>\';\n  toast("Chat reset","tok");\n}\nfunction esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}\nfunction toast(msg,c="tok"){\n  const e=document.getElementById("tst");\n  e.textContent=msg;e.className=`toast ${c} show`;\n  setTimeout(()=>e.classList.remove("show"),3000);\n}\n\n// ── Init ───────────────────────────────────────────────────────────────────\nmkMods();\nsetInterval(pollLog,500);\nsetInterval(pollSt,1500);\nfetch("/api/state").then(r=>r.json()).then(st=>{\n  mkMods(st.mstates||{});\n  const t=st.target||"",d=st.domain||"";\n  document.getElementById("ti").value=t;\n  document.getElementById("di").value=d;\n  if(t){\n    document.getElementById("st").value=t;\n    document.getElementById("sd").value=d;\n    document.getElementById("ti").classList.add("ok");\n    document.getElementById("ti").classList.remove("bad");\n    // Target already set — close dialog\n    document.getElementById("sov").style.display="none";\n  }\n  fetch("/api/log?offset=0").then(r=>r.json()).then(data=>{\n    if(data.lines.length){addLines(data.lines);logOff=data.total;}\n  });\n  fetch("/api/score").then(r=>r.json()).then(sc=>{\n    if(sc.overall){\n      document.getElementById("scb").style.display="block";\n      document.getElementById("sn").textContent=sc.overall.toFixed(1);\n      document.getElementById("sf").style.width=`${sc.overall*10}%`;\n    }\n  }).catch(()=>{});\n});\n</script>\n</body>\n</html>'


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="PhantomX AI Web GUI")
    ap.add_argument("--port",       type=int, default=7331)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    url    = f"http://127.0.0.1:{args.port}"

    print(f"""
  ╔══════════════════════════════════════════════════════╗
  ║   PhantomX AI Web GUI  v6.0                          ║
  ║   {url:<52}║
  ║                                                      ║
  ║   Startup dialog asks for target before scanning.    ║
  ║   Pages:  /             Dashboard + AI analyst       ║
  ║            /comparison  vs Metasploit, BloodHound    ║
  ║            /architecture  System design              ║
  ║            /help          Full command reference     ║
  ║                                                      ║
  ║   Press Ctrl+C to stop                               ║
  ╚══════════════════════════════════════════════════════╝
""")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  GUI stopped.\n")


if __name__ == "__main__":
    main()
