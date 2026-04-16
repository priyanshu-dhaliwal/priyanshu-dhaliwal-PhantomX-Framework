# priyanshu-dhaliwal-PhantomX-Framework
PhantomX — Advanced Security Assessment Framework
```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║╚██╗██╔╝
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║ ╚███╔╝
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║ ██╔██╗
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
```

**v6.0 — Unified Red Team Assessment Framework**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![Modules](https://img.shields.io/badge/Modules-22-e63946?style=flat-square)](https://github.com)
[![Tests](https://img.shields.io/badge/Tests-62%20Passing-3fb950?style=flat-square)](https://github.com)
[![Deps](https://img.shields.io/badge/External%20Deps-Zero-brightgreen?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

> ⚠️ **For Authorized Penetration Testing Only.**
> Only use on systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal under CFAA, Computer Misuse Act, IT Act (India), and equivalent laws worldwide.

</div>

---

## 📑 Table of Contents

- [Project Summary](#-project-summary)
- [Key Features](#-key-features)
- [Project Statistics](#-project-statistics)
- [Architecture](#-architecture)
- [All 22 Modules](#-all-22-modules)
- [Installation](#-installation-on-kali-linux)
- [Quick Start](#-quick-start)
- [Three Interfaces](#-three-interfaces)
- [All Commands](#-all-commands)
- [AI Integration](#-ai-integration)
- [Automation & Alerting](#-automation--alerting)
- [Reports & Dashboard](#-reports--dashboard)
- [Testing](#-testing)
- [Common Errors & Fixes](#-common-errors--fixes)
- [Project Structure](#-project-structure)
- [GitHub Deployment](#-github-deployment)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 📋 Project Summary

PhantomX is a **unified Python-based security assessment framework** built for
authorized penetration testing on Kali Linux. It brings together 22 scanning
modules covering every phase of an assessment — from passive reconnaissance
through post-exploitation — into one cohesive tool with three interfaces,
AI-powered analysis, and automated reporting.

**What makes PhantomX different:**

- **Single tool, full scope** — recon → enum → vuln scan → AD assessment →
  post-exploitation → reporting, all in one CLI
- **Interactive target prompting** — every interface asks for your target IP
  before any scan runs; nothing touches a network without your input
- **Zero external Python dependencies** — runs on any Python 3.8+ using
  stdlib only; no pip installs required for the framework itself
- **AI integration** — Anthropic Claude API explains findings, maps MITRE
  ATT&CK techniques, writes executive summaries, and suggests remediation
- **62 unit tests** with GitHub Actions CI/CD across Python 3.9–3.12

---

## ✨ Key Features

### Reconnaissance & Discovery
- Passive OSINT: WHOIS, ASN, certificate transparency logs (crt.sh),
  Google dork query generation, email security (SPF/DMARC/DKIM)
- Active: subdomain brute-force (150+ word list, 30 threads), WAF/CDN
  fingerprinting, virtual host discovery, reverse DNS /24 sweep
- DNS: zone transfer (AXFR/IXFR), DNSSEC analysis, subdomain takeover
  via dangling CNAME, open resolver / amplification check

### Vulnerability Scanning
- OWASP CWE Top 25: SQLi, XSS, SSRF, XXE, SSTI, IDOR, path traversal, RCE
- 300+ CVE banner-matching rules: Apache, PHP, MySQL, nginx, Docker, kernel
- OWASP API Top 10 (2023): BOLA, mass assignment, JWT (alg:none, RS256→HS256),
  GraphQL introspection, batch query DoS, rate limiting bypass
- Web: security headers, CORS, cookie flags, SSL/TLS audit, info disclosure

### Active Directory Assessment
- User enumeration (UAC flags, never-expire accounts), group membership
- Kerberoasting (SPN enum), AS-REP roasting, attack commands included
- Delegation abuse: unconstrained, constrained, resource-based (RBCD)
- AD CS / ESC1-ESC8 certificate template detection
- LAPS deployment check, domain trust mapping, password policy extraction
- BloodHound collection commands auto-generated in output

### Network & Protocol Enumeration
- SMB: null sessions, share enum, EternalBlue (MS17-010), signing check,
  RID cycling, domain/workgroup extraction
- SNMP: community string brute-force (20 strings), full OID walk
  (interfaces, ARP table, running processes, installed software, users)
- NetBIOS name table, MAC address, DC detection
- SSH: version/CVE check, weak algorithm detection (MD5, arcfour, DH group1)
- LDAP: anonymous bind, base DN, user/group enum, lockout policy
- FTP: anonymous login, vsftpd 2.3.4 backdoor, bounce attack detection

### Post-Exploitation
- SUID/GTFOBins, sudo misconfigurations (NOPASSWD), cron jobs,
  Linux capabilities, dangerous group membership (docker, lxd, disk)
- Kernel CVE suggestions (DirtyPipe, Dirty COW, etc.)
- Credential harvesting: /etc/shadow, SSH keys, cloud creds (.aws, .azure),
  browser stores, git credentials, bash history
- LOtL (Living-off-the-Land) binary inventory across 7 categories
- Lateral movement guide: PsExec, WMIExec, Evil-WinRM, CrackMapExec,
  Pass-the-Hash, Pass-the-Ticket, DCOM, RDP hijack
- Pivot/tunnel methods: SSH (local/remote/dynamic), Chisel, Ligolo-ng,
  socat, ptunnel (ICMP), dnscat2 (DNS), Metasploit route + SOCKS

### Network Traffic Analysis
- LLMNR / NBT-NS / mDNS poisoning surface detection
- Cleartext credential sniffing (HTTP, FTP, Telnet, SMTP, POP3)
- ARP poisoning / spoofing detection (duplicate MAC entries, gratuitous ARP)
- IPv6 RA spoofing check, rogue DHCP detection, SMB relay surface
- Responder + mitm6 attack workflow auto-generated in output

### AI Integration (Anthropic Claude)
- Analyse findings with risk context and exploitation potential
- Generate professional executive summary (saves to `reports/`)
- Map findings to MITRE ATT&CK techniques with summary
- Identify most likely adversary kill-chain
- Create prioritised remediation roadmap (saves to `reports/`)
- Multi-turn chat interface about your scan results

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| Python files | 38 |
| Plugin modules | 22 |
| Unit tests | 62 (all passing) |
| Dashboard HTML pages | 4 |
| CVE rules | 300+ |
| External Python deps | **0** |
| Lines of code | ~8,000 |
| Supported Python | 3.8, 3.9, 3.10, 3.11, 3.12 |

---

## 🏗 Architecture

```
PhantomX/
├── main.py              CLI + interactive wizard (asks target when missing)
├── tui.py               Curses 3-panel TUI  (target wizard on startup)
├── gui.py               Local HTTP server + SPA Web GUI (startup dialog)
├── autorun.sh           Full automation pipeline + Slack/Discord/email alerts
├── setup_kali.sh        Kali Linux one-command installer (40+ tools)
│
├── core/
│   ├── engine.py        Dynamic plugin loader + session manager
│   ├── banner.py        ANSI output helpers + colour constants
│   ├── scoring.py       CVSS-like risk scoring engine (40+ rules)
│   └── ai_engine.py     Anthropic Claude API (8 methods)
│
├── plugins/             22 modules — all implement run(args, verbose) → dict
│
├── utils/
│   ├── shell.py         Safe subprocess wrapper with timeout + error handling
│   ├── report.py        HTML / JSON / TXT report generator
│   └── input_helper.py  Interactive 5-step target wizard + quick prompts
│
├── dashboard/
│   ├── index.html       Visual JSON report loader
│   ├── help.html        Full searchable command reference
│   ├── comparison.html  PhantomX vs Metasploit, BloodHound, Nmap, Burp...
│   └── architecture.html  System design diagram
│
├── tests/
│   ├── conftest.py      pytest fixtures
│   └── test_phantomx.py 62 unit tests (9 classes)
│
└── .github/
    └── workflows/ci.yml  7-job GitHub Actions pipeline
```

**Data flow:**
```
User input (target)
     ↓
Engine loads plugin dynamically
     ↓
Plugin calls system tools via shell.py
     ↓
Results dict returned + saved to session JSON
     ↓
Scoring engine applies 40+ rules → CVSS-like scores
     ↓
Report generator → HTML / JSON / TXT
     ↓
AI engine → executive summary / MITRE mapping / remediation
```

---

## 🔌 All 22 Modules

| # | Module | Needs Target | Description |
|---|--------|:---:|---------|
| 1 | `enum` | | OS, kernel, users, network interfaces, processes, mounts |
| 2 | `privesc` | | SUID/GTFOBins, sudo, cron, capabilities, docker groups, kernel CVEs |
| 3 | `persist` | | Crontab, .bashrc/.zshrc, SSH authorized_keys, systemd units |
| 4 | `loot` | | /etc/shadow, SSH keys, cloud creds, browser stores, history |
| 5 | `lateral` | | ARP cache, SSH discovery, NFS/SMB shares, trust relationships |
| 6 | `network` | ✓ | Port scan (128 threads), service banners, firewall, DNS, SNMP |
| 7 | `audit` | | Password policy, empty passwords, SSH config, AppArmor, logging |
| 8 | `container` | | Docker socket, K8s service account, cloud metadata, namespaces |
| 9 | `webapp` | ✓ | Security headers, CORS, cookies, SSL/TLS, info disclosure |
| 10 | `vulnscan` | ✓ | OWASP CWE Top 25 — SQLi, XSS, SSRF, XXE, SSTI, IDOR, RCE |
| 11 | `fuzzer` | ✓ | Boundary, CRLF, null byte, format string, HPP, encoding bypass |
| 12 | `cvecheck` | ✓ | 300+ CVE rules across Apache, PHP, MySQL, nginx, Docker, kernel |
| 13 | `recon` | ✓ | OSINT, subdomain enum, WAF/CDN detection, cert transparency |
| 14 | `services` | ✓ | SMB, SNMP, NetBIOS, SSH, LDAP, FTP full enumeration |
| 15 | `activedir` | ✓ | AD users, Kerberoast, AS-REP, delegation, AD CS, LAPS, trusts |
| 16 | `evasion` | ✓ | Firewall detection, fragmentation, source port bypass, pivot guide |
| 17 | `postexploit` | | Credential paths, LOtL binaries, lateral movement, PtH/PTT |
| 18 | `apitesting` | ✓ | OWASP API Top 10, JWT, GraphQL, mass assignment, BOLA |
| 19 | `passattack` | ✓ | Default creds (50+ vendors), lockout-aware spray, hash guide |
| 20 | `wireless` | | AP survey, WPA2/WPS, rogue AP, PMKID, probe requests |
| 21 | `dnsrecon` | ✓ | AXFR, PTR sweep, DNSSEC, open resolver, subdomain takeover |
| 22 | `traffic` | | LLMNR/NBT-NS check, ARP spoofing, cleartext credential sniff |

> ✓ = Module will **prompt for target IP** if `--target` is not supplied.

---

## 🔧 Installation on Kali Linux

### Prerequisites
- Kali Linux (recommended) or any Debian-based distro
- Python 3.8+
- `sudo` privileges

### One-command setup

```bash
# Extract ZIP (or clone from GitHub)
cd ~/Desktop
unzip PhantomX_Framework.zip
cd PhantomX

# Run automated installer — installs all 40+ dependencies
chmod +x setup_kali.sh
bash setup_kali.sh
```

**The setup script installs:**

| Category | Tools |
|----------|-------|
| Core | nmap, curl, wget, netcat, dig, whois, openssl, socat, tcpdump |
| SMB/AD | smbclient, ldap-utils, enum4linux, samba-common-bin, nbtscan |
| Impacket | python3-impacket, impacket-scripts |
| AD Tools | bloodhound, crackmapexec, evil-winrm, certipy-ad |
| Web | nikto, gobuster, sqlmap, hydra, whatweb |
| Network | fping, arp-scan, masscan, hping3, dnsrecon |
| Wireless | aircrack-ng, reaver, hcxdumptool, hcxtools, wireshark |
| Password | hashcat, john, wordlists (rockyou.txt) |
| LLMNR | responder, mitm6 |
| SNMP | snmp, snmp-mibs-downloader |

### After setup

```bash
source ~/.bashrc            # activate shell aliases

python3 main.py --version   # → PhantomX v6.0
phantomx --version          # global alias, works from anywhere
```

---

## ⚡ Quick Start

Run with **no arguments** — the 5-step wizard asks for your target:

```bash
python3 main.py
```

```
══════════════════════════════════════════════════════════
  PhantomX  —  Scan Configuration Wizard
══════════════════════════════════════════════════════════

  Step 1 / 5  —  Target
  Enter the IP or hostname you are authorised to scan.

  Target IP / hostname [127.0.0.1]: 10.10.10.5
  ✓ Target accepted: 10.10.10.5

  Step 2 / 5  —  Domain (optional)
  Domain name  e.g. corp.local: corp.local

  Step 3 / 5  —  Web Port
  Web port [80]: 443

  Step 4 / 5  —  Scan Profile
  [1] Quick Recon          Fast overview — OS + ports (2-3 min)
  [2] Web Application      Full web/API assessment (10-15 min)
  [3] Internal Network     Internal host + protocols (10 min)
  [4] Active Directory     AD enum + post-exploit (8 min)
  [5] Privilege Escalation Local priv-esc + cred harvest (5-8 min)
  [6] Full Assessment      All 22 modules (25-40 min)
  [7] Custom               Choose individual modules manually
  Profile number [1]: 6

  Step 5 / 5  —  Output Format
  [1] HTML  [2] JSON  [3] TXT  [4] None
  Output format [1]: 1

  ✓ Starting scan: 10.10.10.5 | 22 modules
```

---

## 🖥️ Three Interfaces

### 1. CLI (`main.py`)

Best for scripting, automation, and direct module access.

```bash
python3 main.py                              # full 5-step wizard
python3 main.py --interactive                # force wizard
python3 main.py privesc                      # single local module
python3 main.py vulnscan --target 10.10.10.5 # module with target
python3 main.py all      --target 10.10.10.5 # all 22 modules
```

### 2. Terminal UI (`tui.py`)

3-panel curses interface. **Opens with a target setup wizard.**

```bash
python3 tui.py
```

Key bindings:

| Key | Action |
|-----|--------|
| `↑` `↓` or `j` `k` | Navigate module list |
| `Enter` | Run selected module |
| `t` | Change target IP |
| `d` | Change domain |
| `s` | Show risk score overlay |
| `h` | Help overlay |
| `q` | Quit |

### 3. Web GUI (`gui.py`)

Browser-based interface with AI chat tab. **Startup dialog asks for target.**

```bash
python3 gui.py                    # → http://127.0.0.1:7331
python3 gui.py --port 8080        # custom port
python3 gui.py --no-browser       # don't auto-open browser
```

Features: live output streaming, real-time severity counters, AI Analyst tab
(chat, analyse, MITRE mapping, report, attack chain, remediation plan),
risk score dashboard, HTML report generation.

---

## 📟 All Commands

### Scan Modules

```bash
# ── Local modules (no target required) ───────────────────────────
python3 main.py enum
python3 main.py privesc
python3 main.py persist
python3 main.py loot
python3 main.py lateral          --arp-scan
python3 main.py audit
python3 main.py container
python3 main.py postexploit

# ── Remote modules (prompts for target if --target omitted) ───────
python3 main.py network          --target 10.10.10.5
python3 main.py webapp           --target 10.10.10.5 --port 443
python3 main.py vulnscan         --target 10.10.10.5
python3 main.py fuzzer           --target 10.10.10.5 --deep
python3 main.py cvecheck         --target 10.10.10.5
python3 main.py apitesting       --target 10.10.10.5 --jwt --graphql
python3 main.py passattack       --target 10.10.10.5 --spray --delay 2.0
python3 main.py services         --target 10.10.10.5
python3 main.py activedir        --target 10.10.10.5 --domain corp.local
python3 main.py evasion          --target 10.10.10.5
python3 main.py recon            --domain corp.local
python3 main.py dnsrecon         --domain corp.local
sudo python3 main.py traffic     --interface eth0 --duration 30
python3 main.py wireless         --interface wlan0

# ── Run all 22 modules ────────────────────────────────────────────
python3 main.py all
python3 main.py all --target 10.10.10.5 --output html
python3 main.py all --skip lateral wireless traffic
```

### AI Commands

```bash
# Run a scan first, then analyse:
python3 main.py privesc --output json

python3 main.py ai --subcommand analyse     # explain findings + risk
python3 main.py ai --subcommand chat        # interactive Q&A
python3 main.py ai --subcommand report      # executive summary
python3 main.py ai --subcommand mitre       # MITRE ATT&CK mapping
python3 main.py ai --subcommand chain       # adversary attack chain
python3 main.py ai --subcommand remediate   # prioritised fix roadmap
```

### Reports & Scoring

```bash
python3 main.py score                        # risk score table
python3 main.py score --top 20              # top 20 findings
python3 main.py score --export scored.json  # export JSON

python3 main.py report --format html        # dark-theme HTML report
python3 main.py report --format json        # machine-readable JSON
python3 main.py report --format txt         # plain text
python3 main.py report --format html --open # generate + open browser
```

### Automation

```bash
bash autorun.sh                                    # wizard asks target
bash autorun.sh 10.10.10.5 html                   # target + HTML report
bash autorun.sh 10.10.10.5 json lateral,wireless  # skip modules

# With alerting:
PHANTOMX_SLACK="https://hooks.slack.com/services/xxx"   bash autorun.sh
PHANTOMX_DISCORD="https://discord.com/api/webhooks/xxx" bash autorun.sh
PHANTOMX_EMAIL="you@example.com"                        bash autorun.sh

# Verbose + schedule cron:
PHANTOMX_VERBOSE=1 bash autorun.sh 10.10.10.5
bash autorun.sh --install-cron   # daily at 02:00
```

### Dashboard & Help

```bash
python3 main.py help                        # open help.html in browser
xdg-open dashboard/help.html               # full command reference
xdg-open dashboard/index.html              # visual JSON report loader
xdg-open dashboard/comparison.html         # vs Metasploit, BloodHound, Nmap
xdg-open dashboard/architecture.html       # system design diagram
```

### Global Flags

> Must come **before** the module name: `python3 main.py --verbose privesc` ✓

| Flag | Description |
|------|-------------|
| `--verbose / -v` | Detailed output |
| `--output / -o html\|json\|txt` | Auto-save report after scan |
| `--interactive / -i` | Force full 5-step wizard |
| `--no-color` | Disable ANSI colour output |
| `--target <ip>` | Target IP / hostname |
| `--domain <d>` | Domain name (AD / DNS modules) |
| `--port <n>` | Web port (default: 80) |
| `--version` | Print version and exit |

### Environment Variables

| Variable | Effect |
|----------|--------|
| `PHANTOMX_VERBOSE=1` | Verbose output in autorun.sh |
| `PHANTOMX_OPEN=1` | Auto-open HTML report after scan |
| `PHANTOMX_SLACK=<url>` | Slack webhook for critical alerts |
| `PHANTOMX_DISCORD=<url>` | Discord webhook for critical alerts |
| `PHANTOMX_EMAIL=<addr>` | Email critical findings |
| `NO_COLOR=1` | Disable all ANSI colours |

---

## ✦ AI Integration

PhantomX integrates with **Anthropic Claude** (`claude-sonnet-4-20250514`).

```bash
# Step 1: run any scan
python3 main.py privesc --output json
python3 main.py activedir --target 10.10.10.5 --domain corp.local

# Step 2: AI analysis
python3 main.py ai --subcommand analyse     # findings explained
python3 main.py ai --subcommand mitre       # ATT&CK techniques mapped
python3 main.py ai --subcommand chain       # attack kill-chain
python3 main.py ai --subcommand remediate   # fix roadmap
python3 main.py ai --subcommand report      # executive summary
python3 main.py ai --subcommand chat        # ask anything

# Or use the Web GUI for best AI experience:
python3 gui.py   # → http://127.0.0.1:7331 → "✦ AI" tab
```

| Sub-command | Output |
|-------------|--------|
| `analyse` | Risk analysis with exploitation context |
| `chat` | Multi-turn conversation about your findings |
| `report` | Professional executive summary saved to `reports/` |
| `mitre` | MITRE ATT&CK table + 2-sentence profile summary |
| `chain` | Step-by-step adversary kill-chain narrative |
| `remediate` | 24h / 2-week / 3-month fix roadmap saved to `reports/` |

---

## 🤖 Automation & Alerting

`autorun.sh` runs the complete pipeline unattended:

1. Validates target and configuration
2. Runs all 22 modules sequentially
3. Scores all findings
4. Generates HTML report
5. Sends Slack / Discord / email alert if critical findings detected
6. Writes timestamped log file

```bash
# Example with Discord alerting
PHANTOMX_DISCORD="https://discord.com/api/webhooks/YOUR/WEBHOOK"   bash autorun.sh 10.10.10.5 html

# Schedule to run daily at 02:00
bash autorun.sh --install-cron
```

---

## 📄 Reports & Dashboard

After any scan, generate reports:

```bash
python3 main.py report --format html --open
```

**Four dashboard HTML pages** (open in any browser, no server needed):

| Page | Purpose |
|------|---------|
| `dashboard/index.html` | Load any JSON report for visual analysis |
| `dashboard/help.html` | Complete searchable command reference |
| `dashboard/comparison.html` | PhantomX vs Metasploit, BloodHound, Nmap, Burp, Nessus |
| `dashboard/architecture.html` | System architecture diagram |

---

## 🧪 Testing

```bash
# Run all 62 tests
python3 -m unittest tests/test_phantomx.py

# Verbose output
python3 -m unittest tests/test_phantomx.py -v

# Specific class
python3 -m unittest tests.test_phantomx.TestPluginSmoke -v
python3 -m unittest tests.test_phantomx.TestRiskScorer  -v

# Quick syntax check all files
python3 -c "
import ast, pathlib
for f in pathlib.Path('.').rglob('*.py'):
    ast.parse(f.read_text())
print('All files: syntax OK')
"
```

**Test suite (62 tests, 9 classes):**

| Class | Count | What it covers |
|-------|-------|----------------|
| `TestSyntax` | 4 | All .py files parse, plugin count, required files exist |
| `TestShellUtils` | 11 | run_cmd success/fail/timeout, cmd_exists, file read, permissions |
| `TestPluginEngine` | 9 | Plugin loading, session fields, count_findings, MODULE_MAP |
| `TestRiskScorer` | 6 | Score findings, overall risk, export JSON, required fields |
| `TestReportGenerator` | 5 | HTML/JSON/TXT output, flatten findings |
| `TestCLIParsing` | 7 | All 26+ subcommands, global flags correctly positioned |
| `TestPluginSmoke` | 13 | Each plugin returns dict without crashing (all calls mocked) |
| `TestBanner` | 4 | print_status, print_finding, print_table don't raise |
| `TestIntegration` | 3 | Full session roundtrip, scoring pipeline |

**GitHub Actions CI/CD** (runs on every push):

| Job | Checks |
|-----|--------|
| `syntax-check` | All .py parse, plugin count ≥15, required files present |
| `unit-tests` | 62 tests on Python 3.9 / 3.10 / 3.11 / 3.12 |
| `security-lint` | Bandit scan, no hardcoded secrets |
| `plugin-contracts` | All plugins implement `run()` → dict |
| `dashboard-check` | HTML files well-formed |
| `docs-check` | README exists, plugins have docstrings |
| `build-summary` | Project statistics |

---

## 🐛 Common Errors & Fixes

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError: No module named 'core'` | Run from the PhantomX directory: `cd ~/Desktop/PhantomX` |
| `Permission denied` on traffic module | Use sudo: `sudo python3 main.py traffic --interface eth0` |
| `smbclient: command not found` | `sudo apt install smbclient` |
| `ldapsearch: command not found` | `sudo apt install ldap-utils` |
| `snmpwalk: command not found` | `sudo apt install snmp snmp-mibs-downloader` |
| `impacket not found` | `sudo apt install python3-impacket impacket-scripts` |
| `airmon-ng not found` | `sudo apt install aircrack-ng` |
| `rockyou.txt not found` | `sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz` |
| `curses error` in TUI | Resize terminal to at least **80×24** characters |
| `Port 7331 already in use` | `python3 gui.py --port 8080` |
| `AI API error` | Check internet: `curl -I https://api.anthropic.com` |
| Tests failing after edits | Check syntax first: `python3 -c "import ast,pathlib; [ast.parse(f.read_text()) for f in pathlib.Path('.').rglob('*.py')]"` |

---

## 📁 Project Structure

```
PhantomX/
├── main.py                  CLI entry point + interactive wizard
├── tui.py                   Curses terminal UI
├── gui.py                   Local web GUI (HTTP server + SPA)
├── autorun.sh               Automation pipeline
├── setup_kali.sh            Kali deployment installer
├── requirements.txt         Empty — zero external Python deps
├── pytest.ini               Test configuration
├── .gitignore               Excludes scan results and secrets
├── LICENSE                  MIT license
│
├── core/
│   ├── __init__.py
│   ├── engine.py            Plugin loader + session manager
│   ├── banner.py            ANSI output + colour constants
│   ├── scoring.py           CVSS-like risk scoring (40+ rules)
│   └── ai_engine.py         Anthropic API (8 methods)
│
├── plugins/                 22 assessment modules (each: run(args, verbose) → dict)
│   ├── enumeration.py       privesc.py    persistence.py   loot.py
│   ├── lateral.py           network.py    audit.py         container.py
│   ├── webapp.py            vulnscan.py   fuzzer.py        cvecheck.py
│   ├── recon.py             services.py   activedir.py     evasion.py
│   ├── postexploit.py       apitesting.py passattack.py    wireless.py
│   ├── dnsrecon.py          traffic.py    ai_analyst.py
│   └── __init__.py
│
├── utils/
│   ├── __init__.py
│   ├── shell.py             Safe subprocess wrapper
│   ├── report.py            Report generator (HTML/JSON/TXT)
│   └── input_helper.py      Interactive 5-step wizard + quick prompts
│
├── dashboard/
│   ├── index.html           Visual JSON report loader
│   ├── help.html            Searchable command reference
│   ├── comparison.html      vs industry tools
│   └── architecture.html    System diagram
│
├── reports/                 Generated reports (git-ignored)
│
├── tests/
│   ├── conftest.py          pytest fixtures and shared helpers
│   └── test_phantomx.py     62 unit tests (9 test classes)
│
└── .github/
    └── workflows/
        └── ci.yml           7-job GitHub Actions pipeline
```

---

## ⚠️ Legal Disclaimer

This tool is provided for **authorized security assessment and educational purposes only.**

- Use only on systems you **own** or have **explicit written permission** to test
- Written authorization should be obtained before any engagement
- Unauthorized use is a criminal offense under:
  - Computer Fraud and Abuse Act (CFAA) — USA
  - Computer Misuse Act — UK
  - Information Technology Act — India
  - And equivalent laws in all other jurisdictions
- The authors accept **no liability** for unauthorized or illegal use

