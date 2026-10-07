#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║       PhantomX — Automated Red Team Orchestration Script            ║
# ║       Full pipeline: scan → analyze → report → alert                ║
# ║       [For Authorized Penetration Testing Only]                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PX="${SCRIPT_DIR}/main.py"
REPORT_DIR="${SCRIPT_DIR}/reports"
LOG_FILE="${REPORT_DIR}/autorun_$(date +%Y%m%d_%H%M%S).log"
TARGET="${1:-127.0.0.1}"           # Pass target as $1, default localhost
OUTPUT_FORMAT="${2:-html}"         # html | json | txt
SKIP_MODULES="${3:-}"              # Comma-separated modules to skip
VERBOSE="${PHANTOMX_VERBOSE:-0}"   # Set PHANTOMX_VERBOSE=1 to enable

# Alert settings (optional — set env vars to enable)
SLACK_WEBHOOK="${PHANTOMX_SLACK:-}"
DISCORD_WEBHOOK="${PHANTOMX_DISCORD:-}"
EMAIL_TO="${PHANTOMX_EMAIL:-}"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; MAG='\033[95m'; DIM='\033[2m'; RST='\033[0m'; BLD='\033[1m'

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "  ${CYN}[*]${RST} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "  ${GRN}[+]${RST} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "  ${YLW}[!]${RST} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "  ${RED}[-]${RST} $*" | tee -a "$LOG_FILE"; }
sep()  { echo -e "\n  ${MAG}$(printf '─%.0s' {1..62})${RST}\n" | tee -a "$LOG_FILE"; }

run_module() {
    local name="$1"; shift
    local args=("$@")
    sep
    log "Running module: ${BLD}${name^^}${RST}"

    if [[ "${VERBOSE}" == "1" ]]; then
        python3 "$PX" "$name" "${args[@]}" --verbose 2>&1 | tee -a "$LOG_FILE" || true
    else
        python3 "$PX" "$name" "${args[@]}" 2>&1 | tee -a "$LOG_FILE" || true
    fi
    ok "Module ${name^^} complete."
}

is_skipped() {
    local mod="$1"
    [[ ",$SKIP_MODULES," == *",$mod,"* ]]
}

send_slack_alert() {
    local msg="$1"
    [[ -z "$SLACK_WEBHOOK" ]] && return 0
    curl -sf -X POST "$SLACK_WEBHOOK" \
        -H 'Content-type: application/json' \
        --data "{\"text\": \"🔴 PhantomX Alert — $msg\"}" >/dev/null 2>&1 || true
    log "Slack alert sent."
}

send_discord_alert() {
    local msg="$1"
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0
    curl -sf -X POST "$DISCORD_WEBHOOK" \
        -H 'Content-Type: application/json' \
        --data "{\"content\": \"🔴 **PhantomX Alert** — $msg\"}" >/dev/null 2>&1 || true
    log "Discord alert sent."
}

send_email_alert() {
    local subject="$1" body="$2"
    [[ -z "$EMAIL_TO" ]] && return 0
    command -v mail >/dev/null 2>&1 || return 0
    echo "$body" | mail -s "$subject" "$EMAIL_TO" 2>/dev/null || true
    log "Email alert sent to $EMAIL_TO."
}

notify_all() {
    local msg="$1"
    send_slack_alert "$msg"
    send_discord_alert "$msg"
    send_email_alert "PhantomX — $msg" "$msg\nHost: $(hostname)\nTime: $(date)"
}

check_critical_findings() {
    # Parse last JSON session for critical findings and trigger alerts
    local session="${REPORT_DIR}/.last_session.json"
    [[ ! -f "$session" ]] && return 0

    local host; host="$(python3 -c "import json; d=json.load(open('$session')); print(d.get('hostname','?'))"  2>/dev/null)"
    local user; user="$(python3 -c "import json; d=json.load(open('$session')); print(d.get('user','?'))"     2>/dev/null)"

    # Check privesc results
    local suid_count; suid_count=$(python3 -c "
import json, sys
try:
    d = json.load(open('$session'))
    r = d.get('results',{}).get('privesc',{})
    print(len(r.get('suid_interesting',[])) + len(r.get('sudo_findings',[])) + len(r.get('dangerous_groups',[])))
except: print(0)
" 2>/dev/null)

    local shadow; shadow=$(python3 -c "
import json, sys
try:
    d = json.load(open('$session'))
    print(d.get('results',{}).get('loot',{}).get('shadow',{}).get('readable', False))
except: print(False)
" 2>/dev/null)

    local cloud_creds; cloud_creds=$(python3 -c "
import json, sys
try:
    d = json.load(open('$session'))
    print(len(d.get('results',{}).get('loot',{}).get('cloud_creds',[])))
except: print(0)
" 2>/dev/null)

    local docker_socket; docker_socket=$(python3 -c "
import json, sys
try:
    d = json.load(open('$session'))
    s = d.get('results',{}).get('container',{}).get('docker_socket',[])
    print(any(w for _,_,w in (s if s else [])))
except: print(False)
" 2>/dev/null)

    # Alert on critical findings
    if [[ "$shadow" == "True" ]]; then
        warn "/etc/shadow is READABLE on ${host} (${user})"
        notify_all "/etc/shadow readable on host:${host} user:${user}"
    fi

    if [[ "${suid_count:-0}" -gt 3 ]]; then
        warn "${suid_count} privesc vectors found on ${host}"
        notify_all "${suid_count} privilege escalation vectors on host:${host}"
    fi

    if [[ "${cloud_creds:-0}" -gt 0 ]]; then
        warn "Cloud credentials found on ${host}"
        notify_all "${cloud_creds} cloud credential file(s) on host:${host}"
    fi

    if [[ "$docker_socket" == "True" ]]; then
        err "WRITABLE Docker socket on ${host} — container escape possible!"
        notify_all "Writable Docker socket on host:${host} — CRITICAL escape vector"
    fi
}

print_header() {
    echo -e "${RED}${BLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║     PhantomX Automated Red Team Orchestrator                ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RST}"
    echo -e "  ${DIM}Target        : ${RST}${CYN}${TARGET}${RST}"
    echo -e "  ${DIM}Report Format : ${RST}${OUTPUT_FORMAT}"
    echo -e "  ${DIM}Skip Modules  : ${RST}${SKIP_MODULES:-none}"
    echo -e "  ${DIM}Log File      : ${RST}${LOG_FILE}"
    echo -e "  ${DIM}Timestamp     : ${RST}$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  ${DIM}Operator      : ${RST}$(whoami)@$(hostname)"
    echo -e "\n  ${YLW}[!] FOR AUTHORIZED PENETRATION TESTING ONLY${RST}\n"
}

print_final_summary() {
    local elapsed="$1"
    local report="$2"
    sep
    echo -e "  ${GRN}${BLD}SCAN COMPLETE${RST}"
    echo -e "  ${DIM}Duration     :${RST} ${elapsed}s"
    echo -e "  ${DIM}Report saved :${RST} ${CYN}${report}${RST}"
    echo -e "  ${DIM}Log file     :${RST} ${LOG_FILE}"
    echo -e "  ${DIM}Session JSON :${RST} ${REPORT_DIR}/.last_session.json"
    echo ""
    # Count total findings from log
    local findings; findings=$(grep -c '\[+\]\|\[!!!\]\|CRITICAL\|HIGH\|WRITABLE\|READABLE' "$LOG_FILE" 2>/dev/null || echo 0)
    echo -e "  ${YLW}Total flagged lines in log: ${findings}${RST}"
    sep
}

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    log "Checking dependencies…"
    python3 --version >/dev/null 2>&1 || { err "python3 not found!"; exit 1; }
    [[ -f "$PX" ]] || { err "main.py not found at $PX"; exit 1; }

    # Recommend optional tools
    for tool in fping snmpwalk smbclient showmount getcap nmap curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            warn "Optional tool not found: ${tool} (some checks may be limited)"
        fi
    done
    ok "Dependency check done."
}

# ── Main Orchestration ────────────────────────────────────────────────────────
main() {
    mkdir -p "$REPORT_DIR"
    touch "$LOG_FILE"

    print_header | tee -a "$LOG_FILE"
    START_TIME=$(date +%s)

    check_deps

    # Phase 1: Enumeration
    is_skipped "enum"      || run_module "enum"

    # Phase 2: Security Audit
    is_skipped "audit"     || run_module "audit"

    # Phase 3: Privilege Escalation Discovery
    is_skipped "privesc"   || run_module "privesc"

    # Phase 4: Persistence Analysis
    is_skipped "persist"   || run_module "persist"

    # Phase 5: Container / Cloud Escape
    is_skipped "container" || run_module "container"

    # Phase 6: Credential Harvesting
    is_skipped "loot"      || run_module "loot"

    # Phase 7: Network Recon (with target)
    is_skipped "network"   || run_module "network" --target "$TARGET"

    # Phase 8: Lateral Movement Prep
    is_skipped "lateral"   || run_module "lateral"

    # Phase 9: OWASP CWE Top 25 Vulnerability Scan
    is_skipped "vulnscan"  || run_module "vulnscan" --target "$TARGET"

    # Phase 10: CVE Banner Matching
    is_skipped "cvecheck"  || run_module "cvecheck" --target "$TARGET"

    # Phase 11: Parameter & Header Fuzzer
    is_skipped "fuzzer"    || run_module "fuzzer"   --target "$TARGET"

    sep
    log "Generating ${OUTPUT_FORMAT^^} report…"
    REPORT=$(python3 "$PX" report --format "$OUTPUT_FORMAT" 2>&1 | grep -oE '/[^ ]+\.(html|json|txt)' | tail -1)
    ok "Report: ${REPORT}"

    # Phase 9: Critical finding alerts
    sep
    log "Analysing critical findings for alerts…"
    check_critical_findings

    END_TIME=$(date +%s)
    ELAPSED=$(( END_TIME - START_TIME ))
    print_final_summary "$ELAPSED" "${REPORT:-reports/}" | tee -a "$LOG_FILE"

    # Open report if on desktop
    [[ -n "${REPORT:-}" && "${PHANTOMX_OPEN:-0}" == "1" ]] && \
        xdg-open "$REPORT" 2>/dev/null || true
}

# ── Scheduling Helper (run as cron) ──────────────────────────────────────────
install_cron() {
    echo ""
    warn "Installing PhantomX as a daily cron job (for continuous assessment)…"
    CRON_CMD="0 2 * * * cd ${SCRIPT_DIR} && bash autorun.sh ${TARGET} json >> ${REPORT_DIR}/cron.log 2>&1"
    ( crontab -l 2>/dev/null | grep -v "autorun.sh" ; echo "$CRON_CMD" ) | crontab -
    ok "Cron job installed: runs daily at 02:00"
    crontab -l | grep "autorun.sh"
}

# ── Entry point ───────────────────────────────────────────────────────────────
case "${1:-run}" in
    --install-cron) install_cron ;;
    --help|-h)
        echo ""
        echo "  Usage: bash autorun.sh [target_ip] [format] [skip_modules]"
        echo ""
        echo "  Arguments:"
        echo "    target_ip    IP to scan with network module (default: 127.0.0.1)"
        echo "    format       Report format: html | json | txt   (default: html)"
        echo "    skip_modules Comma-separated modules to skip    (default: none)"
        echo ""
        echo "  Environment variables:"
        echo "    PHANTOMX_VERBOSE=1          Enable verbose output"
        echo "    PHANTOMX_OPEN=1             Auto-open report after scan"
        echo "    PHANTOMX_SLACK=<webhook>    Send critical findings to Slack"
        echo "    PHANTOMX_DISCORD=<webhook>  Send critical findings to Discord"
        echo "    PHANTOMX_EMAIL=<addr>       Email critical findings"
        echo ""
        echo "  Examples:"
        echo "    bash autorun.sh                          # Full local scan, HTML report"
        echo "    bash autorun.sh 10.10.10.5 json          # Scan target, JSON report"
        echo "    bash autorun.sh 10.10.10.5 html lateral  # Skip lateral module"
        echo "    PHANTOMX_VERBOSE=1 bash autorun.sh       # Verbose full scan"
        echo "    bash autorun.sh --install-cron           # Schedule daily cron"
        echo ""
        ;;
    *) main ;;
esac
