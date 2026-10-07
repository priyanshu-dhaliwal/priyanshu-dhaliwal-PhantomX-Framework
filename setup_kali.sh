#!/usr/bin/env bash
# PhantomX v6.0 — Kali Linux Full Deployment
# Usage: bash setup_kali.sh
# [!] For Authorized Penetration Testing Only
set -euo pipefail

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; MAG='\033[95m'; BLD='\033[1m'; RST='\033[0m'
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
info() { echo -e "  ${CYN}[*]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
sep()  { echo -e "\n  ${MAG}$(printf '%.0s─' {1..62})${RST}"; }
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${RED}${BLD}"
echo "  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗  ██╗"
echo "  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║╚██╗██╔╝"
echo "  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║ ╚███╔╝ "
echo "  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║ ██╔██╗ "
echo "  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██╔╝ ██╗"
echo "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝"
echo -e "${RST}${CYN}  Kali Linux Deployment  v6.0${RST}"
echo -e "  ${YLW}[!] For Authorized Penetration Testing Only${RST}"

sep; info "Step 1/9 — Checking environment..."
grep -qi "kali" /etc/os-release 2>/dev/null && ok "Kali Linux detected" || warn "Non-Kali OS — some packages may differ"
python3 --version &>/dev/null || { echo "python3 not found"; exit 1; }
ok "Python $(python3 --version 2>&1 | grep -oP '\d+\.\d+')"

sep; info "Step 2/9 — Updating package lists..."
sudo apt-get update -qq 2>/dev/null && ok "Package lists updated" || warn "apt update failed — continuing"

sep; info "Step 3/9 — Core tools..."
for pkg in nmap curl wget netcat-openbsd dnsutils whois net-tools iproute2 tcpdump openssl socat python3-full git; do
    dpkg -l "$pkg" &>/dev/null && ok "$pkg — already installed" || {
        sudo apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg installed" || warn "$pkg skipped"; }
done

sep; info "Step 4/9 — Penetration testing tools..."
for pkg in smbclient ldap-utils samba-common-bin nbtscan enum4linux snmp snmp-mibs-downloader ftp sshpass nikto gobuster whatweb sqlmap hydra fping arp-scan masscan hping3 dnsrecon; do
    dpkg -l "$pkg" &>/dev/null && ok "$pkg — already installed" || {
        sudo apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg installed" || warn "$pkg skipped"; }
done

sep; info "Step 5/9 — Active Directory tools..."
for pkg in python3-impacket impacket-scripts bloodhound crackmapexec evil-winrm certipy-ad; do
    dpkg -l "$pkg" &>/dev/null && ok "$pkg — already installed" || {
        sudo apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg installed" || warn "$pkg skipped"; }
done

sep; info "Step 6/9 — Wireless tools..."
for pkg in aircrack-ng reaver hcxdumptool hcxtools wireshark tshark kismet; do
    dpkg -l "$pkg" &>/dev/null && ok "$pkg — already installed" || {
        sudo apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg installed" || warn "$pkg skipped"; }
done

sep; info "Step 7/9 — Password cracking tools..."
for pkg in hashcat john wordlists; do
    dpkg -l "$pkg" &>/dev/null && ok "$pkg — already installed" || {
        sudo apt-get install -y "$pkg" -qq 2>/dev/null && ok "$pkg installed" || warn "$pkg skipped"; }
done
[ -f /usr/share/wordlists/rockyou.txt.gz ] && ! [ -f /usr/share/wordlists/rockyou.txt ] && \
    sudo gunzip /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt decompressed"
[ -f /usr/share/wordlists/rockyou.txt ] && ok "rockyou.txt — available" || warn "rockyou.txt not found"

sep; info "Step 8/9 — LLMNR / NBT-NS tools..."
dpkg -l responder &>/dev/null && ok "responder — already installed" || {
    sudo apt-get install -y responder -qq 2>/dev/null && ok "responder installed" || warn "responder skipped"; }
command -v mitm6 &>/dev/null && ok "mitm6 — available" || {
    pip3 install mitm6 --break-system-packages -q 2>/dev/null && ok "mitm6 installed" || warn "mitm6 skipped"; }

sep; info "Step 9/9 — Configuring PhantomX..."
cd "$DIR"
chmod +x main.py tui.py gui.py autorun.sh 2>/dev/null; ok "Scripts executable"
mkdir -p reports; ok "Reports directory ready"
sudo ln -sf "$DIR/main.py" /usr/local/bin/phantomx 2>/dev/null && ok "Global: phantomx command" || warn "Could not create global symlink"
for RC in ~/.bashrc ~/.zshrc; do
    [ -f "$RC" ] || continue
    grep -qF "phantomx-tui" "$RC" || {
        echo "alias phantomx='python3 $DIR/main.py'"       >> "$RC"
        echo "alias phantomx-tui='python3 $DIR/tui.py'"   >> "$RC"
        echo "alias phantomx-gui='python3 $DIR/gui.py'"   >> "$RC"
        ok "Aliases added to $RC"; }
done

sep
python3 "$DIR/main.py" --version
echo ""
echo -e "  ${GRN}${BLD}PhantomX deployment complete!${RST}"
echo ""
echo -e "  ${CYN}Start with:${RST}"
echo -e "  ${YLW}  python3 main.py${RST}      # Wizard — asks for target"
echo -e "  ${YLW}  python3 tui.py${RST}       # Terminal UI"
echo -e "  ${YLW}  python3 gui.py${RST}       # Web GUI → http://127.0.0.1:7331"
echo -e "  ${YLW}  python3 main.py help${RST} # Full command reference in browser"
echo ""
echo -e "  ${MAG}Run: source ~/.bashrc  then use: phantomx${RST}"
echo ""
echo -e "  ${RED}[!] Only scan systems you own or have written permission to test.${RST}"
echo ""
