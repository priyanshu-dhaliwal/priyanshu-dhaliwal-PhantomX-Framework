# GitHub Deployment Guide — PhantomX

Complete step-by-step guide to push PhantomX to GitHub, handle every
common error, and set up CI/CD so tests run automatically on every push.

---

## Part 1 — First-Time GitHub Setup on Kali Linux

### Step 1 — Install Git

```bash
sudo apt install git -y
git --version
# git version 2.x.x
```

### Step 2 — Configure Git identity

```bash
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"
git config --global core.editor nano
git config --global init.defaultBranch main

# Verify
git config --list
```

### Step 3 — Create SSH key for GitHub (recommended over HTTPS)

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "you@example.com"
# Press Enter 3 times to accept defaults and no passphrase

# Show your public key — copy this entire output
cat ~/.ssh/id_ed25519.pub
```

### Step 4 — Add SSH key to GitHub

1. Go to **https://github.com/settings/keys**
2. Click **"New SSH key"**
3. Title: `Kali Linux`
4. Paste your public key
5. Click **"Add SSH key"**

### Step 5 — Test the connection

```bash
ssh -T git@github.com
# Hi YOUR_USERNAME! You've successfully authenticated...
```

---

## Part 2 — Create the GitHub Repository

### Step 1 — Create repo on GitHub

1. Go to **https://github.com/new**
2. Repository name: `PhantomX`
3. Description: `Advanced Security Assessment Framework — 22 modules, AI integration, Kali Linux`
4. Set to **Public** or **Private**
5. **Do NOT** check "Add README" (we already have one)
6. **Do NOT** check "Add .gitignore" (we already have one)
7. Click **"Create repository"**

### Step 2 — Add .gitignore

```bash
cd ~/Desktop/PhantomX
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg
*.egg-info/
dist/
build/
.eggs/

# PhantomX generated files
reports/*.html
reports/*.json
reports/*.txt
reports/*.md
reports/.last_session.json

# Sensitive files — NEVER commit these
*.key
*.pem
*.p12
id_rsa
id_ed25519
*.keystore
secrets.json
.env
config.local.*

# Tools output
/tmp/phantomx*
*.pcap
*.pcapng
*.hccapx
*.hc22000
*.hashes

# Test artifacts
.coverage
coverage.xml
.pytest_cache/
htmlcov/

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo
EOF
```

### Step 3 — Initialise local Git repo and push

```bash
cd ~/Desktop/PhantomX

# Initialise
git init
git branch -M main

# Add remote (SSH — replace YOUR_USERNAME)
git remote add origin git@github.com:YOUR_USERNAME/PhantomX.git

# Stage all files
git add .

# Check what will be committed
git status

# First commit
git commit -m "Initial commit — PhantomX v6.0

- 22 security assessment modules
- CLI wizard, TUI, and Web GUI interfaces
- AI integration via Anthropic Claude API
- Interactive target prompting across all interfaces
- CVSS-like risk scoring engine
- HTML/JSON/TXT report generation
- 62 unit tests with GitHub Actions CI/CD
- Zero external Python dependencies"

# Push to GitHub
git push -u origin main
```

---

## Part 3 — Every Common Error and Fix

### ❌ Error: `remote: Repository not found`

```
ERROR: remote: Repository not found.
fatal: repository 'https://github.com/...' not found
```

**Fix:**
```bash
# Check your remote URL
git remote -v

# Remove and re-add with correct username
git remote remove origin
git remote add origin git@github.com:YOUR_USERNAME/PhantomX.git

# Verify SSH connection
ssh -T git@github.com
```

---

### ❌ Error: `Permission denied (publickey)`

```
git@github.com: Permission denied (publickey).
fatal: Could not read from remote repository.
```

**Fix:**
```bash
# Check your SSH key exists
ls ~/.ssh/
# Should show: id_ed25519  id_ed25519.pub

# If missing, create new key
ssh-keygen -t ed25519 -C "you@example.com"

# Show public key and add to GitHub settings
cat ~/.ssh/id_ed25519.pub
# → github.com/settings/keys → New SSH key → paste

# Test connection
ssh -T git@github.com
```

---

### ❌ Error: `src refspec main does not match any`

```
error: src refspec main does not match any
error: failed to push some refs
```

**Fix:**
```bash
# You have no commits yet — add files and commit first
git add .
git commit -m "Initial commit"
git push -u origin main
```

---

### ❌ Error: `Updates were rejected (non-fast-forward)`

```
 ! [rejected]  main -> main (non-fast-forward)
error: failed to push some refs
hint: Updates were rejected because the tip of your current branch is behind
```

**Fix:**
```bash
# If you just created the repo with a README on GitHub:
git pull origin main --allow-unrelated-histories
# Resolve any merge conflicts, then:
git add .
git commit -m "Merge remote"
git push origin main
```

---

### ❌ Error: `Large file exceeds GitHub limit`

```
error: File some_file.bin is 102.00 MB; this exceeds GitHub's file size limit of 100.00 MB
```

**Fix:**
```bash
# Remove the large file from tracking
git rm --cached large_file.bin
echo "large_file.bin" >> .gitignore
git add .gitignore
git commit -m "Remove large file from tracking"
git push origin main
```

---

### ❌ Error: `SSL certificate problem`

```
SSL certificate problem: certificate has expired
```

**Fix:**
```bash
# Update CA certificates
sudo apt update && sudo apt install ca-certificates -y
sudo update-ca-certificates

# Or temporarily disable (not recommended for production)
git config --global http.sslVerify false
```

---

### ❌ Error: `CRLF / LF line ending warnings`

```
warning: LF will be replaced by CRLF
```

**Fix:**
```bash
# On Linux, set to use LF only
git config --global core.autocrlf input
```

---

### ❌ Error: `fatal: not a git repository`

```
fatal: not a git repository (or any of the parent directories): .git
```

**Fix:**
```bash
# Make sure you are in the PhantomX directory
cd ~/Desktop/PhantomX
ls .git   # should exist

# If not, initialise
git init
```

---

### ❌ Error: `nothing to commit, working tree clean`

This is not actually an error — it means all files are already tracked.

```bash
# Check what Git sees
git status
git log --oneline -5
```

---

### ❌ Error: `Commit failed — pre-commit hook`

```
pre-commit hook failed (add --no-verify to bypass)
```

**Fix:**
```bash
# Bypass the hook (only if you know what you are doing)
git commit --no-verify -m "your message"

# Or fix the hook issue
cat .git/hooks/pre-commit
```

---

### ❌ Error: GitHub Actions CI failing

```
Run python3 -m unittest tests/test_phantomx.py
Error: Process completed with exit code 1
```

**Fix — check the Actions log:**
```bash
# Reproduce locally first
python3 -m unittest tests/test_phantomx.py -v 2>&1 | tail -20

# Common causes:
# 1. Import error in a plugin
python3 -c "import plugins.privesc"

# 2. Missing __init__.py
touch plugins/__init__.py
touch core/__init__.py
touch utils/__init__.py
touch tests/__init__.py

# 3. Test uses real filesystem path
# Check test for hardcoded /home/user paths
```

---

## Part 4 — Day-to-Day Git Workflow

### Make changes and push

```bash
cd ~/Desktop/PhantomX

# See what changed
git status
git diff

# Stage specific files
git add plugins/new_module.py
git add core/engine.py

# Or stage everything
git add .

# Commit with a descriptive message
git commit -m "Add new_module plugin: <description>

- What it does
- Which CVEs or techniques it covers"

# Push
git push origin main
```

### Create a feature branch (recommended)

```bash
# Create and switch to new branch
git checkout -b feature/dns-hijack-detection

# Make your changes, then commit
git add .
git commit -m "Add DNS hijack detection to dnsrecon module"

# Push branch to GitHub
git push origin feature/dns-hijack-detection

# On GitHub: open a Pull Request from this branch to main
```

### Update local copy after remote changes

```bash
git pull origin main
```

### View history

```bash
git log --oneline -10
git log --oneline --graph --all
```

### Undo last commit (before pushing)

```bash
git reset --soft HEAD~1    # undo commit, keep changes staged
git reset --hard HEAD~1    # undo commit, discard changes (careful!)
```

### Tag a release

```bash
git tag -a v6.0 -m "PhantomX v6.0 — 22 modules, AI integration"
git push origin v6.0
```

---

## Part 5 — GitHub Actions CI/CD

The CI/CD pipeline is already configured at `.github/workflows/ci.yml`.
It runs automatically on every push and pull request.

**7 Jobs:**

| Job | What it checks |
|---|---|
| `syntax-check` | All .py files parse, plugin count ≥ 15, required files exist |
| `unit-tests` | 62 tests on Python 3.9, 3.10, 3.11, 3.12 |
| `security-lint` | Bandit scan, no hardcoded secrets |
| `plugin-contracts` | All plugins implement `run()` → dict |
| `dashboard-check` | HTML files are well-formed |
| `docs-check` | README exists, plugins have docstrings |
| `build-summary` | Prints project statistics |

**View CI results:** `https://github.com/YOUR_USERNAME/PhantomX/actions`

**Force a CI run:**
```bash
git commit --allow-empty -m "CI: trigger test run"
git push origin main
```

**Add a CI badge to README:**

Replace `YOUR_USERNAME` in this line (already in README.md):
```
[![CI](https://github.com/YOUR_USERNAME/PhantomX/workflows/PhantomX%20CI/badge.svg)](https://github.com/YOUR_USERNAME/PhantomX/actions)
```

---

## Part 6 — Protecting Sensitive Files

**Never commit:**
- Hash files (`*.hashes`, `*.txt` with passwords)
- Capture files (`*.pcap`, `*.pcapng`)
- Private keys (`id_rsa`, `*.pem`, `*.key`)
- Scan reports (`reports/*.html`, `reports/*.json`)
- Session data (`reports/.last_session.json`)

All of these are already in `.gitignore`.

**Check before pushing:**
```bash
# Make sure no sensitive files are staged
git status
git diff --cached --name-only

# If you accidentally staged something sensitive
git reset HEAD sensitive_file.txt
```

**If you accidentally pushed a secret:**
```bash
# Immediately rotate the credential (change the password/key)
# Then remove from Git history:
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/secret_file" \
  --prune-empty --tag-name-filter cat -- --all
git push origin --force --all
```

---

## Quick Reference

```bash
# First-time setup
git init && git remote add origin git@github.com:USER/PhantomX.git
git add . && git commit -m "Initial commit" && git push -u origin main

# Daily workflow
git add . && git commit -m "description" && git push

# Check status
git status && git log --oneline -5

# Create release
git tag -a v6.0 -m "Release v6.0" && git push origin v6.0

# Fix pushed mistake
git revert HEAD && git push

# View CI
open https://github.com/YOUR_USERNAME/PhantomX/actions
```
