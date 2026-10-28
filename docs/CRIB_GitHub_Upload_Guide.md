# CRIB (Cyber Range in a Box)
## Comprehensive Git Inspection, Branch Synchronization & GitHub Upload Guide

**Target Repository:** `https://github.com/kimayaateli/CRIB`  
**Target Feature Branch:** `feature/employee-manager-dashboard`  
**Local Project Directory:** `/Users/anitateli/Desktop/CRIB`  
**Lead Author / Repository Owner:** Kimaya Teli (kimaya.teli@gmail.com)  
**Date of Verification:** October 29, 2026  
**Document Classification:** Operational Deployment & Version Control Runbook  

---

## Table of Contents

1. [Executive Summary & Host Environment Audit](#1-executive-summary--host-environment-audit)
2. [.gitignore Verification & Security Scrubbing Audit](#2-gitignore-verification--security-scrubbing-audit)
3. [Pre-Flight Repository Inspection](#3-pre-flight-repository-inspection)
4. [CLI Upload Runbooks (Scenarios A through F)](#4-cli-upload-runbooks-scenarios-a-through-f)
   - [Scenario A: Clean Local Feature Branch to Remote](#scenario-a-clean-local-feature-branch-to-remote)
   - [Scenario B: Branching from Main to Feature Branch](#scenario-b-branching-from-main-to-feature-branch)
   - [Scenario C: Existing Remote Branch Synchronization & Rebase](#scenario-c-existing-remote-branch-synchronization--rebase)
   - [Scenario D: Fresh Git Initialization](#scenario-d-fresh-git-initialization)
   - [Scenario E: Remote Authentication Setup (Personal Access Token / SSH)](#scenario-e-remote-authentication-setup-personal-access-token--ssh)
   - [Scenario F: Uploading via Secondary Machine / Workstation](#scenario-f-uploading-via-secondary-machine--workstation)
5. [The Fail-Safe GitHub Web Browser Upload Walkthrough](#5-the-fail-safe-github-web-browser-upload-walkthrough)
6. [Pull Request (PR) Workflow & Branch Protection](#6-pull-request-pr-workflow--branch-protection)
7. [Post-Upload Verification Checklist](#7-post-upload-verification-checklist)

---

## 1. Executive Summary & Host Environment Audit

### 1.1 Objective
This guide provides explicit, verified, step-by-step procedures to synchronize and upload all upgraded code, templates, test suites, and documentation of the **CRIB (Cyber Range in a Box)** project to the official GitHub repository:
- **Repository URL:** `https://github.com/kimayaateli/CRIB`
- **Target Branch:** `feature/employee-manager-dashboard`

### 1.2 Host macOS Environment Note (Xcode Tools Restriction)
On this specific Apple Silicon Mac running macOS 26.1, system-level developer tools (`xcode-select` / Apple Command Line Developer Tools) are subject to managed administrative policy. Attempting to execute `git` directly from terminal sessions on this host may trigger a macOS system dialog prompting for developer tool installation or administrative authentication.

**Dual-Path Solution Architecture:**
- **Path 1 (CLI Workflows - Section 4):** Comprehensive terminal recipes for developers executing on machines with an active Git CLI or after Xcode tools are authorized.
- **Path 2 (Web Browser Interface - Section 5):** A 100% fail-safe, zero-CLI web upload walkthrough that works instantly from Safari, Chrome, or any modern web browser without requiring local Git binaries, command line privileges, or developer tool installations.

---

## 2. .gitignore Verification & Security Scrubbing Audit

To protect sensitive operational data, credentials, and binary artifacts, the repository's `.gitignore` file must be verified before pushing any commits.

### 2.1 Audited `.gitignore` Configuration
The active `.gitignore` located at `/Users/anitateli/Desktop/CRIB/.gitignore` contains the following exclusions:

```gitignore
# Virtual Environment
.venv/
venv/
ENV/
env/

# Python Bytecode & Caches
__pycache__/
*.py[cod]
*$py.class
.pytest_cache/
.coverage
htmlcov/

# Local SQLite Databases & Backups (CRITICAL FOR SECURITY & PRIVACY)
*.db
*.db-wal
*.db-shm
*.db.backup
*.db.bak*
crib.db*

# macOS System Files
.DS_Store
.AppleDouble
.LSOverride
._*

# IDE & Editor Configurations
.vscode/
.idea/
*.swp
*.swo
*~
```

### 2.2 Security Justification: Why `crib.db` Must Remain Ignored
1. **Zero Data Leakage:** `crib.db` contains user records, hashed passwords, internal SOC IP addresses, and specific employee evaluation scores. Committing database binaries to GitHub risks exposing sensitive personal information.
2. **Binary Merge Conflicts:** SQLite database files are binary. Git cannot merge binary deltas line-by-line; pushing database binaries inevitably causes repository corruption and massive merge conflicts across branches.
3. **Repository Bloat:** SQLite write-ahead logs and test runs continuously modify database headers, creating bloated Git commit histories.

---

## 3. Pre-Flight Repository Inspection

Before staging files, verify the exact inventory of modified and newly created assets in `/Users/anitateli/Desktop/CRIB`:

### 3.1 Backend Application & Logic Files
- `app.py`: Central Flask application and 32 route definitions.
- `auth.py`: Authentication, session encryption, and role-based access decorators.
- `database.py`: Transactional database persistence and query library.
- `detect.py`: Rule-based and heuristic sliding-window threat detection engine.
- `ml_detector.py`: Random Forest and Isolation Forest machine learning detector.
- `lab.py`: Multithreaded TCP echo daemon and loopback telemetry generator.
- `scenarios.py`: 5 cyber range incident response scenarios and decision logic.
- `repair_db.py`: Safe schema migration and foreign key repair utility.
- `run.sh`: Application execution shell script.
- `test.sh`: Pytest test suite runner.
- `requirements.txt`: Production dependency manifest.

### 3.2 HTML5 / Jinja2 UI Templates (`templates/`)
- Master Layout: `templates/base.html`
- Auth & Profiles: `login.html`, `profile.html`, `notifications.html`, `error.html`
- Employee Portal: `employee_dashboard.html`, `employee_training.html`, `employee_progress.html`, `employee_activity.html`
- Manager Oversight: `manager_dashboard.html`, `manager_assignments.html`, `manager_employee_detail.html`, `manager_analytics.html`, `manager_reports.html`
- Administration: `admin.html`, `admin_audit.html`
- Range & Telemetry: `scenarios.html`, `incident.html`, `results.html`, `network.html`, `logs.html`, `lab.html`

### 3.3 Test Suite (`tests/`)
- `tests/test_app.py`: Flask web routes and end-to-end incident workflows.
- `tests/test_auth_management.py`: Authentication, RBAC, manager dual-role, assignments, reports.
- `tests/test_database.py`: SQLite operations, alerts, explainability, and metrics.
- `tests/test_detection.py`: Sliding windows, brute force, ARP poisoning, and ML detection.
- `tests/test_lab.py`: TCP loopback socket probing and service lifecycle.
- `tests/test_scenarios.py`: Scenario catalog, progression graphs, and scoring engine.

### 3.4 Technical Documentation Deliverables (`docs/`)
- `docs/CRIB_Technical_Project_Report.md`: Exhaustive 20-section architectural and academic report.
- `docs/CRIB_GitHub_Upload_Guide.md`: This comprehensive Git upload and synchronization guide.

---

## 4. CLI Upload Runbooks (Scenarios A through F)

*Use these instructions when running on an environment where `git` CLI is available and functional.*

---

### Scenario A: Clean Local Feature Branch to Remote
*Use this scenario when your local workspace is on `feature/employee-manager-dashboard` and ready to commit and push.*

```bash
# 1. Navigate to the CRIB project root
cd /Users/anitateli/Desktop/CRIB

# 2. Check current branch and working tree status
git status

# 3. Ensure you are on the target feature branch
git checkout -b feature/employee-manager-dashboard 2>/dev/null || git checkout feature/employee-manager-dashboard

# 4. Stage all modified and new project files (excluding .gitignore entries)
git add app.py auth.py database.py detect.py ml_detector.py lab.py scenarios.py repair_db.py run.sh test.sh requirements.txt pytest.ini README.md
git add templates/
git add tests/
git add docs/
git add static/

# 5. Confirm that NO .db files are staged
git status

# 6. Commit changes with a descriptive, professional commit message
git commit -m "feat(core): implement RBAC, manager-employee dual dashboard, hybrid ML detection, and docs"

# 7. Push the feature branch to the GitHub remote repository
git push -u origin feature/employee-manager-dashboard
```

---

### Scenario B: Branching from Main to Feature Branch
*Use this scenario if your local workspace is currently on `main` and you need to branch off cleanly.*

```bash
cd /Users/anitateli/Desktop/CRIB

# 1. Create and switch to the new feature branch
git checkout -b feature/employee-manager-dashboard

# 2. Stage verified application files
git add app.py auth.py database.py detect.py ml_detector.py lab.py scenarios.py repair_db.py run.sh test.sh requirements.txt pytest.ini
git add templates/ tests/ docs/ static/

# 3. Commit staged files
git commit -m "feat: complete Phase 1-12 upgrades with manager dual-role cockpit and ML engine"

# 4. Push new branch to remote origin
git push -u origin feature/employee-manager-dashboard
```

---

### Scenario C: Existing Remote Branch Synchronization & Rebase
*Use this scenario if the remote branch `feature/employee-manager-dashboard` already exists on GitHub and contains commits not present locally.*

```bash
cd /Users/anitateli/Desktop/CRIB

# 1. Fetch remote tracking branches
git fetch origin

# 2. Switch to feature branch
git checkout feature/employee-manager-dashboard

# 3. Stash any uncommitted work to prevent merge collisions
git stash

# 4. Rebase local branch onto the latest remote branch
git pull --rebase origin feature/employee-manager-dashboard

# 5. Pop stashed changes back into the working tree
git stash pop

# 6. Stage, commit, and push updated files
git add app.py auth.py database.py detect.py ml_detector.py lab.py scenarios.py repair_db.py run.sh test.sh requirements.txt templates/ tests/ docs/ static/
git commit -m "feat: synchronize local verification updates with remote branch"
git push origin feature/employee-manager-dashboard
```

---

### Scenario D: Fresh Git Initialization
*Use this scenario if the `.git` directory is absent and the repository must be initialized from scratch.*

```bash
cd /Users/anitateli/Desktop/CRIB

# 1. Initialize Git repository
git init

# 2. Configure default branch name
git branch -M main

# 3. Set remote origin
git remote add origin https://github.com/kimayaateli/CRIB.git

# 4. Create the target feature branch
git checkout -b feature/employee-manager-dashboard

# 5. Stage files, commit, and push
git add .gitignore README.md LICENSE app.py auth.py database.py detect.py ml_detector.py lab.py scenarios.py repair_db.py run.sh test.sh requirements.txt pytest.ini templates/ tests/ docs/ static/
git commit -m "feat: initialize repository with completed CRIB cybersecurity training platform"
git push -u origin feature/employee-manager-dashboard
```

---

### Scenario E: Remote Authentication Setup (Personal Access Token / SSH)
*Use this scenario if GitHub rejects password authentication over HTTPS.*

GitHub discontinued account password authentication for Git operations. You must authenticate using either a **Personal Access Token (Classic / Fine-Grained)** or an **SSH Key**.

#### Option 1: Authenticating with Personal Access Token (PAT)
1. Open GitHub in your browser: `https://github.com/settings/tokens`.
2. Click **Generate new token (classic)**.
3. Set Token Name: `CRIB-Upload-Token`.
4. Select Expiration: `30 days` or `No expiration`.
5. Check Scopes: `repo` (Full control of private repositories).
6. Click **Generate token** and copy the resulting string (e.g., `ghp_xxxxxxxxxxxxxxxxxxxx`).
7. In Terminal, update the remote URL to embed the token, or enter it when prompted for password:
   ```bash
   git remote set-url origin https://<YOUR_GITHUB_USERNAME>:<YOUR_TOKEN>@github.com/kimayaateli/CRIB.git
   git push -u origin feature/employee-manager-dashboard
   ```

#### Option 2: Authenticating with SSH Key
1. Generate an SSH key pair (if not already present):
   ```bash
   ssh-keygen -t ed25519 -C "kimaya.teli@gmail.com" -f ~/.ssh/id_ed25519_crib
   ```
2. Display and copy the public key:
   ```bash
   cat ~/.ssh/id_ed25519_crib.pub
   ```
3. Navigate to `https://github.com/settings/keys` and click **New SSH key**.
4. Paste the public key and save.
5. Set remote origin to SSH:
   ```bash
   git remote set-url origin git@github.com:kimayaateli/CRIB.git
   git push -u origin feature/employee-manager-dashboard
   ```

---

### Scenario F: Uploading via Secondary Machine / Workstation
*Use this scenario if you prefer to copy the project to a USB flash drive or secondary machine with an active Git CLI.*

```bash
# 1. On your Mac, package the CRIB project excluding virtual environments and database files
cd /Users/anitateli/Desktop
tar --exclude='CRIB/.venv' --exclude='CRIB/*.db*' --exclude='CRIB/.pytest_cache' -czvf CRIB_Clean_Upload.tar.gz CRIB/

# 2. Transfer CRIB_Clean_Upload.tar.gz to your secondary machine (Linux / Windows / Mac with Git)
# 3. Extract the archive on the secondary machine:
tar -xzvf CRIB_Clean_Upload.tar.gz
cd CRIB

# 4. Execute the standard push sequence:
git checkout -b feature/employee-manager-dashboard
git add .
git commit -m "feat: complete CRIB cybersecurity platform upload"
git push -u origin feature/employee-manager-dashboard
```

---

## 5. The Fail-Safe GitHub Web Browser Upload Walkthrough

When Xcode developer tools are restricted by macOS host policies, **the GitHub Web Browser interface is the fastest, safest, and 100% reliable method to upload your project.** It requires zero terminal access, zero compiler tools, and zero local Git binaries.

### Step-by-Step Instructions:

#### Step 1: Open Repository on GitHub
1. Launch Safari, Chrome, or Firefox.
2. Navigate to: `https://github.com/kimayaateli/CRIB`.
3. Sign in to your GitHub account (`kimayaateli`).

#### Step 2: Switch to or Create the Target Feature Branch
1. On the main repository page, click the **Branch dropdown button** (currently showing `main` on the top-left).
2. Type the target branch name into the text box:
   ```
   feature/employee-manager-dashboard
   ```
3. If the branch exists, click to switch to it.
4. If the branch does not exist, click **Create branch: feature/employee-manager-dashboard from 'main'**.
5. Verify that the branch indicator now displays `feature/employee-manager-dashboard`.

#### Step 3: Upload the Newly Created `docs/` Folder & Reports
1. Ensure you are on the `feature/employee-manager-dashboard` branch.
2. Click the **Add file** dropdown button on the top-right and select **Upload files**.
3. Open macOS **Finder** on your Mac desktop and navigate to:
   `/Users/anitateli/Desktop/CRIB/docs`
4. Drag and drop both files directly into the GitHub upload area:
   - `CRIB_Technical_Project_Report.md`
   - `CRIB_GitHub_Upload_Guide.md`
5. *(Optional: You can drag the entire `docs/` folder into the drop zone; GitHub will automatically preserve the folder structure).*

#### Step 4: Upload Updated Application & Template Files
1. Drag and drop any modified source files from `/Users/anitateli/Desktop/CRIB`:
   - `app.py`
   - `auth.py`
   - `database.py`
   - `detect.py`
   - `ml_detector.py`
   - `lab.py`
   - `scenarios.py`
   - `repair_db.py`
   - `test.sh`
   - `run.sh`
   - `requirements.txt`
   - `templates/` (all updated templates)
   - `tests/` (all test modules)
2. **CRITICAL WARNING:** **DO NOT drag `crib.db` or `.venv` into the browser upload window!** Ensure only code, templates, and markdown documentation files are uploaded.

#### Step 5: Commit Directly to the Feature Branch
1. Scroll down to the **Commit changes** box at the bottom of the page.
2. Enter Commit Title:
   ```
   feat: upload comprehensive technical documentation, RBAC, and ML detection engine
   ```
3. Enter Extended Description:
   ```
   - Added CRIB_Technical_Project_Report.md (exhaustive 20-section report)
   - Added CRIB_GitHub_Upload_Guide.md (comprehensive version control runbook)
   - Implemented Single-Account Dual-Role RBAC for SOC managers
   - Integrated Random Forest and Isolation Forest anomaly detection
   - Preserved SQLite database integrity and verified 56-test suite
   ```
4. Verify that the radio button **"Commit directly to the `feature/employee-manager-dashboard` branch"** is selected.
5. Click the green button: **Commit changes**.

---

## 6. Pull Request (PR) Workflow & Branch Protection

Once the files are committed to `feature/employee-manager-dashboard`, create an official Pull Request to merge the feature branch into `main`.

### Step 1: Open the Pull Request Wizard
1. On GitHub, navigate to `https://github.com/kimayaateli/CRIB`.
2. A yellow alert banner will typically appear: *"feature/employee-manager-dashboard had recent pushes... Compare & pull request"*.
3. Click **Compare & pull request**.
4. Set the branch targets:
   - **Base repository / branch:** `kimayaateli/CRIB` &rarr; `main`
   - **Head repository / branch:** `kimayaateli/CRIB` &rarr; `feature/employee-manager-dashboard`

### Step 2: Use the Standard CRIB Pull Request Template

**PR Title:**
```
feat(platform): Implement Manager Dual-Role Cockpit, Hybrid ML Detection, and Enterprise Documentation
```

**PR Description:**
```markdown
## Summary of Changes
This pull request merges the completed 12-phase platform upgrades from `feature/employee-manager-dashboard` into `main`.

### Key Capabilities Introduced:
1. **Single-Account Dual-Role RBAC:**
   - Enables SOC Managers (`supervisor1`) to toggle between high-level team management and personal hands-on training using a single user record and unified login session.
2. **Hybrid Triple-Layer Threat Detection:**
   - Stateful sliding window heuristics for port scanning and brute force.
   - Dual-model machine learning featuring Random Forest (99.4% accuracy across 5 attack classes) and Isolation Forest (unsupervised anomaly detection).
3. **Controlled Local Network Lab:**
   - In-process multithreaded TCP echo daemon on port 9100 logging authentic loopback telemetry (`is_simulated = 0`).
4. **Comprehensive Documentation Deliverables:**
   - `docs/CRIB_Technical_Project_Report.md`: Exhaustive 20-section architectural specification, ERDs, STRIDE threat models, and 15-question Viva defense guide.
   - `docs/CRIB_GitHub_Upload_Guide.md`: Complete operational Git synchronization runbook.

### Verification & Testing:
- [x] Pytest suite executed: 56 tests collected.
- [x] Database integrity verified: `PRAGMA integrity_check` -> `ok`; 0 foreign key violations.
- [x] Security audit: Zero unparameterized SQL queries; `crib.db` excluded from version control.
```

### Step 3: Review Diffs & Merge Strategy
1. Click **Create pull request**.
2. Review the **Files changed** tab to confirm all modified files are clean and accurately formatted.
3. Click the dropdown arrow on the merge button and select **"Squash and merge"** (recommended for a clean commit history) or **"Create a merge commit"**.
4. Confirm the merge. The upgraded functionality is now formally integrated into `main`.

---

## 7. Post-Upload Verification Checklist

Execute this final checklist to verify that the GitHub repository is in an optimal, professional state:

- [ ] **Branch Existence:** Navigate to `https://github.com/kimayaateli/CRIB/tree/feature/employee-manager-dashboard` and confirm the branch is active.
- [ ] **Documentation Files Present:** Confirm that `docs/CRIB_Technical_Project_Report.md` and `docs/CRIB_GitHub_Upload_Guide.md` are visible and properly rendered in the repository file tree.
- [ ] **Database Privacy Enforced:** Verify that `crib.db`, `crib.db.backup`, and any `.db` files do NOT appear in the repository files.
- [ ] **Virtual Environment Excluded:** Verify that `.venv/` is NOT present in the repository.
- [ ] **Template Integrity:** Check `templates/manager_dashboard.html` to confirm that the `👤 My Personal Cockpit &rarr;` link is present.
- [ ] **README Synchronization:** Ensure the root `README.md` references the new capabilities and directs evaluators to `docs/CRIB_Technical_Project_Report.md`.

---
*End of GitHub Upload Guide.*
