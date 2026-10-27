# CRIB — Cyber Range in a Box

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.x-informational.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-30%20passed-brightgreen.svg)](#running-tests)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**CRIB (Cyber Range in a Box)** is an interactive, lightweight cybersecurity incident-response training platform designed for IT department staff, junior security analysts, and incident-response personnel.

Rather than presenting static descriptions of attacks, CRIB provides a hands-on, local training environment where users investigate suspicious activity, analyze evidence, make critical incident-response decisions, receive detailed technical evaluations, and understand the real consequences of their choices.

---

## 🎯 Key Design Principles & Safety Guarantees

* **Controlled Local Environment:** CRIB operates entirely on `127.0.0.1` (loopback) without requiring commercial SIEM software, cloud infrastructure, or multi-machine lab setups.
* **Truth in Telemetry:** Clear programmatic separation between **Genuine Local Observations** (actual TCP socket communication on loopback) and **Simulated Training Datasets** (predefined forensic logs). CRIB never fabricates fake live network traffic.
* **Strict Boundary Isolation:** Lab tools are programmatically restricted to loopback (`127.0.0.1`) and unprivileged user ports (1024–65535) with bounded socket timeouts. Arbitrary command execution is impossible.
* **No Artificial Hype:** Transparent, deterministic, rule-based detection with clear explanations of rule criteria and detection limitations.

---

## 🏛️ Architecture & Core Modules

```
┌─────────────────────────────────────────────────────────────┐
│                      Web UI (Flask)                         │
│  Dashboard • Scenarios • Network Monitor • Lab • Reports    │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
┌──────────────▼─────────────┐   ┌─────────────▼──────────────┐
│   Incident Engine & AAR    │   │  Controlled TCP Net Lab    │
│  4-Stage IR State Machine  │   │  Loopback Socket Service   │
│  (Triage -> Recovery)      │   │  & Real-Time Telemetry     │
└──────────────┬─────────────┘   └─────────────┬──────────────┘
               │                               │
┌──────────────▼───────────────────────────────▼──────────────┐
│                   Rule Detection Engine                     │
│    Port Scan • Brute Force • ARP Spoofing • Flood Surge     │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                SQLite Storage (crib.db)                     │
│       incidents • events • decisions • alerts               │
└─────────────────────────────────────────────────────────────┘
```

### 1. Security Dashboard (`/` & `/dashboard`)
Central operational view displaying training environment health, key metrics (active incidents, completed sessions, event count, alert count), quick-start scenario launch cards, and recent audit logs.

### 2. Incident Scenarios Engine (`/scenarios`)
Four foundational, structured incident response scenarios:
1. **Port Scanning & Network Reconnaissance:** Sequential SYN connection bursts probing DMZ service ports.
2. **Repeated Authentication Failures:** High-frequency SSH brute-force credential attacks.
3. **ARP Anomalies & Spoofing:** Duplicate MAC assignments and gateway impersonation (local MitM).
4. **Traffic Flooding (DoS):** Volumetric TCP SYN floods degrading service availability.

### 3. Four-Stage Incident Response Workflow (`/incident/<id>`)
Every scenario guides the user through the standard cybersecurity incident lifecycle:
* **Stage 1: Triage:** Classify urgency, assess scope, and establish initial operational priority.
* **Stage 2: Investigation:** Interrogate evidence, isolate affected nodes, and determine attack vector.
* **Stage 3: Containment:** Select appropriate quarantine actions without causing collateral outages.
* **Stage 4: Recovery & Hardening:** Eradicate root causes, apply preventive controls, and restore services.

### 4. Controlled TCP Network Lab (`/lab`)
* **Echo Service:** Threaded TCP listener on loopback port `9100`.
* **TCP Probe:** Measures socket latency, connection success, and response payloads.
* **Port Verification:** Evaluates TCP connection states across designated local ports (`9100–9103`).
* **Detection Demonstration:** Generates controlled local traffic bursts to trigger detection rules in real time.

### 5. Detection Engine (`detect.py`)
Sliding-window, rule-based detection engine identifying:
* `PORT_SCAN`: $\ge 10$ distinct ports contacted within 10 seconds.
* `AUTH_BRUTE_FORCE`: $\ge 5$ authentication failures within 10 seconds.
* `TRAFFIC_SURGE`: $\ge 100$ connections targeting a port within 2 seconds.
* `ARP_MAC_CHANGE` & `ARP_DUPLICATE_MAC`: Conflicting IP-MAC mappings.

### 6. After-Action Reporting & History (`/incident/<id>/results` & `/history`)
Generates comprehensive After-Action Reports (AAR) featuring:
* Overall numerical score (0–100) and proficiency grade.
* Detailed stage-by-stage decision review.
* Technical justifications and explanations of consequences.
* Recommended long-term preventative controls.

---

## 🚀 Quickstart Guide

### Prerequisites
* Python 3.10+ (or [uv](https://github.com/astral-sh/uv))

### Quick Start (One Command)

From inside the `CRIB` directory, simply run:
```bash
./run.sh
```
This automatically handles environment setup and starts the server at **[http://127.0.0.1:5001](http://127.0.0.1:5001)**.

To execute the test suite:
```bash
./test.sh
```

---

### Manual Launch

---

## 🧪 Running Tests

The test suite includes 30 unit and integration tests covering database schemas, rule detection, local TCP socket exercises, scenario definitions, and Flask endpoints:

```bash
pytest -v
```

All 30 tests execute in under 1 second without external network dependencies.

---

## 📂 Project Structure

```
CRIB/
├── app.py                  # Flask routes and application controller
├── database.py             # SQLite data access layer and schema management
├── detect.py               # Transparent rule-based detection engine
├── lab.py                  # Controlled loopback TCP networking lab
├── scenarios.py            # Predefined training scenarios and 4-stage IR lifecycle
├── requirements.txt        # Minimal production and testing dependencies
├── pytest.ini              # Pytest configuration
├── .gitignore              # Git ignore rules for clean repository hygiene
├── static/
│   └── style.css           # Modern dark-theme SOC stylesheet
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Master navigation and layout
│   ├── dashboard.html      # Security operations overview
│   ├── network.html        # Monitored network telemetry
│   ├── lab.html            # Controlled TCP lab controls
│   ├── scenarios.html      # Scenario catalog
│   ├── incident.html       # 4-stage incident response interface
│   ├── results.html        # After-action report and scoring breakdown
│   ├── history.html        # Past training sessions table
│   ├── logs.html           # Filterable event & alert audit logs
│   └── error.html          # Standardized error page
└── tests/                  # Automated pytest suite (30 passing tests)
    ├── test_app.py         # Flask client integration and workflow tests
    ├── test_database.py    # Database transactions, schema, and limits
    ├── test_detection.py   # Detection rule window and threshold tests
    ├── test_lab.py         # Loopback socket and port validation tests
    └── test_scenarios.py   # Scenario integrity and lifecycle progression
```

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
