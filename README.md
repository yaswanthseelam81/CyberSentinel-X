# 🛡️ CyberSentinel X

### Explainable Security Operations, Attack-Chain Reconstruction & Investigation Platform

CyberSentinel X is a lightweight security operations and investigation platform designed to transform security events into actionable incidents.

The platform combines detection rules, event correlation, behavior-based risk scoring, MITRE ATT&CK mapping, evidence-backed attack-chain reconstruction, explainable narratives, analyst investigation workflows, persistent case storage, and automated detection evaluation.

> **Project status:** Working prototype / portfolio-grade security engineering project

---

## 🎯 What CyberSentinel X Does

CyberSentinel X follows this pipeline:

```text
Security Logs / Simulated Events
            ↓
      Event Parsing
            ↓
       Rule Engine
            ↓
          Alerts
            ↓
        Correlation
            ↓
         Incidents
            ↓
    Risk + MITRE Mapping
            ↓
   Attack-Chain Reconstruction
            ↓
 Evidence + Timeline + Narrative
            ↓
    Analyst Investigation
            ↓
      SQLite Persistence
            ↓
       SOC Dashboard
```

The goal is not only to detect suspicious behavior, but also to explain **why an incident was created and how the observed events form a possible attack sequence**.

---

## ✨ Key Features

### 1. Rule-Based Detection

CyberSentinel X supports configurable detection rules for multiple simulated security behaviors.

Current scenarios include:

* Brute Force / Account Compromise
* Privilege Escalation
* Suspicious Process Execution
* Suspicious DNS Activity
* Unusual Network Connection

Rules are stored as configuration files rather than being hard-coded entirely into the dashboard.

---

### 2. Alert Generation

Detected behaviors produce structured alerts containing information such as:

```text
Rule ID
Rule Name
Source IP
Username
Host
Severity
Confidence
MITRE Technique
Finding
```

---

### 3. Event Correlation

Related alerts and events can be grouped into incidents based on their contextual relationships.

This transforms multiple individual detections into a higher-level security case.

---

### 4. Behavior-Based Risk Scoring

CyberSentinel X calculates a risk score using observed security behavior, including:

* Event severity
* Repeated failed authentication
* Successful authentication after repeated failures
* Privilege escalation
* Process execution
* DNS activity
* Network activity
* Detection confidence

Risk is classified into:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

---

### 5. MITRE ATT&CK Mapping

Current mappings include techniques such as:

```text
T1110
Brute Force

T1548
Abuse Elevation Control Mechanism

T1059
Command and Scripting Interpreter

T1071
Application Layer Protocol

T1078
Valid Accounts
```

The attack-chain engine also associates individual stages with MITRE ATT&CK techniques and tactics.

---

### 6. Attack-Chain Reconstruction

One of the core features of CyberSentinel X is reconstruction of a multi-stage sequence.

Example:

```text
INITIAL_ACCESS
       ↓
PRIVILEGE_ESCALATION
       ↓
EXECUTION
       ↓
DISCOVERY_OR_C2
       ↓
NETWORK_ACTIVITY
```

The system can produce an evidence-backed chain containing:

```text
Stage
Timestamp
Event Type
Source IP
Username
Host
MITRE Technique
MITRE Tactic
Risk Contribution
Confidence
Evidence
```

For the current five-stage synthetic chain, the system reports:

```text
Chain Risk: 80/100
Confidence: 86.4%
```

---

### 7. Explainable Investigation

CyberSentinel X generates analyst-readable explanations describing the observed behavior.

Example:

```text
A privilege-grant event was observed, indicating possible privilege escalation.
A process execution event was observed and requires investigation for potentially suspicious execution.
A DNS query associated with the incident was observed.
An unusual network connection was observed and should be investigated as possible outbound activity.
```

---

### 8. Evidence and Timeline

Every enriched incident can contain:

```text
Evidence
Attack Timeline
MITRE Mapping
Risk
Confidence
Analyst Narrative
Attack Chain
```

This allows an analyst to move from an alert to the underlying evidence.

---

### 9. Investigation Workflow

The dashboard supports an investigation lifecycle:

```text
OPEN
  ↓
INVESTIGATING
  ↓
CONTAINED
  ↓
RESOLVED
```

Analyst actions can contain notes such as:

```text
Analyst started investigation.

Source IP blocked and affected host isolated.

Investigation completed and incident resolved.
```

---

### 10. Persistent Case Storage

SQLite is used to persist:

```text
Incidents
Investigation Actions
Status
Risk
Severity
Confidence
Created Time
```

Database:

```text
data/cybersentinel.db
```

Investigation history survives dashboard restarts.

---

### 11. Incident History

Stored incidents can be viewed through the dashboard with information such as:

```text
Incident ID
Source IP
Severity
Risk
Risk Level
Status
Created Time
```

Saved investigation actions can also be retrieved from the database.

---

### 12. Automated Security Evaluation

CyberSentinel X includes an automated scenario evaluation framework.

Current synthetic evaluation:

```text
Attack Scenarios : 5
Detected         : 5
Detection Rate   : 100.0%

Normal Alerts    : 0
False Positive Rate : 0.0%

Overall Result   : PASS
```

### Important

These numbers represent the project's **five synthetic attack scenarios and current benign test data**. They are not a claim of 100% real-world detection accuracy.

---

## 🧪 Current Test Scenarios

| Scenario             | Events | Alerts | Result |
| -------------------- | -----: | -----: | ------ |
| Brute Force          |      6 |      2 | PASS   |
| Privilege Escalation |      2 |      1 | PASS   |
| Suspicious Process   |      1 |      1 | PASS   |
| Suspicious DNS       |      1 |      1 | PASS   |
| Unusual Network      |      1 |      1 | PASS   |

---

## 🏗️ Architecture

```text
                      CyberSentinel X
                             │
            ┌────────────────┴────────────────┐
            │                                 │
      Event Sources                       Rule Files
            │                                 │
            └────────────────┬────────────────┘
                             ↓
                       Event Parser
                             ↓
                        Rule Engine
                             ↓
                           Alerts
                             ↓
                         Correlation
                             ↓
                         Incidents
                    ┌────────┼────────┐
                    ↓        ↓        ↓
                   Risk     MITRE   Evidence
                    │        │        │
                    └────────┼────────┘
                             ↓
                    Attack-Chain Engine
                             ↓
                    Analyst Investigation
                             ↓
                           SQLite
                             ↓
                     Streamlit Dashboard
```

---

## 📁 Project Structure

```text
CyberSentinel-X/
│
├── app/
│   ├── collectors/
│   │   └── log_reader.py
│   │
│   ├── normalizer/
│   │   └── log_parser.py
│   │
│   ├── detection/
│   │   ├── rule_engine.py
│   │   ├── rule_loader.py
│   │   └── rule_manager.py
│   │
│   ├── correlation/
│   │   └── correlated_incident.py
│   │
│   ├── investigation/
│   │   ├── actions.py
│   │   ├── attack_chain.py
│   │   ├── attack_chain_report.py
│   │   ├── attack_narrative.py
│   │   ├── evidence.py
│   │   └── timeline.py
│   │
│   ├── risk/
│   │   ├── risk_engine.py
│   │   └── risk_level.py
│   │
│   ├── mitre/
│   │   └── technique_map.py
│   │
│   ├── storage/
│   │   ├── database.py
│   │   └── incident_store.py
│   │
│   ├── evaluation/
│   │   ├── metrics.py
│   │   └── scenario_runner.py
│   │
│   ├── event_model.py
│   ├── incident_enricher.py
│   └── pipeline.py
│
├── dashboard/
│   └── dashboard.py
│
├── data/
│   ├── simulated_attack.log
│   ├── privilege_escalation.log
│   ├── suspicious_process.log
│   ├── suspicious_dns.log
│   ├── unusual_network.log
│   ├── full_attack_chain.log
│   └── cybersentinel.db
│
├── rules/
│   ├── brute_force.json
│   ├── suspicious_login.json
│   ├── privilege_escalation.json
│   ├── suspicious_process.json
│   ├── suspicious_dns.json
│   └── unusual_network.json
│
├── simulators/
│   ├── privilege_escalation_simulator.py
│   ├── process_execution_simulator.py
│   ├── dns_activity_simulator.py
│   └── network_activity_simulator.py
│
├── tests/
│   ├── test_all_scenarios.py
│   ├── test_all_risk_scores.py
│   ├── test_attack_chain.py
│   ├── test_attack_chain_report.py
│   ├── test_false_positive.py
│   ├── test_security_scorecard.py
│   ├── test_scenario_runner.py
│   ├── test_actions.py
│   ├── test_database.py
│   ├── test_incident_store.py
│   └── ...
│
└── README.md
```

---

## ⚙️ Requirements

Recommended environment:

```text
Python 3.14+
Streamlit
SQLite
```

Create and activate the virtual environment:

```powershell
python -m venv .venv
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install Streamlit:

```powershell
pip install streamlit
```

---

## ▶️ Running CyberSentinel X

From:

```text
D:\PROJECTS\CyberSentinel-X
```

activate the environment:

```powershell
.venv\Scripts\Activate.ps1
```

Run the dashboard:

```powershell
streamlit run dashboard\dashboard.py
```

Then open:

```text
http://localhost:8501
```

---

## 🧪 Running Tests

Run the complete security scorecard:

```powershell
python -m tests.test_security_scorecard
```

Run all attack scenarios:

```powershell
python -m tests.test_all_scenarios
```

Run attack-chain reconstruction:

```powershell
python -m tests.test_attack_chain_report
```

Run false-positive testing:

```powershell
python -m tests.test_false_positive
```

Run risk calibration:

```powershell
python -m tests.test_all_risk_scores
```

---

## 🔍 Example Attack Chain

CyberSentinel X can reconstruct the following synthetic sequence:

```text
21:00:01
LOGIN_SUCCESS
       ↓
INITIAL_ACCESS
       ↓
21:00:10
PRIVILEGE_GRANTED
       ↓
PRIVILEGE_ESCALATION
       ↓
21:00:20
PROCESS_STARTED
       ↓
EXECUTION
       ↓
21:00:30
DNS_QUERY
       ↓
DISCOVERY_OR_C2
       ↓
21:00:40
NETWORK_CONNECTION
       ↓
NETWORK_ACTIVITY
```

The chain is then enriched with MITRE information, evidence, confidence, and risk contribution.

---

## 🛡️ Design Goals

CyberSentinel X focuses on:

* Explainable detection
* Evidence-backed investigation
* Attack-chain reconstruction
* Behavior-based risk analysis
* Persistent incident management
* Automated evaluation
* Lightweight local deployment
* Beginner-accessible security engineering

---

## 🚧 Current Limitations

This is a portfolio and research-oriented prototype.

Current limitations include:

* Security events are primarily simulated.
* Detection performance has only been evaluated against a small synthetic test set.
* Risk scoring is a custom project-specific model rather than a validated industry standard.
* MITRE mapping currently covers a limited set of techniques.
* Automated containment actions are represented as investigation actions rather than production endpoint controls.
* The platform is not intended to replace a production SIEM/SOAR system.

---

## 🔮 Future Enhancements

Potential future work includes:

```text
Real log ingestion
        ↓
Streaming detection
        ↓
Expanded MITRE coverage
        ↓
Graph-based attack reconstruction
        ↓
Advanced correlation
        ↓
Entity behavior analytics
        ↓
Automated response integrations
        ↓
Threat intelligence enrichment
        ↓
More realistic evaluation datasets
        ↓
Cloud / distributed deployment
```

---

## 👨‍💻 Project Focus

CyberSentinel X was developed as a hands-on cybersecurity engineering project with emphasis on:

```text
Detection
Correlation
Risk Analysis
MITRE ATT&CK
Explainability
Attack Reconstruction
Investigation
Persistence
Testing
```

---

## 📌 Portfolio Summary

> **CyberSentinel X is an explainable security operations and investigation platform that detects simulated attack behaviors, correlates related events into incidents, calculates behavior-based risk, maps activity to MITRE ATT&CK, reconstructs multi-stage attack chains with evidence and confidence, generates analyst-readable explanations, persists investigation state in SQLite, and evaluates detection logic against synthetic attack and benign scenarios.**

---

## ⚠️ Disclaimer

CyberSentinel X is intended for **authorized security research, education, testing, and controlled lab environments**.

Use only against systems and data for which you have permission to monitor or test.
