# 🛡️ Financial Fraud → Cyber Threat Detection Pipeline

---

## 🚨 Executive SOC Summary

**What was simulated:**

* Credential stuffing attacks against Active Directory (SMB/NTLM authentication)
* Insider threat activity involving privileged account abuse on Domain Controller
* Lateral movement across internal Windows endpoints after initial compromise

**What was detected:**

* Authentication failure spikes (Event IDs 4625, 4771)
* Privilege escalation and account manipulation (Event IDs 4720, 4728)
* Anti-forensics behavior including log clearing (Event ID 1102)
* Lateral movement patterns via SMB and Kerberos anomalies (Event IDs 4624 Type 3, 4769)

**Business risk simulated:**

* Banking customer account takeover (ATO) via credential stuffing
* Internal fraud enabled by privileged insider abuse
* Domain-wide compromise risk through credential dumping and lateral movement

---

## 🧭 Table of Contents

* [Overview](#-overview)
* [Lab Architecture](#-lab-architecture)
* [Evidence-Driven Attack Walkthrough](#-evidence-driven-attack-walkthrough)
* [Scenario A — Account Takeover](#-scenario-a--account-takeover-credential-stuffing)
* [Scenario B — Insider Threat](#-scenario-b--insider-threat-privileged-abuse)
* [Scenario C — Lateral Movement](#-scenario-c--lateral-movement)
* [Custom Detection Engineering](#-custom-detection-engineering-wazuh)
* [Detection Engineering Decisions](#-detection-engineering-decisions)
* [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
* [Compliance Mapping](#-compliance-mapping)
* [Threat Intelligence Enrichment](#-threat-intelligence-enrichment)
* [SOC Visibility Summary](#-soc-visibility-summary)
* [What This Project Demonstrates](#-what-this-project-demonstrates)
* [Author](#-author)

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.14.1-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Lab](https://img.shields.io/badge/Environment-SOC%20Lab-green)
![Focus](https://img.shields.io/badge/Security-Detection%20Engineering-orange)
![Status](https://img.shields.io/badge/Project-Completed-success)

---

## 🔍 Overview

An end-to-end SOC detection engineering project simulating real-world financial cyber attacks inside an Active Directory environment.

This project demonstrates how a SOC detects, investigates, and correlates:

* Account Takeover (Credential Stuffing)
* Insider Threat (Privileged Abuse)
* Lateral Movement (Post-Compromise Attack Paths)

Mapped to:

* MITRE ATT&CK Framework
* PCI-DSS Security Controls
* Banking Fraud Detection Scenarios

---

## 🧱 Lab Architecture

```
                     ┌──────────────┐
                     │  Kali Linux  │
                     │ (Attacker)   │
                     └──────┬───────┘
                            │
                            ▼
        ┌──────────────────────────────┐
        │   pfSense Firewall (10.0.0.1)│
        └──────────────┬───────────────┘
                       │
     ┌─────────────────┼──────────────────┐
     ▼                 ▼                  ▼
┌──────────┐   ┌──────────────┐   ┌──────────────┐
│  DC01    │   │ WKSTNO1      │   │ Wazuh Server │
│ AD Server│   │ Windows 10   │   │ SIEM         │
│10.0.0.10 │   │10.0.0.100    │   │10.0.10.11    │
└──────────┘   └──────────────┘   └──────────────┘
```

---

# 📸 Evidence-Driven Attack Walkthrough

> Each scenario is documented using **real execution evidence + SIEM detection output**

---

# 🔴 Scenario A — Account Takeover (Credential Stuffing)

## 1️⃣ Attack Execution (Kali Linux)

### Reconnaissance

![Scenario A Recon](evidence/kali_attacks/scenarioA_recon.png)

### Domain Enumeration

![Scenario A Enumeration](evidence/kali_attacks/scenarioA_enum.png)

### Credential Stuffing Attack

![Scenario A NetExec Attack](evidence/kali_attacks/scenarioA_netexec.png)

---

## 2️⃣ SIEM Detection (Wazuh)

### Authentication Failures Flood

![Wazuh ATO Alerts](evidence/wazuh_dashboard/scenarioA_alerts.png)

### Account Lockout Detection

![Lockout Event](evidence/windows_dc01/scenarioA_lockout.png)

---

## 3️⃣ Endpoint Evidence (DC01)

### Security Event Logs

![DC01 Event Logs](evidence/windows_dc01/scenarioA_eventlog.png)

---

## 🧠 Detection Outcome

✔ Credential stuffing detected via frequency-based correlation
✔ Account lockout confirmed brute force threshold breach

---

# 🟠 Scenario B — Insider Threat (Privileged Abuse)

## 1️⃣ Privileged Activity (DC01)

### AD Enumeration

![AD Enumeration](evidence/windows_dc01/scenarioB_ad_enum.png)

### Sensitive Data Access

![Sensitive File Access](evidence/windows_dc01/scenarioB_sensitive_data.png)

---

## 2️⃣ Persistence & Abuse

### Backdoor Account Creation

![Backdoor Account](evidence/windows_dc01/scenarioB_user_creation.png)

### Privilege Escalation

![Domain Admin Addition](evidence/windows_dc01/scenarioB_privilege_escalation.png)

---

## 3️⃣ Anti-Forensics Activity

### Security Log Cleared (CRITICAL)

![Event Log Cleared](evidence/windows_dc01/scenarioB_eventlog_cleared.png)

---

## 4️⃣ SIEM Detection (Wazuh)

![Insider Threat Alerts](evidence/wazuh_dashboard/scenarioB_alerts.png)

---

## 🧠 Detection Outcome

✔ Privilege escalation detected
✔ Anti-forensics behavior flagged as critical

---

# 🔵 Scenario C — Lateral Movement

## 1️⃣ Post-Compromise Activity (Kali)

### SMB Share Enumeration

![SMB Enumeration](evidence/kali_attacks/scenarioC_smb_enum.png)

### Remote Command Execution

![Remote Execution](evidence/kali_attacks/scenarioC_remote_exec.png)

---

## 2️⃣ Target Compromise

### Workstation Access (WKSTNO1)

![WKSTNO1 Access](evidence/windows_workstation/scenarioC_access.png)

---

## 3️⃣ SIEM Correlation (Wazuh)

### Lateral Movement Timeline

![Lateral Movement Timeline](evidence/wazuh_dashboard/scenarioC_timeline.png)

---

## 🧠 Detection Outcome

✔ SMB lateral movement detected
✔ Kerberos abuse patterns identified
✔ Full attacker pivot chain reconstructed

---

# ⚙️ Custom Detection Engineering (Wazuh)

11 custom rules implemented:

* Credential stuffing detection
* Password spraying thresholds
* Privilege escalation alerts
* Log tampering detection
* NTDS extraction detection
* SMB lateral movement detection
* Kerberoasting detection

---

## 🔥 Detection Engineering Decisions

This section explains the rationale behind detection tuning and correlation design choices made in this SOC project.

**1. Frequency-based thresholds (Credential Stuffing)**

* Set low thresholds (5–20 events) within short time windows (60–120s)
* Balances detection sensitivity vs false positives in authentication systems
* Designed to detect burst-style ATO attempts without flagging normal user mistypes

**2. Insider threat detection (low frequency, high severity)**

* Privilege escalation events are rare but high impact
* Rules tuned to trigger immediately on single occurrence (e.g., 4720, 1102)
* Prioritizes business risk over noise reduction

**3. Anti-forensics behavior handling**

* Event log clearing (1102) treated as CRITICAL regardless of context
* No thresholding applied due to its strong malicious correlation in banking environments

**4. Lateral movement correlation windows**

* Time windows (30–120 seconds) used to correlate SMB logons and remote execution
* Helps reconstruct attacker kill chain across multiple hosts

**5. MITRE tagging strategy**

* Each rule mapped to ATT&CK techniques for SOC triage efficiency
* Enables faster analyst interpretation and standardized reporting

**6. Banking SOC alignment**

* Detection logic designed to reflect real-world constraints in financial institutions:

  * High alert volume environments
  * Need for rapid fraud detection
  * Strict compliance logging requirements

---

# 🧠 MITRE ATT&CK Mapping

| Technique ID | Technique            |
| ------------ | -------------------- |
| T1110.003    | Password Spraying    |
| T1078        | Valid Accounts       |
| T1070.001    | Log Clearing         |
| T1021.002    | SMB Lateral Movement |
| T1558.003    | Kerberoasting        |
| T1003.003    | NTDS Dumping         |
| T1136.001    | Account Creation     |

---

# 🏦 Compliance Mapping

* PCI-DSS Req 10 → Logging & Monitoring
* PCI-DSS Req 7 → Access Control
* PCI-DSS Req 8 → Identity Management
* Banking fraud detection alignment (CBK / AML patterns)

---

# 🐍 Threat Intelligence Enrichment

Python script enriches alerts with:

* AbuseIPDB reputation scoring
* MITRE mapping
* Risk classification (LOW → CRITICAL)
* Analyst action recommendations

---

# 📊 SOC Visibility Summary

![Full Dashboard View](evidence/wazuh_dashboard/full_view.png)

---

# 🚀 What This Project Demonstrates

* SOC detection engineering
* SIEM correlation logic design
* MITRE ATT&CK operational mapping
* Banking fraud simulation
* Security automation with Python

---

# 👤 Author

Moses Kinuthia
Cybersecurity Analyst | SOC Engineering | Nairobi, Kenya
Focus: Detection Engineering • Threat Intelligence • SOC Automation
