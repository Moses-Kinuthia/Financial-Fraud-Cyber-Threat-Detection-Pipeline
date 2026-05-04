#!/usr/bin/env python3
"""
Financial Fraud → Cyber Threat Detection Pipeline
Alert Enrichment Tool
Author: Moses Kinuthia
Description: Enriches Wazuh alert data with AbuseIPDB threat intelligence
Usage: python3 enrich_alerts.py --input alerts.csv --output enriched_report.csv
"""

import argparse
import csv
import json
import requests
import time
import datetime
from tabulate import tabulate

# ---- Configuration ----
ABUSEIPDB_API_KEY = "YOUR_API_KEY_HERE"  # Free at abuseipdb.com
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_API_KEY = "YOUR_VT_KEY_HERE"       # Free at virustotal.com
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# MITRE TTP mapping (matches our Wazuh rules)
RULE_MITRE_MAP = {
    "100001": {"ttp": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    "100002": {"ttp": "T1110.003", "tactic": "Credential Access", "name": "Password Spraying"},
    "100003": {"ttp": "T1110.003", "tactic": "Credential Access", "name": "Password Spraying"},
    "100004": {"ttp": "T1110", "tactic": "Credential Access", "name": "Brute Force - Lockout"},
    "100005": {"ttp": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts"},
    "100010": {"ttp": "T1136.001", "tactic": "Persistence", "name": "Create Local Account"},
    "100011": {"ttp": "T1078.002", "tactic": "Privilege Escalation", "name": "Domain Accounts"},
    "100012": {"ttp": "T1070.001", "tactic": "Defense Evasion", "name": "Clear Windows Logs"},
    "100020": {"ttp": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Admin Shares"},
    "100021": {"ttp": "T1558.003", "tactic": "Credential Access", "name": "Kerberoasting"},
    "100022": {"ttp": "T1021.002", "tactic": "Lateral Movement", "name": "Remote SMB Execution"},
}

def check_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        data = response.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", "N/A"),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0),
            "is_tor": data.get("isTor", False),
        }
    except Exception as e:
        return {"abuse_score": "ERR", "country": "ERR", "isp": str(e), "total_reports": 0, "is_tor": False}

def get_risk_level(abuse_score, rule_id: str) -> str:
    """Calculate composite risk level from abuse score and rule severity."""
    critical_rules = ["100005", "100012", "100013"]
    if rule_id in critical_rules:
        return "CRITICAL"
    try:
        score = int(abuse_score)
        if score >= 80: return "HIGH"
        elif score >= 40: return "MEDIUM"
        elif score >= 10: return "LOW"
        else: return "INFO"
    except:
        return "UNKNOWN"

def process_alerts(input_file: str, output_file: str):
    """Main processing function."""
    enriched = []
    ip_cache = {}  # Cache to avoid duplicate API calls

    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"\n[*] Processing {len(rows)} alerts from {input_file}")
    print(f"[*] Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    for i, row in enumerate(rows):
        rule_id = row.get("rule_id", "unknown")
        src_ip = row.get("src_ip", "")
        target_user = row.get("target_user", "N/A")

        print(f"[{i+1}/{len(rows)}] Enriching alert: Rule {rule_id} | IP: {src_ip}")

        # Get IP intel (use cache if already looked up)
        if src_ip and src_ip not in ip_cache:
            ip_data = check_abuseipdb(src_ip)
            ip_cache[src_ip] = ip_data
            time.sleep(1)  # Respect API rate limits
        else:
            ip_data = ip_cache.get(src_ip, {})

        # Get MITRE mapping
        mitre = RULE_MITRE_MAP.get(rule_id, {"ttp": "N/A", "tactic": "N/A", "name": "Unknown"})
        risk = get_risk_level(ip_data.get("abuse_score", 0), rule_id)

        enriched.append({
            "timestamp": row.get("timestamp", "N/A"),
            "rule_id": rule_id,
            "alert_description": row.get("description", "N/A"),
            "src_ip": src_ip,
            "target_user": target_user,
            "mitre_ttp": mitre["ttp"],
            "mitre_tactic": mitre["tactic"],
            "mitre_technique": mitre["name"],
            "abuse_score": ip_data.get("abuse_score", "N/A"),
            "ip_country": ip_data.get("country", "N/A"),
            "ip_isp": ip_data.get("isp", "N/A"),
            "total_reports": ip_data.get("total_reports", 0),
            "is_tor": ip_data.get("is_tor", False),
            "risk_level": risk,
            "analyst_action": "ESCALATE" if risk in ["CRITICAL", "HIGH"] else "MONITOR"
        })

    # Write enriched CSV
    if enriched:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=enriched[0].keys())
            writer.writeheader()
            writer.writerows(enriched)

        # Print summary table
        display_cols = ["timestamp", "rule_id", "src_ip", "mitre_ttp", "abuse_score", "risk_level", "analyst_action"]
        table_data = [{k: r[k] for k in display_cols} for r in enriched]
        print("\n" + tabulate(table_data, headers="keys", tablefmt="grid"))
        print(f"\n[+] Enriched report saved to: {output_file}")

        # Print stats
        critical = sum(1 for r in enriched if r["risk_level"] == "CRITICAL")
        high = sum(1 for r in enriched if r["risk_level"] == "HIGH")
        print(f"\n[SUMMARY] Total: {len(enriched)} | CRITICAL: {critical} | HIGH: {high}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazuh Alert Enrichment Tool")
    parser.add_argument("--input", required=True, help="Input CSV file of alerts")
    parser.add_argument("--output", default="enriched_report.csv", help="Output CSV file")
    args = parser.parse_args()
    process_alerts(args.input, args.output)
