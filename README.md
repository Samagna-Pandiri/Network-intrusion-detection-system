# 🛡️ Network Intrusion Detection System (NIDS)

A Python-based NIDS that analyses network packet captures and automatically detects intrusion attempts, malware, exploits, and suspicious behaviour — inspired by real tools like Snort and Suricata.

---

## What It Detects

| Rule | Threat | Severity |
|------|--------|----------|
| RULE-001 | Port Scan (Reconnaissance) | 🔴 HIGH |
| RULE-002 | DNS Tunnelling (Data Exfiltration) | 🔴 HIGH |
| RULE-003 | Known Malware Ports (Metasploit/RAT) | 🔴 CRITICAL |
| RULE-004 | IRC Botnet C2 Traffic | 🔴 CRITICAL |
| RULE-005 | SQL Injection Attempt | 🔴 HIGH |
| RULE-006 | Cross-Site Scripting (XSS) | 🟡 MEDIUM |
| RULE-007 | EternalBlue SMB Exploit (MS17-010) | 🔴 CRITICAL |
| RULE-008 | Suspicious DNS TLD Query | 🟡 MEDIUM |
| RULE-009 | Telnet Login Attempt | 🟡 MEDIUM |
| RULE-010 | Shell Command in Payload (RCE) | 🔴 CRITICAL |

---

## Project Structure

```
nids/
├── nids.py                        # Main detection engine
├── captures/
│   └── sample_traffic.json        # Simulated packet capture (30 packets)
├── rules/
│   └── detection_rules.json       # Detection rules config
├── reports/
│   └── nids_report.txt            # Human-readable incident report (auto-generated)
├── alerts/
│   └── alerts.json                # Machine-readable alerts (auto-generated)
└── README.md
```

---

## How to Run

```bash
# No dependencies — pure Python standard library
python3 nids.py
```

---

## Sample Output

```
🛡️  Network Intrusion Detection System Starting...

[1/4] Loading packet capture and rules...
      → 30 packets loaded, 10 rules active

[2/4] Running detection engine...
      → 13 alerts generated

[ TRAFFIC SUMMARY ]
  Total Packets Analysed : 30
  Total Alerts Generated : 13
  CRITICAL               : 7
  HIGH                   : 2
  MEDIUM                 : 4

[ THREAT CATEGORIES DETECTED ]
  • MALWARE (4 alerts)
  • BOTNET (2 alerts)
  • EXPLOIT (1 alert)
  • RECONNAISSANCE (1 alert)
  • WEB ATTACK (2 alerts)
  • COMMAND & CONTROL (3 alerts)
```

---

## How It Works

1. **Packet Ingestion** — loads JSON-formatted packet capture data (simulating a `.pcap` file)
2. **Rule Engine** — runs 10 independent detection functions, each targeting a specific threat
3. **Alert Generation** — each match creates a structured alert with severity, category, IPs, and timestamp
4. **Reporting** — outputs a human-readable incident report and a machine-readable JSON file

---

## Detection Logic Explained

- **Port Scan**: groups packets by source IP + timestamp; flags IPs hitting 8+ ports per second
- **DNS Anomaly**: checks query length (tunnelling) and TLD reputation (C2 beaconing)
- **Malware Ports**: flags traffic on ports 4444 (Metasploit) and 1337 (RAT)
- **IRC Botnet**: detects IRC protocol keywords used by botnet C2 frameworks
- **Web Attacks**: regex matching against known SQL injection and XSS payloads
- **EternalBlue**: signature matching for MS17-010 SMB exploit (used by WannaCry)
- **Shell Commands**: detects `cmd.exe`, `whoami`, `/bin/bash` in packet payloads

---

## Extending This Project

- Connect to live traffic using `scapy` for real packet capture
- Add a Flask web dashboard to visualise alerts in real time
- Integrate with a SIEM (Splunk, ELK Stack)
- Add GeoIP lookups to map attacker origins
- Implement email/Slack alerting for CRITICAL threats
- Add more rules — ICMP flood, ARP spoofing, DNS rebinding

---

## Skills Demonstrated

- Python scripting & modular architecture
- Network protocol knowledge (TCP, UDP, DNS, SMB, IRC)
- Regex-based signature detection
- Threat intelligence & IOC matching
- Incident reporting & structured JSON output
- Security operations (SOC analyst mindset)
