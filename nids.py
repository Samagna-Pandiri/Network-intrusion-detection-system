#!/usr/bin/env python3
"""
=============================================================
  NETWORK INTRUSION DETECTION SYSTEM (NIDS)
  Author: Samagna Pandiri
  Description: Analyses network packet captures to detect
               intrusion attempts, malware, exploits, and
               suspicious network behaviour — mirroring
               real-world SOC analyst tooling (like Snort).
=============================================================
"""

import json
import re
import os
from collections import defaultdict
from datetime import datetime


# ─────────────────────────────────────────────
#  COLOUR OUTPUT
# ─────────────────────────────────────────────
class C:
    RED      = "\033[91m"
    ORANGE   = "\033[33m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    MAGENTA  = "\033[95m"
    BOLD     = "\033[1m"
    RESET    = "\033[0m"

SEVERITY_COLOUR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.ORANGE + C.BOLD,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "INFO":     C.CYAN
}


# ─────────────────────────────────────────────
#  STEP 1: LOAD DATA
# ─────────────────────────────────────────────
def load_packets(filepath: str) -> list[dict]:
    """Load simulated packet capture from JSON file."""
    with open(filepath) as f:
        return json.load(f)

def load_rules(filepath: str) -> dict:
    """Load detection rules — keyed by rule ID."""
    with open(filepath) as f:
        data = json.load(f)
    return {r["id"]: r for r in data["rules"]}


# ─────────────────────────────────────────────
#  STEP 2: DETECTION ENGINE
#  Each function checks for one threat type.
#  Returns a list of alert dicts if triggered.
# ─────────────────────────────────────────────

def detect_port_scan(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-001: Port Scan Detection
    If one IP hits 8+ different ports in the same second → likely scanning.
    Attackers do this to find open services before exploiting them.
    """
    alerts = []
    # Group: src_ip → timestamp → set of destination ports
    scan_map = defaultdict(lambda: defaultdict(set))

    for pkt in packets:
        ts  = pkt["timestamp"][:19]   # trim to second precision
        scan_map[pkt["src_ip"]][ts].add(pkt["dst_port"])

    for ip, time_buckets in scan_map.items():
        for ts, ports in time_buckets.items():
            if len(ports) >= 8:
                rule = rules["RULE-001"]
                alerts.append({
                    "rule_id":   "RULE-001",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    ip,
                    "dst_ip":    "multiple",
                    "timestamp": ts,
                    "detail":    f"{ip} scanned {len(ports)} ports at {ts}: {sorted(ports)}"
                })
    return alerts


def detect_suspicious_dns(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-002 & RULE-008: DNS Anomaly Detection
    - Long subdomains = possible DNS tunnelling (data exfiltration over DNS)
    - Queries to suspicious TLDs (.ru, .cc, .pw, .tk) = possible C2 beaconing
    Malware often uses DNS to talk to command-and-control servers.
    """
    alerts = []
    suspicious_tlds = (".ru", ".cc", ".pw", ".tk", ".xyz", ".top")

    for pkt in packets:
        if pkt["dst_port"] != 53:
            continue
        payload = pkt.get("payload", "")
        if "DNS QUERY:" not in payload:
            continue

        domain = payload.replace("DNS QUERY:", "").strip()
        subdomain = domain.split(".")[0]

        # Long subdomain = DNS tunnelling
        if len(subdomain) > 30:
            rule = rules["RULE-002"]
            alerts.append({
                "rule_id":   "RULE-002",
                "severity":  rule["severity"],
                "category":  rule["category"],
                "name":      rule["name"],
                "src_ip":    pkt["src_ip"],
                "dst_ip":    pkt["dst_ip"],
                "timestamp": pkt["timestamp"],
                "detail":    f"Suspicious DNS query — long subdomain detected: {domain}"
            })

        # Suspicious TLD
        elif any(domain.endswith(tld) for tld in suspicious_tlds):
            rule = rules["RULE-008"]
            alerts.append({
                "rule_id":   "RULE-008",
                "severity":  rule["severity"],
                "category":  rule["category"],
                "name":      rule["name"],
                "src_ip":    pkt["src_ip"],
                "dst_ip":    pkt["dst_ip"],
                "timestamp": pkt["timestamp"],
                "detail":    f"DNS query to suspicious TLD: {domain}"
            })

    return alerts


def detect_malware_ports(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-003: Known Malware Port Detection
    Port 4444 = Metasploit default reverse shell
    Port 1337 = Common backdoor/RAT port
    Seeing traffic here almost always = compromise.
    """
    alerts = []
    malware_ports = {4444: "Metasploit reverse shell", 1337: "backdoor/RAT"}

    for pkt in packets:
        for port, label in malware_ports.items():
            if pkt["dst_port"] == port or pkt["src_port"] == port:
                rule = rules["RULE-003"]
                alerts.append({
                    "rule_id":   "RULE-003",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"Traffic on port {port} ({label}) between {pkt['src_ip']} → {pkt['dst_ip']}"
                })
    return alerts


def detect_irc_botnet(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-004: IRC Botnet C2 Detection
    Port 6667 = IRC protocol. Botnets use IRC channels as command centres.
    Keywords like JOIN, NICK, PRIVMSG = classic botnet chatter.
    """
    alerts = []
    irc_keywords = ["JOIN #", "NICK ", "PRIVMSG ", "PART #", "botnet"]

    for pkt in packets:
        if pkt.get("dst_port") == 6667 or pkt.get("src_port") == 6667:
            payload = pkt.get("payload", "")
            if any(kw.lower() in payload.lower() for kw in irc_keywords):
                rule = rules["RULE-004"]
                alerts.append({
                    "rule_id":   "RULE-004",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"IRC botnet C2 traffic detected — payload: '{payload[:60]}'"
                })
    return alerts


def detect_web_attacks(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-005 & RULE-006: Web Attack Detection
    SQL Injection: payloads with ' --, UNION SELECT, OR 1=1, etc.
    XSS: payloads with <script>, javascript:, onerror= etc.
    """
    alerts = []

    sql_patterns = [r"'\s*--", r"UNION\s+SELECT", r"OR\s+1\s*=\s*1",
                    r"DROP\s+TABLE", r"INSERT\s+INTO", r"admin'\s*--"]
    xss_patterns = [r"<script", r"javascript:", r"onerror\s*=",
                    r"alert\s*\(", r"onload\s*=", r"<img\s+src"]

    for pkt in packets:
        payload = pkt.get("payload", "")
        if not payload or pkt["dst_port"] not in (80, 8080, 443):
            continue

        # SQL Injection check
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                rule = rules["RULE-005"]
                alerts.append({
                    "rule_id":   "RULE-005",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"SQL injection pattern detected in HTTP request from {pkt['src_ip']}"
                })
                break

        # XSS check
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                rule = rules["RULE-006"]
                alerts.append({
                    "rule_id":   "RULE-006",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"XSS pattern detected in HTTP request from {pkt['src_ip']}"
                })
                break

    return alerts


def detect_eternalblue(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-007: EternalBlue SMB Exploit Detection
    MS17-010 = the NSA exploit used by WannaCry ransomware.
    Triggered by SMB traffic on port 445 containing exploit signatures.
    """
    alerts = []
    signatures = ["MS17-010", "EternalBlue", "ETERNALBLUE"]

    for pkt in packets:
        if pkt.get("dst_port") == 445:
            payload = pkt.get("payload", "")
            if any(sig in payload for sig in signatures):
                rule = rules["RULE-007"]
                alerts.append({
                    "rule_id":   "RULE-007",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"EternalBlue exploit attempt (MS17-010) detected: {pkt['src_ip']} → {pkt['dst_ip']}"
                })
    return alerts


def detect_shell_commands(packets: list[dict], rules: dict) -> list[dict]:
    """
    RULE-010: Shell Command in Payload
    Finding cmd.exe or /bin/sh in traffic = likely remote code execution.
    This is what happens after a successful exploit — attacker runs commands.
    """
    alerts = []
    shell_patterns = ["cmd.exe", "/bin/bash", "/bin/sh", "powershell",
                      "whoami", "net user", "passwd"]

    for pkt in packets:
        payload = pkt.get("payload", "")
        for pattern in shell_patterns:
            if pattern.lower() in payload.lower():
                rule = rules["RULE-010"]
                alerts.append({
                    "rule_id":   "RULE-010",
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "name":      rule["name"],
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "timestamp": pkt["timestamp"],
                    "detail":    f"Shell command '{pattern}' found in packet payload — possible RCE"
                })
                break
    return alerts


# ─────────────────────────────────────────────
#  STEP 3: RUN ALL DETECTION RULES
# ─────────────────────────────────────────────
def run_all_detectors(packets: list[dict], rules: dict) -> list[dict]:
    """Run every detector and combine all alerts."""
    all_alerts = []
    all_alerts += detect_port_scan(packets, rules)
    all_alerts += detect_suspicious_dns(packets, rules)
    all_alerts += detect_malware_ports(packets, rules)
    all_alerts += detect_irc_botnet(packets, rules)
    all_alerts += detect_web_attacks(packets, rules)
    all_alerts += detect_eternalblue(packets, rules)
    all_alerts += detect_shell_commands(packets, rules)

    # Sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_alerts.sort(key=lambda a: order.get(a["severity"], 99))
    return all_alerts


# ─────────────────────────────────────────────
#  STEP 4: GENERATE REPORT
# ─────────────────────────────────────────────
def generate_report(packets: list[dict], alerts: list[dict]) -> str:
    """Build a structured incident report."""
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1

    lines = []
    lines.append("=" * 65)
    lines.append("      NETWORK INTRUSION DETECTION SYSTEM — REPORT")
    lines.append(f"      Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)
    lines.append("")
    lines.append("[ TRAFFIC SUMMARY ]")
    lines.append(f"  Total Packets Analysed : {len(packets)}")
    lines.append(f"  Total Alerts Generated : {len(alerts)}")
    lines.append(f"  CRITICAL               : {counts['CRITICAL']}")
    lines.append(f"  HIGH                   : {counts['HIGH']}")
    lines.append(f"  MEDIUM                 : {counts['MEDIUM']}")
    lines.append("")

    # Group alerts by category
    by_category = defaultdict(list)
    for a in alerts:
        by_category[a["category"]].append(a)

    lines.append("[ THREAT CATEGORIES DETECTED ]")
    for cat, cat_alerts in by_category.items():
        lines.append(f"  • {cat} ({len(cat_alerts)} alert{'s' if len(cat_alerts)>1 else ''})")
    lines.append("")

    lines.append("[ DETAILED ALERTS ]")
    for i, alert in enumerate(alerts, 1):
        lines.append(f"\n  [{i}] [{alert['severity']}] {alert['name']}  ({alert['rule_id']})")
        lines.append(f"      Category  : {alert['category']}")
        lines.append(f"      Source IP : {alert['src_ip']}")
        lines.append(f"      Dest IP   : {alert['dst_ip']}")
        lines.append(f"      Time      : {alert['timestamp']}")
        lines.append(f"      Detail    : {alert['detail']}")

    lines.append("")
    lines.append("[ RECOMMENDED ACTIONS ]")
    if counts["CRITICAL"] > 0:
        lines.append("  !! CRITICAL threats found — isolate affected hosts immediately")
        lines.append("  !! Block source IPs at firewall")
        lines.append("  !! Escalate to incident response team")
    if counts["HIGH"] > 0:
        lines.append("  !  HIGH alerts — investigate source IPs, review firewall rules")
    if counts["MEDIUM"] > 0:
        lines.append("  ~  MEDIUM alerts — monitor and review within 24 hours")

    lines.append("")
    lines.append("=" * 65)
    lines.append("  END OF REPORT")
    lines.append("=" * 65)
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    PACKET_FILE  = "captures/sample_traffic.json"
    RULES_FILE   = "rules/detection_rules.json"
    REPORT_TXT   = "reports/nids_report.txt"
    ALERTS_JSON  = "alerts/alerts.json"

    os.makedirs("reports", exist_ok=True)
    os.makedirs("alerts", exist_ok=True)

    print(f"\n{C.CYAN}{C.BOLD}  🛡️  Network Intrusion Detection System Starting...{C.RESET}\n")

    # Load
    print(f"{C.CYAN}  [1/4] Loading packet capture and rules...{C.RESET}")
    packets = load_packets(PACKET_FILE)
    rules   = load_rules(RULES_FILE)
    print(f"        → {len(packets)} packets loaded, {len(rules)} rules active\n")

    # Detect
    print(f"{C.CYAN}  [2/4] Running detection engine...{C.RESET}")
    alerts = run_all_detectors(packets, rules)
    print(f"        → {len(alerts)} alerts generated\n")

    # Text report
    print(f"{C.CYAN}  [3/4] Generating incident report...{C.RESET}")
    report = generate_report(packets, alerts)
    with open(REPORT_TXT, "w") as f:
        f.write(report)
    print(f"        → Saved to {REPORT_TXT}\n")

    # JSON alerts
    print(f"{C.CYAN}  [4/4] Exporting JSON alerts...{C.RESET}")
    json_out = {
        "generated_at": datetime.now().isoformat(),
        "total_packets": len(packets),
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open(ALERTS_JSON, "w") as f:
        json.dump(json_out, f, indent=2)
    print(f"        → Saved to {ALERTS_JSON}\n")

    # Print report
    print(report)

    # Final summary with colour
    crit = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    if crit > 0:
        print(f"\n{C.RED}{C.BOLD}  🚨 {crit} CRITICAL threat(s) detected! Immediate action required.{C.RESET}\n")
    else:
        print(f"\n{C.GREEN}  ✅ No critical threats.{C.RESET}\n")


if __name__ == "__main__":
    main()
