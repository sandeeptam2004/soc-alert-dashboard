"""
log_parser.py
=============
Reads a .log file line by line and detects security threats.

Threats we detect:
  - Brute Force   : 5+ failed logins from the same IP
  - Port Scan     : any PORT_SCAN event
  - Suspicious    : known bad process names (mimikatz, etc.)
  - Exfiltration  : large data transfers out
"""

import re
from collections import defaultdict
from datetime import datetime


# ── Threat rules ─────────────────────────────────────────────────────────────

# If an IP fails login this many times → brute force alert
BRUTE_FORCE_THRESHOLD = 5

# Process names that are always suspicious
MALICIOUS_PROCESSES = ["mimikatz", "pwdump", "meterpreter", "netcat", "nc.exe"]

# Data transfer above this size (bytes) is suspicious (~50 MB)
EXFIL_THRESHOLD_BYTES = 50_000_000

# MITRE ATT&CK mapping for each threat type
MITRE_MAP = {
    "Brute Force":      "T1110 - Brute Force",
    "Port Scan":        "T1046 - Network Service Scanning",
    "Suspicious Process": "T1055 - Process Injection / Malicious Tool",
    "Data Exfiltration": "T1041 - Exfiltration Over C2 Channel",
}


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_logs(filepath):
    """
    Opens the log file and reads every line.
    Returns a list of parsed log dictionaries.
    """
    parsed = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Every line starts with: DATE TIME EVENT_TYPE key=value key=value ...
            parts = line.split(" ", 3)          # split into max 4 parts
            if len(parts) < 3:
                continue

            date_str  = parts[0]               # e.g. 2026-05-30
            time_str  = parts[1]               # e.g. 01:12:03
            event     = parts[2]               # e.g. FAILED_LOGIN
            rest      = parts[3] if len(parts) > 3 else ""

            # Parse the key=value pairs at the end of each line
            fields = {}
            for match in re.finditer(r'(\w+)=([\S]+)', rest):
                fields[match.group(1)] = match.group(2)

            parsed.append({
                "timestamp": f"{date_str} {time_str}",
                "event":     event,
                "fields":    fields,
                "raw":       line,
            })

    return parsed


def detect_threats(parsed_logs):
    """
    Looks through all parsed log entries and builds a list of alerts.
    Each alert is a dictionary with: time, threat type, severity, details, MITRE tag.
    """
    alerts    = []
    # Track how many times each IP fails a login
    fail_count = defaultdict(int)
    # Track which IPs we've already raised a brute force alert for
    bf_alerted = set()

    for entry in parsed_logs:
        event  = entry["event"]
        fields = entry["fields"]
        ts     = entry["timestamp"]

        # ── 1. Failed login tracking ──────────────────────────────────────────
        if event == "FAILED_LOGIN":
            ip = fields.get("src_ip", "unknown")
            fail_count[ip] += 1

            # Raise alert the moment threshold is crossed (only once per IP)
            if fail_count[ip] == BRUTE_FORCE_THRESHOLD and ip not in bf_alerted:
                bf_alerted.add(ip)
                alerts.append({
                    "time":     ts,
                    "type":     "Brute Force",
                    "severity": "HIGH",
                    "src_ip":   ip,
                    "detail":   f"{fail_count[ip]}+ failed logins | user={fields.get('user','?')} | dst={fields.get('dst','?')}",
                    "mitre":    MITRE_MAP["Brute Force"],
                })

        # ── 2. Port scan ──────────────────────────────────────────────────────
        elif event == "PORT_SCAN":
            ip    = fields.get("src_ip", "unknown")
            ports = fields.get("ports_scanned", "?")
            alerts.append({
                "time":     ts,
                "type":     "Port Scan",
                "severity": "MEDIUM",
                "src_ip":   ip,
                "detail":   f"Ports scanned: {ports} | target={fields.get('dst','?')}",
                "mitre":    MITRE_MAP["Port Scan"],
            })

        # ── 3. Suspicious process ─────────────────────────────────────────────
        elif event == "SUSPICIOUS_PROCESS":
            process = fields.get("process", "").lower()
            if any(bad in process for bad in MALICIOUS_PROCESSES):
                alerts.append({
                    "time":     ts,
                    "type":     "Suspicious Process",
                    "severity": "CRITICAL",
                    "src_ip":   fields.get("src_ip", "unknown"),
                    "detail":   f"Process={fields.get('process','?')} | user={fields.get('user','?')} | host={fields.get('dst','?')}",
                    "mitre":    MITRE_MAP["Suspicious Process"],
                })

        # ── 4. Data exfiltration ──────────────────────────────────────────────
        elif event == "DATA_EXFILTRATION":
            try:
                size_bytes = int(fields.get("bytes", 0))
            except ValueError:
                size_bytes = 0

            if size_bytes >= EXFIL_THRESHOLD_BYTES:
                size_mb = round(size_bytes / 1_000_000, 1)
                alerts.append({
                    "time":     ts,
                    "type":     "Data Exfiltration",
                    "severity": "CRITICAL",
                    "src_ip":   fields.get("src_ip", "unknown"),
                    "detail":   f"{size_mb} MB sent to {fields.get('dst_ip','?')} via {fields.get('protocol','?')}",
                    "mitre":    MITRE_MAP["Data Exfiltration"],
                })

    return alerts


def get_summary(parsed_logs, alerts):
    """
    Returns a simple summary dictionary for the dashboard header.
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for a in alerts:
        sev = a.get("severity", "MEDIUM")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "total_events": len(parsed_logs),
        "total_alerts": len(alerts),
        "critical":     severity_counts["CRITICAL"],
        "high":         severity_counts["HIGH"],
        "medium":       severity_counts["MEDIUM"],
    }
