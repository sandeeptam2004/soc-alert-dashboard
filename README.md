# SOC Alert Dashboard

A Python-based Security Operations Center (SOC) tool that **parses log files, detects security threats, and displays live alerts in a web dashboard** — built to simulate real L1 SOC analyst workflows.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![Flask](https://img.shields.io/badge/Flask-2.0+-green) ![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

---

## What it does

| Feature | Description |
|---|---|
| Log Parsing | Reads raw `.log` files line by line and extracts structured fields |
| Brute Force Detection | Alerts when an IP exceeds 5 failed logins (T1110) |
| Port Scan Detection | Flags any network scanning activity (T1046) |
| Suspicious Process | Detects known malicious tools like mimikatz (T1055) |
| Data Exfiltration | Alerts on large outbound transfers >50MB (T1041) |
| MITRE ATT&CK Mapping | Every alert tagged with the relevant technique ID |
| Web Dashboard | Clean dark-mode dashboard showing all alerts with severity |

---

## Dashboard preview

```
┌─────────────────────────────────────────────────────┐
│  ● SOC Alert Dashboard                              │
│  25 Events │ 6 Alerts │ 2 Critical │ 2 High │ 2 Med │
├──────────┬──────────┬────────────┬──────────────────┤
│ Time     │ Severity │ Type       │ MITRE            │
├──────────┼──────────┼────────────┼──────────────────┤
│ 01:12:11 │ HIGH     │ Brute Force│ T1110            │
│ 02:45:00 │ MEDIUM   │ Port Scan  │ T1046            │
│ 07:15:33 │ CRITICAL │ Susp. Proc │ T1055            │
│ 08:20:10 │ CRITICAL │ Data Exfil │ T1041            │
└──────────┴──────────┴────────────┴──────────────────┘
```

---

## Setup & run

```bash
# 1. Clone the repo
git clone https://github.com/sandeepta2004/soc-alert-dashboard.git
cd soc-alert-dashboard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the dashboard
python dashboard.py

# 4. Open your browser
# Go to: http://127.0.0.1:5000
```

---

## Project structure

```
soc-alert-dashboard/
├── dashboard.py       # Flask web server + HTML dashboard
├── log_parser.py      # Core parser and threat detection engine
├── sample_logs.log    # Sample log file with realistic attack scenarios
├── requirements.txt   # Python dependencies
└── README.md
```

---

## Log format supported

```
YYYY-MM-DD HH:MM:SS EVENT_TYPE key=value key=value ...
```

Example events:
```
2026-05-30 01:12:05 FAILED_LOGIN user=admin src_ip=192.168.1.105 dst=WIN-SERVER01
2026-05-30 02:45:00 PORT_SCAN src_ip=10.0.0.45 ports_scanned=135,139,445 dst=192.168.1.0/24
2026-05-30 07:15:33 SUSPICIOUS_PROCESS process=mimikatz.exe user=john src_ip=192.168.1.50
2026-05-30 08:20:10 DATA_EXFILTRATION src_ip=192.168.1.50 dst_ip=203.0.113.50 bytes=504857600
```

---

## Detection rules

| Threat | Trigger | Severity | MITRE |
|---|---|---|---|
| Brute Force | 5+ failed logins from same IP | HIGH | T1110 |
| Port Scan | Any PORT_SCAN event | MEDIUM | T1046 |
| Suspicious Process | Known malicious process names | CRITICAL | T1055 |
| Data Exfiltration | Outbound transfer > 50 MB | CRITICAL | T1041 |

---

## Skills demonstrated

- Python file I/O and regex parsing
- Security threat detection logic
- MITRE ATT&CK framework mapping
- Flask web framework
- SOC L1 alert triage concepts
- Log analysis and incident documentation

---

## Author

**Sandeepta Mahanta**
[LinkedIn](https://linkedin.com/in/sandeepta-mahanta) · [GitHub](https://github.com/sandeepta2004)

*Final-year B.Tech IT student | Aspiring SOC Analyst*
