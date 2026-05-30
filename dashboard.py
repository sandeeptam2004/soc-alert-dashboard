"""
dashboard.py
============
Runs a local web server and shows all alerts in a clean dashboard.

How to run:
    python dashboard.py
Then open your browser and go to:
    http://127.0.0.1:5000
"""

from flask import Flask, render_template_string
from log_parser import parse_logs, detect_threats, get_summary
import os

app = Flask(__name__)

# Path to the log file — change this if your log file is somewhere else
LOG_FILE = "sample_logs.log"


# ── HTML template (the web page) ──────────────────────────────────────────────
# This is the full HTML/CSS page that renders in the browser.
# We use Jinja2 {{ }} placeholders that Flask fills in with real data.

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Alert Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0f1117;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 24px;
    }

    /* ── Header ── */
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 28px;
    }
    .header h1 {
      font-size: 22px;
      font-weight: 600;
      color: #f1f5f9;
    }
    .header .subtitle {
      font-size: 13px;
      color: #64748b;
      margin-top: 2px;
    }
    .dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      background: #22c55e;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.3; }
    }

    /* ── Summary cards ── */
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }
    .card {
      background: #1e2130;
      border: 1px solid #2d3148;
      border-radius: 10px;
      padding: 16px;
    }
    .card .label {
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }
    .card .value {
      font-size: 28px;
      font-weight: 700;
    }
    .card.critical .value { color: #f87171; }
    .card.high     .value { color: #fb923c; }
    .card.medium   .value { color: #facc15; }
    .card.total    .value { color: #60a5fa; }
    .card.events   .value { color: #a78bfa; }

    /* ── Alert table ── */
    .section-title {
      font-size: 15px;
      font-weight: 600;
      color: #cbd5e1;
      margin-bottom: 12px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #1e2130;
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid #2d3148;
    }
    thead { background: #161825; }
    th {
      padding: 12px 16px;
      text-align: left;
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid #2d3148;
    }
    td {
      padding: 12px 16px;
      font-size: 13px;
      border-bottom: 1px solid #1a1d2e;
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #252840; }

    /* Severity badges */
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.04em;
    }
    .badge.CRITICAL { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .badge.HIGH     { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
    .badge.MEDIUM   { background: #422006; color: #facc15; border: 1px solid #713f12; }

    /* Threat type colors */
    .type-brute    { color: #fb923c; }
    .type-scan     { color: #facc15; }
    .type-process  { color: #f87171; }
    .type-exfil    { color: #f87171; }

    .mitre {
      font-size: 11px;
      color: #60a5fa;
      font-family: monospace;
    }
    .ip { font-family: monospace; color: #a78bfa; }
    .time-col { font-family: monospace; font-size: 12px; color: #64748b; }

    /* No alerts state */
    .empty {
      text-align: center;
      padding: 40px;
      color: #64748b;
      font-size: 14px;
    }

    .footer {
      margin-top: 24px;
      font-size: 12px;
      color: #334155;
      text-align: center;
    }
  </style>
</head>
<body>

  <!-- Header -->
  <div class="header">
    <div class="dot"></div>
    <div>
      <h1>SOC Alert Dashboard</h1>
      <div class="subtitle">Log file: {{ log_file }} &nbsp;|&nbsp; Built by Sandeepta Mahanta</div>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="summary">
    <div class="card events">
      <div class="label">Total Events</div>
      <div class="value">{{ summary.total_events }}</div>
    </div>
    <div class="card total">
      <div class="label">Alerts Raised</div>
      <div class="value">{{ summary.total_alerts }}</div>
    </div>
    <div class="card critical">
      <div class="label">Critical</div>
      <div class="value">{{ summary.critical }}</div>
    </div>
    <div class="card high">
      <div class="label">High</div>
      <div class="value">{{ summary.high }}</div>
    </div>
    <div class="card medium">
      <div class="label">Medium</div>
      <div class="value">{{ summary.medium }}</div>
    </div>
  </div>

  <!-- Alerts table -->
  <div class="section-title">Active Alerts</div>

  {% if alerts %}
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Severity</th>
        <th>Threat Type</th>
        <th>Source IP</th>
        <th>Details</th>
        <th>MITRE ATT&CK</th>
      </tr>
    </thead>
    <tbody>
      {% for alert in alerts %}
      <tr>
        <td class="time-col">{{ alert.time }}</td>
        <td><span class="badge {{ alert.severity }}">{{ alert.severity }}</span></td>
        <td>
          {% if alert.type == "Brute Force" %}
            <span class="type-brute">&#9632; {{ alert.type }}</span>
          {% elif alert.type == "Port Scan" %}
            <span class="type-scan">&#9632; {{ alert.type }}</span>
          {% else %}
            <span class="type-process">&#9632; {{ alert.type }}</span>
          {% endif %}
        </td>
        <td class="ip">{{ alert.src_ip }}</td>
        <td>{{ alert.detail }}</td>
        <td class="mitre">{{ alert.mitre }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No threats detected. All systems normal.</div>
  {% endif %}

  <div class="footer">
    SOC Alert Dashboard &mdash; github.com/sandeepta2004/soc-alert-dashboard
  </div>

</body>
</html>
"""


@app.route("/")
def index():
    """
    This function runs when someone visits http://127.0.0.1:5000
    It reads the log file, runs the parser, and sends data to the HTML page.
    """
    # Step 1: Read and parse the log file
    parsed = parse_logs(LOG_FILE)

    # Step 2: Detect threats in the parsed logs
    alerts = detect_threats(parsed)

    # Step 3: Build summary numbers for the cards at the top
    summary = get_summary(parsed, alerts)

    # Step 4: Send everything to the HTML template
    return render_template_string(
        HTML_TEMPLATE,
        alerts=alerts,
        summary=summary,
        log_file=LOG_FILE,
    )


if __name__ == "__main__":
    print("\n  SOC Alert Dashboard")
    print("  -------------------")
    print(f"  Reading log file : {LOG_FILE}")
    print("  Starting server  : http://127.0.0.1:5000")
    print("  Press CTRL+C to stop\n")
    app.run(debug=True)
