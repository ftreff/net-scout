#!/usr/bin/env python3
"""
net-scout UI (one-shot Flask app)

Run from net-sentinel/net-scout:
  python3 ui.py

Then open http://127.0.0.1:5001 in your browser.

Endpoints:
- GET  /netscout            -> UI page
- GET  /api/alerts         -> JSON list of alerts (with optional ?since=1h)
- POST /api/run_scan       -> run scout.py (JSON body: {"since":"1 hour","enrich":false})
- POST /api/enrich_alert   -> run enrich.py for a specific alert id (JSON body: {"alert_id": 42})
- POST /api/clear_alerts   -> optional: clear alerts (dangerous; not enabled by default)
"""

import os
import sys
import json
import sqlite3
import subprocess
import threading
import shlex
from flask import Flask, jsonify, request, render_template, send_from_directory, abort

# Basic config: DB path one level up
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "net_sentinel.db")
SCOUT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scout.py")
ENRICH_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enrich.py")

app = Flask(__name__, template_folder="templates", static_folder="static")

# Helper: read alerts and attach lat/lon if available from ip_events
def fetch_alerts(since=None, limit=500):
    if not os.path.exists(DB_PATH):
        return {"error": f"DB not found at {DB_PATH}"}
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Basic alerts query
    q = "SELECT id, alert_type, src_ip, dst_ip, score, evidence_json, enrichment_json, status, created_at FROM scout_alerts"
    params = []
    if since:
        # filter by created_at >= since (expects ISO Z string or simple relative handled by client)
        q += " WHERE created_at >= ?"
        params.append(since)
    q += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = cur.execute(q, params).fetchall()
    alerts = []
    for r in rows:
        a = dict(r)
        # parse JSON fields
        try:
            a["evidence"] = json.loads(a.get("evidence_json") or "{}")
        except Exception:
            a["evidence"] = {}
        try:
            a["enrichment"] = json.loads(a.get("enrichment_json") or "{}")
        except Exception:
            a["enrichment"] = {}
        # Try to find coordinates: prefer dst_ip then src_ip in ip_events table
        lat = lon = None
        ip_to_check = a.get("dst_ip") or a.get("src_ip")
        if ip_to_check:
            # look up most recent ip_events row for that IP with lat/lon
            cur2 = conn.execute(
                "SELECT latitude, longitude FROM ip_events WHERE (src_ip = ? OR dst_ip = ?) AND latitude IS NOT NULL AND longitude IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
                (ip_to_check, ip_to_check)
            ).fetchone()
            if cur2:
                lat, lon = cur2[0], cur2[1]
        a["latitude"] = lat
        a["longitude"] = lon
        alerts.append(a)
    conn.close()
    return alerts

# Run a subprocess in a background thread and capture output to a file
def run_subprocess_async(cmd_args, out_file=None):
    def target():
        try:
            with open(out_file, "a") if out_file else subprocess.DEVNULL as f:
                proc = subprocess.Popen(cmd_args, stdout=f, stderr=subprocess.STDOUT)
                proc.wait()
        except Exception as e:
            print("Subprocess error:", e)
    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t

@app.route("/netscout")
def netscout_ui():
    return render_template("netscout.html")

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    since = request.args.get("since")  # optional ISO timestamp or empty
    limit = int(request.args.get("limit", "500"))
    alerts = fetch_alerts(since=since or None, limit=limit)
    return jsonify({"alerts": alerts})

@app.route("/api/run_scan", methods=["POST"])
def api_run_scan():
    data = request.get_json() or {}
    since = data.get("since", "1 hour")
    enrich = bool(data.get("enrich", False))
    dry_run = bool(data.get("dry_run", False))
    # Build command
    cmd = [sys.executable, SCOUT_SCRIPT, "--since", since]
    if enrich:
        cmd.append("--enrich")
    if dry_run:
        cmd.append("--dry-run")
    # Run async and return immediately
    logpath = os.path.join(os.path.dirname(DB_PATH), "logs", "netscout_scan.log")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    run_subprocess_async(cmd, out_file=logpath)
    return jsonify({"status": "started", "cmd": " ".join(shlex.quote(p) for p in cmd), "log": logpath})

@app.route("/api/enrich_alert", methods=["POST"])
def api_enrich_alert():
    data = request.get_json() or {}
    alert_id = data.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id required"}), 400
    cmd = [sys.executable, ENRICH_SCRIPT, "--alert-id", str(alert_id)]
    logpath = os.path.join(os.path.dirname(DB_PATH), "logs", f"netscout_enrich_{alert_id}.log")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    run_subprocess_async(cmd, out_file=logpath)
    return jsonify({"status": "started", "cmd": " ".join(shlex.quote(p) for p in cmd), "log": logpath})

@app.route("/api/refresh_alerts", methods=["GET"])
def api_refresh_alerts():
    # simple wrapper to return alerts (same as /api/alerts)
    return api_alerts()

# Serve static files (JS/CSS) from static folder automatically via Flask static route

if __name__ == "__main__":
    # Run on port 5001 to avoid conflict with net-sentinel if it runs on 5000
    app.run(host="127.0.0.1", port=5001, debug=False)
