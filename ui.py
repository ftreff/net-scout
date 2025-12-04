#!/usr/bin/env python3
"""
net-scout UI (Flask app) - updated with status, filters, enrichment cache, snooze, and bulk enrich.

Run from net-sentinel/net-scout:
  python3 ui.py

Open http://127.0.0.1:5001/netscout
"""

import os
import sys
import json
import sqlite3
import subprocess
import threading
import shlex
import time
import glob
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template, abort

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "net_sentinel.db")
SCOUT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scout.py")
ENRICH_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enrich.py")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
SCAN_LOG = os.path.join(LOG_DIR, "netscout_scan.log")

app = Flask(__name__, template_folder="templates", static_folder="static")

# -------------------------
# Helpers
# -------------------------
def utc_now_z():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def run_subprocess_async(cmd_args, out_file=None):
    def target():
        try:
            os.makedirs(os.path.dirname(out_file), exist_ok=True) if out_file else None
            with open(out_file, "a") if out_file else subprocess.DEVNULL as f:
                proc = subprocess.Popen(cmd_args, stdout=f, stderr=subprocess.STDOUT)
                proc.wait()
        except Exception as e:
            print("Subprocess error:", e)
    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t

def read_log_tail(path, max_lines=200):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0 and len(data.splitlines()) <= max_lines:
                size -= block
                if size < 0:
                    block += size
                    size = 0
                f.seek(size)
                data = f.read() + data
            lines = data.decode(errors="replace").splitlines()[-max_lines:]
            return lines
    except Exception:
        # fallback simple read
        try:
            with open(path, "r", errors="replace") as f:
                return f.read().splitlines()[-max_lines:]
        except Exception:
            return []

def find_running_tasks():
    """
    Best-effort detection of running scout/enrich tasks using pgrep.
    Returns dict with booleans and PIDs list.
    """
    tasks = {"scan_running": False, "scan_pids": [], "enrich_running": False, "enrich_pids": []}
    try:
        # pgrep -f "scout.py"
        out = subprocess.run(["pgrep", "-f", "scout.py"], capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            pids = [int(x) for x in out.stdout.split()]
            tasks["scan_running"] = True
            tasks["scan_pids"] = pids
    except Exception:
        pass
    try:
        out = subprocess.run(["pgrep", "-f", "enrich.py"], capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            pids = [int(x) for x in out.stdout.split()]
            tasks["enrich_running"] = True
            tasks["enrich_pids"] = pids
    except Exception:
        pass
    return tasks

def parse_scan_log_for_progress(path):
    """
    Parse scan log to estimate progress:
    - look for 'scanning since' (start time)
    - look for 'candidate alerts detected' (total candidates)
    - count '[INSERTED]' or '[DRY RUN]' lines as processed
    - detect '[DONE] scan complete' as finished
    Return dict: {started_at, finished_at, total_candidates, processed, percent, est_remaining_seconds, last_lines}
    """
    lines = read_log_tail(path, max_lines=1000)
    started_at = None
    finished_at = None
    total_candidates = None
    processed = 0
    last_ts = None

    for ln in lines:
        if "scanning since" in ln:
            # try to extract ISO timestamp after 'scanning since'
            try:
                part = ln.split("scanning since", 1)[1].strip()
                # part may be like '2025-12-04T05:58:13.493566Z'
                started_at = part.split()[0].strip()
            except Exception:
                pass
        if "candidate alerts detected" in ln:
            try:
                # e.g., "[INFO] 19 candidate alerts detected"
                total_candidates = int(''.join(filter(str.isdigit, ln)))
            except Exception:
                pass
        if "[INSERTED]" in ln or "[DRY RUN] Alert:" in ln:
            processed += 1
        if "[DONE] scan complete" in ln:
            finished_at = True
        # try to parse timestamp at start of line if present (not guaranteed)
        # fallback: use file mtime
    # compute percent
    percent = 0
    est_remaining = None
    if finished_at:
        percent = 100
        est_remaining = 0
    else:
        if total_candidates:
            percent = int(min(95, (processed / max(1, total_candidates)) * 100))
            # estimate remaining: if processed>0, estimate time per processed from log timestamps not available reliably
            # best-effort: if file mtime and started_at available, estimate elapsed and remaining
            try:
                mtime = os.path.getmtime(path)
                elapsed = time.time() - mtime  # not accurate; fallback to 0
                # fallback: assume 1s per processed if processed>0
                if processed > 0:
                    est_remaining = int(max(0, (total_candidates - processed) * (elapsed / max(1, processed))))
                else:
                    est_remaining = None
            except Exception:
                est_remaining = None
        else:
            # no candidate info; if process running, show 50%
            tasks = find_running_tasks()
            if tasks.get("scan_running"):
                percent = 50
            else:
                percent = 0
    return {
        "started_at": started_at,
        "finished": bool(finished_at),
        "total_candidates": total_candidates,
        "processed": processed,
        "percent": percent,
        "est_remaining_seconds": est_remaining,
        "last_lines": lines[-20:]
    }

def parse_enrich_logs_for_progress(log_dir):
    """
    Look for netscout_enrich_*.log files and parse them for enrichment progress.
    We count 'enriched alert' occurrences and 'enrich started' markers.
    """
    files = glob.glob(os.path.join(log_dir, "netscout_enrich_*.log"))
    total_processed = 0
    total_started = 0
    last_lines = []
    for f in files:
        lines = read_log_tail(f, max_lines=500)
        last_lines.extend(lines[-20:])
        for ln in lines:
            if "[OK] enriched alert" in ln or "enriched alert" in ln:
                total_processed += 1
            if "Enriching alert" in ln or "enriching alert" in ln or "enrich_alert" in ln:
                total_started += 1
    percent = 0
    if total_started:
        percent = int(min(95, (total_processed / total_started) * 100))
    else:
        # if any enrich process running, show 50
        tasks = find_running_tasks()
        if tasks.get("enrich_running"):
            percent = 50
    return {
        "files": [os.path.basename(f) for f in files],
        "total_started": total_started,
        "total_processed": total_processed,
        "percent": percent,
        "last_lines": last_lines[-20:]
    }

# -------------------------
# DB helpers
# -------------------------
def fetch_alerts_from_db(since=None, limit=500, alert_type=None, src_ip=None, dst_ip=None, min_score=None):
    if not os.path.exists(DB_PATH):
        return {"error": f"DB not found at {DB_PATH}"}
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    q = "SELECT id, alert_type, src_ip, dst_ip, score, evidence_json, enrichment_json, status, created_at FROM scout_alerts"
    clauses = []
    params = []
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if alert_type:
        clauses.append("alert_type = ?")
        params.append(alert_type)
    if src_ip:
        clauses.append("(src_ip = ? OR src_ip LIKE ?)")
        params.append(src_ip)
        params.append(f"%{src_ip}%")
    if dst_ip:
        clauses.append("(dst_ip = ? OR dst_ip LIKE ?)")
        params.append(dst_ip)
        params.append(f"%{dst_ip}%")
    if min_score is not None:
        clauses.append("score >= ?")
        params.append(int(min_score))

    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = cur.execute(q, params).fetchall()
    alerts = []
    for r in rows:
        a = dict(r)
        try:
            a["evidence"] = json.loads(a.get("evidence_json") or "{}")
        except Exception:
            a["evidence"] = {}
        try:
            a["enrichment"] = json.loads(a.get("enrichment_json") or "{}")
        except Exception:
            a["enrichment"] = {}
        # attach lat/lon if available
        lat = lon = None
        ip_to_check = a.get("dst_ip") or a.get("src_ip")
        if ip_to_check:
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

# -------------------------
# API endpoints
# -------------------------
@app.route("/netscout")
def netscout_ui():
    return render_template("netscout.html")

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    since = request.args.get("since")
    limit = int(request.args.get("limit", "500"))
    alert_type = request.args.get("type")
    src_ip = request.args.get("src")
    dst_ip = request.args.get("dst")
    min_score = request.args.get("min_score")
    min_score = int(min_score) if min_score is not None and min_score != "" else None
    alerts = fetch_alerts_from_db(since=since, limit=limit, alert_type=alert_type, src_ip=src_ip, dst_ip=dst_ip, min_score=min_score)
    return jsonify({"alerts": alerts})

@app.route("/api/status", methods=["GET"])
def api_status():
    # Running tasks
    tasks = find_running_tasks()
    # Scan progress
    scan_progress = parse_scan_log_for_progress(SCAN_LOG)
    # Enrich progress
    enrich_progress = parse_enrich_logs_for_progress(LOG_DIR)
    # Last-run times: use file mtime of logs
    last_scan_mtime = None
    if os.path.exists(SCAN_LOG):
        last_scan_mtime = datetime.fromtimestamp(os.path.getmtime(SCAN_LOG), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    # last enrich file
    enrich_files = glob.glob(os.path.join(LOG_DIR, "netscout_enrich_*.log"))
    last_enrich_mtime = None
    if enrich_files:
        latest = max(enrich_files, key=os.path.getmtime)
        last_enrich_mtime = datetime.fromtimestamp(os.path.getmtime(latest), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return jsonify({
        "tasks": tasks,
        "scan_progress": scan_progress,
        "enrich_progress": enrich_progress,
        "last_scan_log": last_scan_mtime,
        "last_enrich_log": last_enrich_mtime
    })

@app.route("/api/run_scan", methods=["POST"])
def api_run_scan():
    data = request.get_json() or {}
    since = data.get("since", "1 hour")
    enrich = bool(data.get("enrich", False))
    dry_run = bool(data.get("dry_run", False))
    cmd = [sys.executable, SCOUT_SCRIPT, "--since", since]
    if enrich:
        cmd.append("--enrich")
    if dry_run:
        cmd.append("--dry-run")
    logpath = SCAN_LOG
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
    logpath = os.path.join(LOG_DIR, f"netscout_enrich_{alert_id}.log")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    run_subprocess_async(cmd, out_file=logpath)
    return jsonify({"status": "started", "cmd": " ".join(shlex.quote(p) for p in cmd), "log": logpath})

@app.route("/api/enrich_bulk", methods=["POST"])
def api_enrich_bulk():
    """
    Body: {"alert_ids": [1,2,3]} or {"limit": 20} to enrich newest N alerts
    """
    data = request.get_json() or {}
    alert_ids = data.get("alert_ids")
    limit = data.get("limit")
    if alert_ids:
        # run enrich.py for each id in background (one process per id)
        logs = []
        for aid in alert_ids:
            logpath = os.path.join(LOG_DIR, f"netscout_enrich_{aid}.log")
            cmd = [sys.executable, ENRICH_SCRIPT, "--alert-id", str(aid)]
            run_subprocess_async(cmd, out_file=logpath)
            logs.append(logpath)
        return jsonify({"status": "started", "logs": logs})
    elif limit:
        # run enrich.py --limit N (enrich.py supports --limit)
        cmd = [sys.executable, ENRICH_SCRIPT, "--limit", str(limit)]
        logpath = os.path.join(LOG_DIR, f"netscout_enrich_bulk_{int(time.time())}.log")
        run_subprocess_async(cmd, out_file=logpath)
        return jsonify({"status": "started", "log": logpath})
    else:
        return jsonify({"error": "alert_ids or limit required"}), 400

@app.route("/api/enrichment_cache", methods=["GET"])
def api_enrichment_cache():
    """
    Return rows from scout_enrichment_cache table (subject, kind, updated_at).
    """
    if not os.path.exists(DB_PATH):
        return jsonify({"error": f"DB not found at {DB_PATH}"}), 500
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT subject, kind, updated_at, result_json FROM scout_enrichment_cache ORDER BY updated_at DESC LIMIT 500;")
    rows = cur.fetchall()
    out = []
    for r in rows:
        subj, kind, updated_at, result_json = r
        try:
            parsed = json.loads(result_json) if result_json else None
        except Exception:
            parsed = result_json
        out.append({"subject": subj, "kind": kind, "updated_at": updated_at, "result": parsed})
    conn.close()
    return jsonify({"cache": out})

@app.route("/api/snooze_alert", methods=["POST"])
def api_snooze_alert():
    """
    Body: {"alert_id": 42, "action": "snooze"|"false_positive", "duration_minutes": 60}
    """
    data = request.get_json() or {}
    aid = data.get("alert_id")
    action = data.get("action", "snooze")
    duration = int(data.get("duration_minutes", 60))
    if not aid:
        return jsonify({"error": "alert_id required"}), 400
    if action not in ("snooze", "false_positive"):
        return jsonify({"error": "invalid action"}), 400

    if not os.path.exists(DB_PATH):
        return jsonify({"error": f"DB not found at {DB_PATH}"}), 500
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if action == "snooze":
        until = datetime.now(timezone.utc) + timedelta(minutes=duration)
        until_iso = until.isoformat().replace("+00:00", "Z")
        cur.execute("UPDATE scout_alerts SET status = ?, enrichment_json = COALESCE(enrichment_json, '') WHERE id = ?;", ("snoozed", aid))
    else:
        cur.execute("UPDATE scout_alerts SET status = ?, enrichment_json = COALESCE(enrichment_json, '') WHERE id = ?;", ("false_positive", aid))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "alert_id": aid, "action": action})

# -------------------------
# Enrichment UI page
# -------------------------
@app.route("/enrichment_cache")
def enrichment_cache_ui():
    return render_template("enrichment_cache.html")

# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    # Run on port 5001 to avoid conflict with net-sentinel if it runs on 5000
    app.run(host="127.0.0.1", port=5001, debug=False)
