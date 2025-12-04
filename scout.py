#!/usr/bin/env python3
"""
net-scout: a one-shot scanner that analyzes net_sentinel.db for suspicious activity.

Usage:
  cd net-sentinel/net-scout
  python3 scout.py --help

Examples:
  python3 scout.py --since "1 hour"            # scan last 1 hour
  python3 scout.py --enrich                    # run enrichment for detected alerts
  python3 scout.py --dry-run                   # show alerts but don't insert
"""

import os
import sys
import sqlite3
import json
import argparse
import datetime
import hashlib
import subprocess
import socket
import time
from typing import List, Dict, Any

# Defaults (can be moved to config.py later)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "net_sentinel.db")
ALERT_TABLE = "scout_alerts"

# Detection thresholds (tunable)
HORIZONTAL_DST_IP_THRESHOLD = 50      # distinct dst IPs in window => horizontal scan
HORIZONTAL_CONN_THRESHOLD = 200       # total connections in window => horizontal scan
VERTICAL_PORTS_THRESHOLD = 50         # distinct dst ports to same dst_ip => vertical scan
REPEATED_CONN_THRESHOLD = 200         # repeated connections from same src to many dsts

# Helper: produce a UTC ISO string ending with Z
def to_utc_z(dt: datetime.datetime) -> str:
    # ensure timezone-aware, convert to UTC, then format with trailing Z
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt_utc = dt.astimezone(datetime.timezone.utc)
    return dt_utc.isoformat().replace("+00:00", "Z")

# Helper: parse human-friendly --since like "1 hour", "30 minutes", "24h"
def parse_since_arg(s: str) -> str:
    # returns an SQLite-compatible datetime string (UTC with trailing Z)
    now = datetime.datetime.now(datetime.timezone.utc)
    if not s:
        dt = now - datetime.timedelta(hours=1)
        return to_utc_z(dt)
    s = s.strip().lower()
    try:
        if s.endswith("h") or "hour" in s:
            n = int(''.join(filter(str.isdigit, s)) or 1)
            dt = now - datetime.timedelta(hours=n)
        elif s.endswith("m") or "min" in s:
            n = int(''.join(filter(str.isdigit, s)) or 30)
            dt = now - datetime.timedelta(minutes=n)
        elif s.endswith("d") or "day" in s:
            n = int(''.join(filter(str.isdigit, s)) or 1)
            dt = now - datetime.timedelta(days=n)
        else:
            # try to parse ISO timestamp (allow trailing Z)
            try:
                parsed = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
                dt = parsed.astimezone(datetime.timezone.utc)
            except Exception:
                # fallback to 1 hour
                dt = now - datetime.timedelta(hours=1)
    except Exception:
        dt = now - datetime.timedelta(hours=1)
    return to_utc_z(dt)

# DB migration: create alerts table and unique index (idempotent)
def ensure_alerts_table(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {ALERT_TABLE} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        score INTEGER DEFAULT 0,
        evidence_json TEXT,
        enrichment_json TEXT,
        status TEXT DEFAULT 'new',
        created_at TEXT NOT NULL
    );
    """)
    # Unique index to avoid duplicate alerts for same src/dst/type within same day
    cur.execute(f"""
    CREATE UNIQUE INDEX IF NOT EXISTS ux_{ALERT_TABLE}_unique
    ON {ALERT_TABLE} (alert_type, src_ip, dst_ip, date(created_at));
    """)
    conn.commit()

# Insert alert (idempotent via unique index)
def insert_alert(conn: sqlite3.Connection, alert: Dict[str, Any], dry_run=False):
    now = to_utc_z(datetime.datetime.now(datetime.timezone.utc))
    evidence = json.dumps(alert.get("evidence", {}))
    enrichment = json.dumps(alert.get("enrichment", {})) if alert.get("enrichment") else None
    if dry_run:
        print("[DRY RUN] Alert:", alert["alert_type"], alert.get("src_ip"), alert.get("dst_ip"), "score=", alert.get("score"))
        print("  evidence:", evidence)
        return
    cur = conn.cursor()
    try:
        cur.execute(f"""
        INSERT OR IGNORE INTO {ALERT_TABLE}
        (alert_type, src_ip, dst_ip, score, evidence_json, enrichment_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("alert_type"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            int(alert.get("score", 0)),
            evidence,
            enrichment,
            now
        ))
        conn.commit()
        if cur.rowcount:
            print("[INSERTED] ", alert.get("alert_type"), alert.get("src_ip"), alert.get("dst_ip"))
        else:
            print("[SKIPPED - duplicate] ", alert.get("alert_type"), alert.get("src_ip"), alert.get("dst_ip"))
    except Exception as e:
        print("[ERROR] inserting alert:", e)

# Simple enrichment helpers (best-effort, optional)
def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def run_traceroute(ip: str, max_hops=20, timeout=10):
    # Try traceroute (Unix) or tracert (Windows)
    try:
        if sys.platform.startswith("win"):
            cmd = ["tracert", "-d", ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or proc.stderr or ""
        return out.strip()[:20000]
    except Exception as e:
        return f"traceroute error: {e}"

def run_whois(ip_or_domain: str):
    # Try system whois if available; otherwise return None
    try:
        proc = subprocess.run(["whois", ip_or_domain], capture_output=True, text=True, timeout=8)
        out = proc.stdout or proc.stderr or ""
        return out.strip()[:20000]
    except Exception:
        return None

# Detection rules (SQL-based). Each returns list of alert dicts.
def detect_horizontal_scans(conn: sqlite3.Connection, since_iso: str) -> List[Dict[str,Any]]:
    q = f"""
    SELECT src_ip,
           COUNT(DISTINCT dst_ip) AS dst_count,
           COUNT(*) AS conn_count
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip
    HAVING dst_count > ? OR conn_count > ?
    ORDER BY dst_count DESC, conn_count DESC
    LIMIT 200;
    """
    cur = conn.execute(q, (since_iso, HORIZONTAL_DST_IP_THRESHOLD, HORIZONTAL_CONN_THRESHOLD))
    alerts = []
    for row in cur.fetchall():
        src_ip, dst_count, conn_count = row
        alerts.append({
            "alert_type": "horizontal_scan",
            "src_ip": src_ip,
            "dst_ip": None,
            "score": int(min(100, dst_count + conn_count//10)),
            "evidence": {"dst_count": dst_count, "conn_count": conn_count, "since": since_iso}
        })
    return alerts

def detect_vertical_scans(conn: sqlite3.Connection, since_iso: str) -> List[Dict[str,Any]]:
    q = f"""
    SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) AS ports
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip, dst_ip
    HAVING ports > ?
    ORDER BY ports DESC
    LIMIT 200;
    """
    cur = conn.execute(q, (since_iso, VERTICAL_PORTS_THRESHOLD))
    alerts = []
    for row in cur.fetchall():
        src_ip, dst_ip, ports = row
        alerts.append({
            "alert_type": "vertical_scan",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "score": int(min(100, ports)),
            "evidence": {"ports": ports, "since": since_iso}
        })
    return alerts

def detect_repeated_connections(conn: sqlite3.Connection, since_iso: str) -> List[Dict[str,Any]]:
    q = f"""
    SELECT src_ip, COUNT(*) AS total_conns
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip
    HAVING total_conns > ?
    ORDER BY total_conns DESC
    LIMIT 200;
    """
    cur = conn.execute(q, (since_iso, REPEATED_CONN_THRESHOLD))
    alerts = []
    for row in cur.fetchall():
        src_ip, total_conns = row
        alerts.append({
            "alert_type": "high_connection_volume",
            "src_ip": src_ip,
            "dst_ip": None,
            "score": int(min(100, total_conns//2)),
            "evidence": {"total_conns": total_conns, "since": since_iso}
        })
    return alerts

# Run detection and optional enrichment
def run_scan(args):
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] DB not found at {DB_PATH}")
        sys.exit(1)

    since_iso = parse_since_arg(args.since)
    print(f"[INFO] scanning since {since_iso}")

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # Only create/migrate alerts table if not running in dry-run mode.
    if not args.dry_run:
        ensure_alerts_table(conn)
    else:
        print("[INFO] dry-run: skipping alerts table migration (no writes will be performed)")

    all_alerts = []
    # Run rules
    all_alerts.extend(detect_horizontal_scans(conn, since_iso))
    all_alerts.extend(detect_vertical_scans(conn, since_iso))
    all_alerts.extend(detect_repeated_connections(conn, since_iso))

    print(f"[INFO] {len(all_alerts)} candidate alerts detected")

    # Enrich and insert
    for a in all_alerts:
        # Basic enrichment: reverse DNS for src/dst
        enrichment = {}
        if args.enrich:
            if a.get("src_ip"):
                enrichment["src_rdns"] = reverse_dns(a["src_ip"])
            if a.get("dst_ip"):
                enrichment["dst_rdns"] = reverse_dns(a["dst_ip"])
            # whois and traceroute are best-effort and can be slow
            if a.get("src_ip"):
                enrichment["src_whois"] = run_whois(a["src_ip"])
                enrichment["src_traceroute"] = run_traceroute(a["src_ip"])
            if a.get("dst_ip"):
                enrichment["dst_whois"] = run_whois(a["dst_ip"])
                enrichment["dst_traceroute"] = run_traceroute(a["dst_ip"])
            # small sleep to be polite if many lookups
            time.sleep(0.2)
            a["enrichment"] = enrichment

        insert_alert(conn, a, dry_run=args.dry_run)

    conn.close()
    print("[DONE] scan complete")

def main():
    p = argparse.ArgumentParser(description="net-scout: scan net_sentinel.db for suspicious activity")
    p.add_argument("--since", type=str, default="1 hour", help="Time window to scan (e.g., '1 hour', '30 minutes', or ISO timestamp)")
    p.add_argument("--enrich", action="store_true", help="Run enrichment (reverse DNS, whois, traceroute) for detected alerts")
    p.add_argument("--dry-run", action="store_true", help="Do not insert alerts; just print them")
    args = p.parse_args()
    run_scan(args)

if __name__ == "__main__":
    main()
