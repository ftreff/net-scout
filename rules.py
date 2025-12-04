#!/usr/bin/env python3
"""
Detection rules for net-scout.

This module provides functions that accept a sqlite3.Connection and a
since_iso timestamp (UTC Z format) and return lists of alert dicts.

Alert dict format:
{
  "alert_type": "horizontal_scan" | "vertical_scan" | "high_connection_volume" | ...,
  "src_ip": "1.2.3.4" or None,
  "dst_ip": "5.6.7.8" or None,
  "score": int,
  "evidence": {...}
}
"""

from typing import List, Dict, Any
import sqlite3

# Try to import thresholds from config.py; fall back to sensible defaults
try:
    from config import (
        HORIZONTAL_DST_IP_THRESHOLD,
        HORIZONTAL_CONN_THRESHOLD,
        VERTICAL_PORTS_THRESHOLD,
        REPEATED_CONN_THRESHOLD,
        MAX_ALERTS_PER_RUN,
    )
except Exception:
    HORIZONTAL_DST_IP_THRESHOLD = 50
    HORIZONTAL_CONN_THRESHOLD = 200
    VERTICAL_PORTS_THRESHOLD = 50
    REPEATED_CONN_THRESHOLD = 200
    MAX_ALERTS_PER_RUN = 500

def detect_horizontal_scans(conn: sqlite3.Connection, since_iso: str, limit: int = 200) -> List[Dict[str, Any]]:
    q = f"""
    SELECT src_ip,
           COUNT(DISTINCT dst_ip) AS dst_count,
           COUNT(*) AS conn_count
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip
    HAVING dst_count > ? OR conn_count > ?
    ORDER BY dst_count DESC, conn_count DESC
    LIMIT ?;
    """
    cur = conn.execute(q, (since_iso, HORIZONTAL_DST_IP_THRESHOLD, HORIZONTAL_CONN_THRESHOLD, limit))
    alerts = []
    for row in cur.fetchall():
        src_ip, dst_count, conn_count = row
        alerts.append({
            "alert_type": "horizontal_scan",
            "src_ip": src_ip,
            "dst_ip": None,
            "score": int(min(100, dst_count + conn_count // 10)),
            "evidence": {"dst_count": dst_count, "conn_count": conn_count, "since": since_iso}
        })
    return alerts

def detect_vertical_scans(conn: sqlite3.Connection, since_iso: str, limit: int = 200) -> List[Dict[str, Any]]:
    q = f"""
    SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) AS ports
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip, dst_ip
    HAVING ports > ?
    ORDER BY ports DESC
    LIMIT ?;
    """
    cur = conn.execute(q, (since_iso, VERTICAL_PORTS_THRESHOLD, limit))
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

def detect_repeated_connections(conn: sqlite3.Connection, since_iso: str, limit: int = 200) -> List[Dict[str, Any]]:
    q = f"""
    SELECT src_ip, COUNT(*) AS total_conns
    FROM ip_events
    WHERE timestamp >= ?
    GROUP BY src_ip
    HAVING total_conns > ?
    ORDER BY total_conns DESC
    LIMIT ?;
    """
    cur = conn.execute(q, (since_iso, REPEATED_CONN_THRESHOLD, limit))
    alerts = []
    for row in cur.fetchall():
        src_ip, total_conns = row
        alerts.append({
            "alert_type": "high_connection_volume",
            "src_ip": src_ip,
            "dst_ip": None,
            "score": int(min(100, total_conns // 2)),
            "evidence": {"total_conns": total_conns, "since": since_iso}
        })
    return alerts

def run_all_rules(conn: sqlite3.Connection, since_iso: str, max_alerts: int = None) -> List[Dict[str, Any]]:
    """
    Run all detection rules and return a combined list of alerts.
    The caller can dedupe or insert them into the alerts table.
    """
    if max_alerts is None:
        max_alerts = MAX_ALERTS_PER_RUN if 'MAX_ALERTS_PER_RUN' in globals() else 500

    alerts = []
    alerts.extend(detect_horizontal_scans(conn, since_iso, limit=max_alerts))
    alerts.extend(detect_vertical_scans(conn, since_iso, limit=max_alerts))
    alerts.extend(detect_repeated_connections(conn, since_iso, limit=max_alerts))

    # Optional: simple dedupe by (alert_type, src_ip, dst_ip)
    seen = set()
    deduped = []
    for a in alerts:
        key = (a.get("alert_type"), a.get("src_ip"), a.get("dst_ip"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(a)
    return deduped
