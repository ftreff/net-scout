#!/usr/bin/env python3
"""
Enrichment helpers for net-scout.

Usage (from net-sentinel/net-scout):
  python3 enrich.py --help

Examples:
  # Enrich up to 10 newest alerts that have no enrichment yet
  python3 enrich.py --limit 10

  # Enrich a single alert by id
  python3 enrich.py --alert-id 42

Notes:
- Optional passive DNS: set PDNS_API_URL and PDNS_API_KEY environment variables to enable.
- This script creates a small sqlite cache table 'scout_enrichment_cache' to avoid repeated lookups.
- Traceroute and whois use system binaries if available; they are best-effort and may be slow.
"""

import os
import sys
import sqlite3
import json
import time
import socket
import subprocess
import argparse
import datetime
from typing import Optional, Dict, Any

# Try to import config values if present
try:
    from config import DB_PATH, ENABLE_RDNS, ENABLE_TRACEROUTE, ENABLE_WHOIS, TRACEROUTE_MAX_HOPS, TRACEROUTE_TIMEOUT, WHOIS_TIMEOUT, ENRICHMENT_SLEEP
except Exception:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DB_PATH = os.path.join(PROJECT_ROOT, "net_sentinel.db")
    ENABLE_RDNS = True
    ENABLE_TRACEROUTE = True
    ENABLE_WHOIS = True
    TRACEROUTE_MAX_HOPS = 20
    TRACEROUTE_TIMEOUT = 10
    WHOIS_TIMEOUT = 8
    ENRICHMENT_SLEEP = 0.2

# Optional passive DNS provider (user must set these env vars)
PDNS_API_URL = os.environ.get("PDNS_API_URL")      # e.g., "https://api.passivedns.example/v1/lookup"
PDNS_API_KEY = os.environ.get("PDNS_API_KEY")

CACHE_TABLE = "scout_enrichment_cache"

def utc_now_z() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

def ensure_cache_table(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {CACHE_TABLE} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject TEXT NOT NULL UNIQUE,   -- IP or domain
        kind TEXT,                      -- 'rdns','whois','traceroute','pdns'
        result_json TEXT,
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()

def cache_get(conn: sqlite3.Connection, subject: str) -> Optional[Dict[str, Any]]:
    cur = conn.execute(f"SELECT result_json, updated_at FROM {CACHE_TABLE} WHERE subject = ?;", (subject,))
    row = cur.fetchone()
    if not row:
        return None
    try:
        return {"result": json.loads(row[0]), "updated_at": row[1]}
    except Exception:
        return None

def cache_set(conn: sqlite3.Connection, subject: str, kind: str, result: Any):
    now = utc_now_z()
    payload = json.dumps(result)
    cur = conn.cursor()
    cur.execute(f"""
    INSERT INTO {CACHE_TABLE} (subject, kind, result_json, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(subject) DO UPDATE SET kind=excluded.kind, result_json=excluded.result_json, updated_at=excluded.updated_at;
    """, (subject, kind, payload, now))
    conn.commit()

def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        rdns = socket.gethostbyaddr(ip)[0]
        return rdns
    except Exception:
        return None

def run_traceroute_cmd(ip: str, max_hops: int = TRACEROUTE_MAX_HOPS, timeout: int = TRACEROUTE_TIMEOUT) -> str:
    try:
        if sys.platform.startswith("win"):
            cmd = ["tracert", "-d", ip]
        else:
            # Use numeric output to avoid slow DNS resolution in traceroute itself
            cmd = ["traceroute", "-n", "-m", str(max_hops), ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or proc.stderr or ""
        return out.strip()[:20000]
    except Exception as e:
        return f"traceroute error: {e}"

def run_whois_cmd(subject: str, timeout: int = WHOIS_TIMEOUT) -> Optional[str]:
    try:
        proc = subprocess.run(["whois", subject], capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or proc.stderr or ""
        return out.strip()[:20000]
    except Exception:
        return None

def pdns_lookup(subject: str) -> Optional[Dict[str, Any]]:
    # Passive DNS requires an external API; this is a best-effort wrapper.
    if not PDNS_API_URL or not PDNS_API_KEY:
        return None
    try:
        import requests
        headers = {"Authorization": f"Bearer {PDNS_API_KEY}", "Accept": "application/json"}
        # The exact API path/params depend on provider; we attempt a common pattern
        url = PDNS_API_URL.rstrip("/") + f"/{subject}"
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"pdns status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def enrich_subject(conn: sqlite3.Connection, subject: str, kinds: Optional[list] = None) -> Dict[str, Any]:
    """
    Enrich a single subject (IP or domain). Returns a dict of enrichment results.
    Uses cache when available.
    """
    if kinds is None:
        kinds = ["rdns", "whois", "traceroute", "pdns"]

    result = {}
    ensure_cache_table(conn)

    # rdns
    if "rdns" in kinds and ENABLE_RDNS:
        cached = cache_get(conn, f"rdns:{subject}")
        if cached:
            result["rdns"] = cached["result"]
        else:
            rdns = reverse_dns_lookup(subject)
            result["rdns"] = rdns
            cache_set(conn, f"rdns:{subject}", "rdns", rdns)
            time.sleep(ENRICHMENT_SLEEP)

    # whois
    if "whois" in kinds and ENABLE_WHOIS:
        cached = cache_get(conn, f"whois:{subject}")
        if cached:
            result["whois"] = cached["result"]
        else:
            who = run_whois_cmd(subject)
            result["whois"] = who
            cache_set(conn, f"whois:{subject}", "whois", who)
            time.sleep(ENRICHMENT_SLEEP)

    # traceroute
    if "traceroute" in kinds and ENABLE_TRACEROUTE:
        cached = cache_get(conn, f"traceroute:{subject}")
        if cached:
            result["traceroute"] = cached["result"]
        else:
            tr = run_traceroute_cmd(subject)
            result["traceroute"] = tr
            cache_set(conn, f"traceroute:{subject}", "traceroute", tr)
            time.sleep(ENRICHMENT_SLEEP)

    # passive DNS
    if "pdns" in kinds:
        cached = cache_get(conn, f"pdns:{subject}")
        if cached:
            result["pdns"] = cached["result"]
        else:
            pd = pdns_lookup(subject)
            result["pdns"] = pd
            cache_set(conn, f"pdns:{subject}", "pdns", pd)
            time.sleep(ENRICHMENT_SLEEP)

    return result

def enrich_alerts(conn: sqlite3.Connection, limit: int = 50, alert_id: Optional[int] = None):
    """
    Enrich alerts in scout_alerts table that have no enrichment_json or status='new'.
    If alert_id is provided, only enrich that alert.
    """
    cur = conn.cursor()
    if alert_id:
        cur.execute("SELECT id, src_ip, dst_ip, enrichment_json FROM scout_alerts WHERE id = ?;", (alert_id,))
    else:
        cur.execute("SELECT id, src_ip, dst_ip, enrichment_json FROM scout_alerts WHERE (enrichment_json IS NULL OR enrichment_json = '') ORDER BY created_at DESC LIMIT ?;", (limit,))
    rows = cur.fetchall()
    if not rows:
        print("[INFO] No alerts to enrich")
        return

    for r in rows:
        aid, src_ip, dst_ip, enrichment_json = r
        print(f"[INFO] enriching alert id={aid} src={src_ip} dst={dst_ip}")
        enrichment = {}
        try:
            if src_ip:
                enrichment["src"] = enrich_subject(conn, src_ip)
            if dst_ip:
                enrichment["dst"] = enrich_subject(conn, dst_ip)
            # update alert row
            now = utc_now_z()
            cur.execute("UPDATE scout_alerts SET enrichment_json = ?, status = ?, created_at = created_at WHERE id = ?;", (json.dumps(enrichment), "enriched", aid))
            conn.commit()
            print(f"[OK] enriched alert {aid}")
        except Exception as e:
            print(f"[ERROR] enriching alert {aid}: {e}")

def main():
    p = argparse.ArgumentParser(description="net-scout enrichment utility")
    p.add_argument("--limit", type=int, default=10, help="Max alerts to enrich (default 10)")
    p.add_argument("--alert-id", type=int, help="Enrich a single alert by id")
    p.add_argument("--db-path", type=str, default=None, help="Path to net_sentinel.db (overrides config)")
    args = p.parse_args()

    db_file = args.db_path if args.db_path else DB_PATH
    if not os.path.exists(db_file):
        print(f"[ERROR] DB not found at {db_file}")
        sys.exit(1)

    conn = sqlite3.connect(db_file, timeout=30)
    try:
        ensure_cache_table(conn)
        enrich_alerts(conn, limit=args.limit, alert_id=args.alert_id)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
