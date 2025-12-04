#!/usr/bin/env python3
"""
Idempotent migrations for net-scout.

Run from the net-scout directory (or from project root):
  python3 migrations.py

This will:
- create the scout_alerts table (if missing)
- add event_hash column to ip_events and ip_events_30 (if missing)
- create unique indexes for event_hash on those tables (if missing)
"""

import os
import sqlite3
import sys
from typing import List

# Try to import config if available; otherwise fall back to ../net_sentinel.db
try:
    from config import DB_PATH, ALERT_TABLE
except Exception:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DB_PATH = os.path.join(PROJECT_ROOT, "net_sentinel.db")
    ALERT_TABLE = "scout_alerts"

def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table,))
    return cur.fetchone() is not None

def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cur = conn.execute(f"PRAGMA table_info('{table}');")
    cols = [r[1] for r in cur.fetchall()]  # second field is column name
    return column in cols

def ensure_scout_alerts(conn: sqlite3.Connection):
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
    cur.execute(f"""
    CREATE UNIQUE INDEX IF NOT EXISTS ux_{ALERT_TABLE}_unique
    ON {ALERT_TABLE} (alert_type, src_ip, dst_ip, date(created_at));
    """)
    conn.commit()
    print(f"Ensured table {ALERT_TABLE} and unique index.")

def ensure_event_hash_on_table(conn: sqlite3.Connection, table: str):
    if not table_exists(conn, table):
        print(f"Table {table} does not exist; skipping event_hash addition.")
        return
    if column_exists(conn, table, "event_hash"):
        print(f"{table}.event_hash already exists")
    else:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN event_hash TEXT;")
            conn.commit()
            print(f"Added event_hash column to {table}")
        except sqlite3.OperationalError as e:
            # If column already exists or other issue, report and continue
            print(f"Warning: could not add event_hash to {table}: {e}")

    # Create unique index on event_hash (idempotent)
    idx_name = f"ux_{table}_event_hash"
    conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {idx_name} ON {table}(event_hash);")
    conn.commit()
    print(f"Ensured unique index {idx_name} on {table}(event_hash)")

def run_all():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        ensure_scout_alerts(conn)
        # Add event_hash to ip_events and ip_events_30 if present
        ensure_event_hash_on_table(conn, "ip_events")
        ensure_event_hash_on_table(conn, "ip_events_30")
    finally:
        conn.close()

if __name__ == "__main__":
    run_all()
    print("Migrations complete.")
