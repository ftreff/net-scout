# net-scout

**net-scout** is a companion CLI tool for **net-sentinel**. It scans the `net_sentinel.db` database for suspicious network activity (port scans, probing, high connection volumes), inserts alerts into a local `scout_alerts` table, and can enrich alerts with reverse DNS, WHOIS, traceroute, and optional passive‑DNS lookups.
---
## Placement
Place the `net-scout` directory inside your `net-sentinel` project folder:
```
net-sentinel/ 
├── net_sentinel.db 
├── dashboard.py 
└── net-scout/ 
  ├── scout.py 
  ├── config.py 
  ├── migrations.py 
  ├── enrich.py 
  ├── rules.py 
  ├── requirements.txt 
  └── README.md
```
--- 
`net-scout` expects the database at `../net_sentinel.db` by default (one level up). You can override the DB path with `--db-path` flags where supported.
---
## Quick start

1. (Optional) Install Python deps:
   ```bash
   cd net-sentinel/net-scout
   pip3 install -r requirements.txt
   ```
2. Run migrations to create the alerts table and optional event_hash columns:
    ```bash
    python3 migrations.py
    ```
3. Run a dry-run scan (no writes):
    ```bash
    python3 scout.py --dry-run
    ```
4. Run a real scan and insert alerts:
    ```bash
    python3 scout.py --since "1 hour"
    ```
5. Enrich newly created alerts (WHOIS, traceroute, rdns):
    ```bash
    python3 enrich.py --limit 10
    ```
---
### Files
scout.py — main CLI scanner (detection + optional enrichment).

config.py — configuration and thresholds.

migrations.py — idempotent DB migrations.

enrich.py — enrichment helpers and cache.

rules.py — detection rules (SQL-based).

requirements.txt — optional Python dependencies.

README.md — this file.
---
### Notes and recommendations
Permissions: scout.py and migrations.py may create or modify the DB; run as a user with write access to net_sentinel.db. Use --dry-run to test without writes.

Enrichment: traceroute and whois use system binaries; ensure traceroute/whois are installed. Passive‑DNS requires an API and credentials; set PDNS_API_URL and PDNS_API_KEY environment variables to enable.

Tuning: adjust thresholds in config.py or via environment variables to match your network’s normal behavior and reduce false positives.

Blocking: net-scout does not automatically apply firewall rules. Use the alert output and enrichment to craft manual rules on your router.
---
### Security and safety
Rate-limit enrichment lookups to avoid abuse of external services.

Cache enrichment results to reduce repeated lookups and API usage.

Be cautious when running traceroute/whois at scale; they can be slow and noisy.

