# net-scout
Add-On / Companion to Net‑Sentinel.  Net-Scout scans the Net‑Sentinel DB, scores suspicious activity, enriches high‑confidence alerts, and exposes an Investigate UI and API for triage and blocking. It complements the net-sentinel dashboard without changing it.


Files

scout.py — main CLI script (runs detection, writes alerts, optional enrichment). (first file I'll provide now)

config.py — small configuration (DB path, thresholds, enrichment toggles).

migrations.py — idempotent DB migration helpers (create alerts table and indexes).

enrich.py — enrichment helpers (traceroute, whois, reverse DNS, caching).

rules.py — detection rules implemented as SQL or Python functions (horizontal/vertical scans, repeated ports).

requirements.txt — Python dependencies (minimal; optional libs noted).

README.md — usage and operational notes for net-scout.
