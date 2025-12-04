"""
net-scout configuration

Place this file in net-scout/ and adjust values as needed.
Values are intentionally simple and can be overridden by environment variables
or by importing and modifying at runtime.
"""

import os
import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("NET_SCOUT_DB_PATH", os.path.join(PROJECT_ROOT, "net_sentinel.db"))

# Alert table name
ALERT_TABLE = os.environ.get("NET_SCOUT_ALERT_TABLE", "scout_alerts")

# Detection thresholds (tunable)
HORIZONTAL_DST_IP_THRESHOLD = int(os.environ.get("NET_SCOUT_HORIZONTAL_DST_IP_THRESHOLD", "50"))
HORIZONTAL_CONN_THRESHOLD = int(os.environ.get("NET_SCOUT_HORIZONTAL_CONN_THRESHOLD", "200"))
VERTICAL_PORTS_THRESHOLD = int(os.environ.get("NET_SCOUT_VERTICAL_PORTS_THRESHOLD", "50"))
REPEATED_CONN_THRESHOLD = int(os.environ.get("NET_SCOUT_REPEATED_CONN_THRESHOLD", "200"))

# Default scan window if not provided on CLI (ISO duration string or human friendly)
DEFAULT_SINCE = os.environ.get("NET_SCOUT_DEFAULT_SINCE", "1 hour")

# Enrichment toggles and limits
ENABLE_WHOIS = os.environ.get("NET_SCOUT_ENABLE_WHOIS", "1") not in ("0", "false", "False")
ENABLE_TRACEROUTE = os.environ.get("NET_SCOUT_ENABLE_TRACEROUTE", "1") not in ("0", "false", "False")
ENABLE_RDNS = os.environ.get("NET_SCOUT_ENABLE_RDNS", "1") not in ("0", "false", "False")

# Traceroute / whois timeouts and rate limits
TRACEROUTE_MAX_HOPS = int(os.environ.get("NET_SCOUT_TRACEROUTE_MAX_HOPS", "20"))
TRACEROUTE_TIMEOUT = int(os.environ.get("NET_SCOUT_TRACEROUTE_TIMEOUT", "10"))  # seconds
WHOIS_TIMEOUT = int(os.environ.get("NET_SCOUT_WHOIS_TIMEOUT", "8"))  # seconds
ENRICHMENT_SLEEP = float(os.environ.get("NET_SCOUT_ENRICHMENT_SLEEP", "0.2"))  # polite pause between lookups

# Limits to avoid excessive work
MAX_ALERTS_PER_RUN = int(os.environ.get("NET_SCOUT_MAX_ALERTS_PER_RUN", "500"))
MAX_ENRICH_PER_RUN = int(os.environ.get("NET_SCOUT_MAX_ENRICH_PER_RUN", "50"))

# Logging
LOG_LEVEL = os.environ.get("NET_SCOUT_LOG_LEVEL", "INFO")
LOG_FILE = os.environ.get("NET_SCOUT_LOG_FILE", os.path.join(PROJECT_ROOT, "logs", "net-scout.log"))

# Utility
UTC_NOW = lambda: datetime.datetime.now(datetime.timezone.utc)
