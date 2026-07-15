"""
Shared configuration for the DemoCorp synthetic log generator.
Adjust these values to change the size and shape of generated data.
"""

import os
from datetime import datetime, timedelta, timezone

# Fictional company name used across all generated logs
COMPANY_NAME = "DemoCorp"
COMPANY_DOMAIN = "democorp.com"

# How many days of history to generate (ending at today)
DAYS_OF_HISTORY = 30

# Number of employees to create (between 20 and 30)
NUM_EMPLOYEES = 25

# Departments and how many users per department (must sum to NUM_EMPLOYEES)
DEPARTMENTS = {
    "HR": 4,
    "Finance": 5,
    "IT": 6,
    "Sales": 6,
    "Security": 4,
}

# Known "normal" countries where DemoCorp employees usually sign in
KNOWN_COUNTRIES = ["United States", "United Kingdom", "Canada", "Germany"]

# Suspicious countries used in attack simulations
SUSPICIOUS_COUNTRIES = ["Russia", "Nigeria", "North Korea", "Brazil"]

# Common corporate device names for baseline activity
KNOWN_DEVICES = [
    "DESKTOP-HR-01",
    "DESKTOP-FIN-02",
    "LAPTOP-IT-03",
    "LAPTOP-SALES-04",
    "WORKSTATION-SEC-05",
    "IPHONE-14-PRO",
    "MACBOOK-PRO-M2",
    "SURFACE-PRO-9",
]

# Attacker infrastructure used in simulations
ATTACKER_IPS = {
    "password_spray": "203.0.113.45",
    "tor_exit": "198.51.100.77",
    "vpn_proxy": "192.0.2.88",
    "suspicious_country": "203.0.113.99",
}

# Output paths (relative to project root)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SIGNINS_CSV = os.path.join(DATA_DIR, "signins.csv")
SIGNINS_JSON = os.path.join(DATA_DIR, "signins.json")
AUDIT_CSV = os.path.join(DATA_DIR, "auditlogs.csv")
AUDIT_JSON = os.path.join(DATA_DIR, "auditlogs.json")

# Bahrain (UTC+3) — timestamps are stored in local time with am/pm suffix.
BAHRAIN_TZ = timezone(timedelta(hours=3))


def format_ts(dt: datetime) -> str:
    """Format a datetime as Bahrain local time, e.g. 2026-07-09 3:38:50 pm."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(BAHRAIN_TZ)
    hour_12 = local.hour % 12 or 12
    am_pm = "am" if local.hour < 12 else "pm"
    return (
        f"{local.year:04d}-{local.month:02d}-{local.day:02d} "
        f"{hour_12}:{local.minute:02d}:{local.second:02d} {am_pm}"
    )


def parse_ts(value: str) -> datetime:
    """Parse a Bahrain timestamp string for sorting."""
    date_part, time_part, am_pm = value.split()
    year, month, day = map(int, date_part.split("-"))
    hour, minute, second = map(int, time_part.split(":"))
    if am_pm.lower() == "pm" and hour != 12:
        hour += 12
    elif am_pm.lower() == "am" and hour == 12:
        hour = 0
    return datetime(year, month, day, hour, minute, second, tzinfo=BAHRAIN_TZ)
