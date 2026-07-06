"""
Shared configuration for the DemoCorp synthetic log generator.
Adjust these values to change the size and shape of generated data.
"""

import os

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
