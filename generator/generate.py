"""
Run all DemoCorp log generators in order.

Usage (from project root):
    python generator/generate.py
"""

import os
import sys

# Allow imports when running as a script from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_audit_logs import generate_all_audit_logs, save_audit_logs
from generate_signins import generate_all_signins, save_signins
from generate_users import generate_users, save_users


def main() -> None:
    print("=== DemoCorp Cloud Identity Security Detection Lab ===\n")

    print("[1/3] Generating users...")
    users = generate_users()
    save_users(users)

    print("\n[2/3] Generating sign-in logs...")
    signins = generate_all_signins(users)
    save_signins(signins)

    print("\n[3/3] Generating audit logs...")
    audit_logs = generate_all_audit_logs(users)
    save_audit_logs(audit_logs)

    print("\nDone! Data files are in the /data folder.")
    print("Start the dashboard: python run.py")


if __name__ == "__main__":
    main()
