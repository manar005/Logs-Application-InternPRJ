"""
Run all DemoCorp log generators in order.

Usage (from project root):
    python generator/generate.py
"""

import os
import sys
from datetime import datetime

# Allow imports when running as a script from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attack_scenarios import plan_attack_scenarios, generate_scenario_events
from generate_audit_logs import generate_all_audit_logs, save_audit_logs
from generate_signins import generate_all_signins, save_signins
from generate_users import generate_users, save_users

SEED = 42


def main() -> None:
    print("=== DemoCorp Cloud Identity Security Detection Lab ===\n")

    print("[1/3] Generating users...")
    users = generate_users(SEED)
    save_users(users)

    base_date = datetime.utcnow().replace(microsecond=0)
    scenarios = plan_attack_scenarios(users, base_date, SEED)
    scenario_signins, scenario_audit = generate_scenario_events(scenarios, users, SEED)

    print("\n[2/3] Generating sign-in logs...")
    signins = generate_all_signins(
        users,
        seed=SEED,
        base_date=base_date,
        scenario_signins=scenario_signins,
    )
    save_signins(signins)

    print("\n[3/3] Generating audit logs...")
    audit_logs = generate_all_audit_logs(
        users,
        seed=SEED,
        base_date=base_date,
        scenario_audit=scenario_audit,
    )
    save_audit_logs(audit_logs)

    print("\nDone! Data files are in the /data folder.")
    print("Start the dashboard: python run.py")


if __name__ == "__main__":
    main()
