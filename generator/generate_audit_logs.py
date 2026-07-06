"""
Generate synthetic Azure AD-style audit logs for DemoCorp.

Includes:
  - Baseline admin activity (approved role assignments, routine auth updates)
  - Attack simulations: authentication changes, privileged role assignments
"""

import csv
import json
import os
import random
from datetime import datetime, timedelta

from config import AUDIT_CSV, AUDIT_JSON, USERS_FILE

# Audit activities that appear in normal operations
NORMAL_ACTIVITIES = [
    "User signed in",
    "Update user",
    "Add member to group",
    "Reset user password",
]

AUTH_CHANGE_ACTIVITIES = [
    "Authentication method added",
    "Authentication method removed",
    "MFA settings changed",
    "Recovery information updated",
]

ROLE_ACTIVITIES = [
    "Add member to role",
    "Remove member from role",
]


def _load_users(path: str = USERS_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _make_audit(
    timestamp: str,
    actor: str,
    activity: str,
    target: str,
    result: str,
    details: str,
    scenario_tag: str = "baseline",
) -> dict:
    return {
        "Timestamp": timestamp,
        "Actor": actor,
        "Activity": activity,
        "TargetUser": target,
        "Result": result,
        "Details": details,
        "ScenarioTag": scenario_tag,
    }


def _ts(base: datetime, days_ago: int, hour: int = 10, minute: int = 0) -> str:
    t = (base - timedelta(days=days_ago)).replace(hour=hour, minute=minute, second=0)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_baseline_audit(users: list[dict], base_date: datetime) -> list[dict]:
    """Routine audit events: approved role changes and normal auth updates."""
    logs = []
    admins = [u for u in users if u["role"] in ("Global Administrator", "Security Administrator")]
    standard_users = [u for u in users if u["role"] == "User"]

    if not admins:
        return logs

    primary_admin = next(u for u in users if u["role"] == "Global Administrator")

    # Approved role assignment for a new hire (normal IT onboarding)
    new_hire = random.choice(standard_users)
    logs.append(_make_audit(
        _ts(base_date, 20, 9, 30),
        primary_admin["user_principal_name"],
        "Add member to role",
        new_hire["user_principal_name"],
        "Success",
        f"Assigned role 'User' to {new_hire['display_name']} during onboarding",
        "baseline",
    ))

    # Normal MFA enrollment by a user
    it_user = next((u for u in users if u["department"] == "IT"), standard_users[0])
    logs.append(_make_audit(
        _ts(base_date, 15, 14, 0),
        it_user["user_principal_name"],
        "Authentication method added",
        it_user["user_principal_name"],
        "Success",
        "User enrolled Microsoft Authenticator app for MFA",
        "baseline",
    ))

    # Security admin reviews a group membership (benign)
    sec_admin = next(u for u in admins if u["role"] == "Security Administrator")
    logs.append(_make_audit(
        _ts(base_date, 10, 11, 0),
        sec_admin["user_principal_name"],
        "Add member to group",
        random.choice(standard_users)["user_principal_name"],
        "Success",
        "Added user to 'All Employees' security group",
        "baseline",
    ))

    # Routine password reset by helpdesk
    logs.append(_make_audit(
        _ts(base_date, 8, 10, 15),
        primary_admin["user_principal_name"],
        "Reset user password",
        random.choice(standard_users)["user_principal_name"],
        "Success",
        "Password reset initiated by IT helpdesk per user request",
        "baseline",
    ))

    return logs


def generate_auth_change_attacks(users: list[dict], base_date: datetime) -> list[dict]:
    """
    Technique 3: Authentication Changes
    Attacker modifies MFA and recovery info, shortly after a suspicious sign-in.
    """
    logs = []
    victim = random.choice([u for u in users if u["role"] == "User"])
    # Attacker acts as the compromised victim (self-service changes)
    actor = victim["user_principal_name"]
    day = 2

    # Suspicious sign-in would have occurred ~30 min before these changes
    changes = [
        (_ts(base_date, day, 3, 15), "Authentication method added", "Added FIDO2 security key from new device"),
        (_ts(base_date, day, 3, 22), "Authentication method removed", "Removed Microsoft Authenticator from previous phone"),
        (_ts(base_date, day, 3, 35), "MFA settings changed", "Changed default MFA method to SMS (weaker factor)"),
        (_ts(base_date, day, 3, 48), "Recovery information updated", "Updated recovery email to external address attacker@mail.ru"),
    ]

    for ts, activity, detail in changes:
        logs.append(_make_audit(
            ts, actor, activity, actor, "Success", detail, "auth_change_attack"
        ))

    return logs


def generate_privileged_role_attacks(users: list[dict], base_date: datetime) -> list[dict]:
    """
    Technique 4: Privileged Role Assignment
    Unusual actor grants Global Admin / Security Admin shortly after compromise.
    """
    logs = []
    standard_users = [u for u in users if u["role"] == "User"]
    victim = random.choice(standard_users)

    # Compromised user elevates themselves (unusual actor = the victim, not an admin)
    logs.append(_make_audit(
        _ts(base_date, 2, 4, 10),
        victim["user_principal_name"],
        "Add member to role",
        victim["user_principal_name"],
        "Success",
        "Assigned role 'Global Administrator' — initiated by non-admin account",
        "privileged_role_self_elevation",
    ))

    # Another scenario: compromised account adds an external-looking accomplice
    accomplice = random.choice([u for u in standard_users if u != victim])
    logs.append(_make_audit(
        _ts(base_date, 2, 4, 25),
        victim["user_principal_name"],
        "Add member to role",
        accomplice["user_principal_name"],
        "Success",
        "Assigned role 'Security Administrator' to accomplice account",
        "privileged_role_accomplice",
    ))

    # Approved baseline-style assignment for contrast (performed by real admin, older date)
    real_admin = next(u for u in users if u["role"] == "Global Administrator")
    logs.append(_make_audit(
        _ts(base_date, 25, 9, 0),
        real_admin["user_principal_name"],
        "Add member to role",
        next(u for u in users if u["department"] == "Security")["user_principal_name"],
        "Success",
        "Assigned role 'Security Administrator' during planned security team expansion",
        "baseline",
    ))

    return logs


def generate_all_audit_logs(users: list[dict] | None = None, seed: int = 42) -> list[dict]:
    """Combine baseline and attack audit logs, sorted by timestamp."""
    random.seed(seed)
    if users is None:
        users = _load_users()

    base_date = datetime.utcnow().replace(microsecond=0)

    logs = []
    logs.extend(generate_baseline_audit(users, base_date))
    logs.extend(generate_auth_change_attacks(users, base_date))
    logs.extend(generate_privileged_role_attacks(users, base_date))

    logs.sort(key=lambda x: x["Timestamp"])
    return logs


def save_audit_logs(logs: list[dict]) -> None:
    """Write audit logs to CSV and JSON."""
    os.makedirs(os.path.dirname(AUDIT_CSV), exist_ok=True)

    fieldnames = [
        "Timestamp", "Actor", "Activity", "TargetUser",
        "Result", "Details", "ScenarioTag",
    ]

    with open(AUDIT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)

    with open(AUDIT_JSON, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    print(f"Saved {len(logs)} audit records to {AUDIT_CSV} and {AUDIT_JSON}")


if __name__ == "__main__":
    audit_logs = generate_all_audit_logs()
    save_audit_logs(audit_logs)
