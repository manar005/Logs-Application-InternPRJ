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
from datetime import datetime

from config import AUDIT_CSV, AUDIT_JSON, DAYS_OF_HISTORY, USERS_FILE
from timestamps import format_ts, plan_attack_timeline, random_baseline_audit_timestamp

AUDIT_FIELDNAMES = [
    "Timestamp",
    "Actor",
    "Activity",
    "TargetUser",
    "Result",
    "ModifiedProperty",
    "OldValue",
    "NewValue",
    "RoleName",
    "Details",
    "ScenarioTag",
]

# Security and distribution groups used in baseline audit events
SECURITY_GROUPS = [
    "All Employees",
    "VPN Users",
    "Finance-Readers",
    "Sales-Team",
    "IT-Admins",
    "HR-Confidential",
    "Security-Operations",
]

LICENSE_SKUS = [
    "Microsoft 365 E3",
    "Microsoft 365 E5",
    "Microsoft 365 Business Premium",
    "Power BI Pro",
    "Microsoft Defender for Office 365",
]

AUTH_METHODS = [
    "SMS",
    "Microsoft Authenticator",
    "FIDO2 Security Key",
    "Windows Hello",
    "Email OTP",
]

PROFILE_FIELDS = {
    "department": ("Department", ["HR", "Finance", "IT", "Sales", "Security"]),
    "job title": ("Job Title", ["Analyst", "Manager", "Engineer", "Specialist"]),
    "manager": ("Manager", []),
    "office location": ("Office Location", ["New York", "London", "Toronto", "Berlin"]),
    "mobile phone": ("Mobile Phone", ["+1-555-0101", "+1-555-0142", "+44-20-7946-0958"]),
}

BASELINE_APPROVED_ROLES = [
    "User",
    "Helpdesk Administrator",
    "License Administrator",
]

PRIVILEGED_ROLES = [
    "Global Administrator",
    "Security Administrator",
    "Privileged Role Administrator",
]

# Attack auth changes — index order preserved for stable subset selection
AUTH_ATTACK_OPTIONS = [
    {
        "activity": "Authentication method added",
        "modified_property": "Authentication Method",
        "old_value": "",
        "new_value": "FIDO2 Security Key",
        "details": "Added FIDO2 security key from new device",
    },
    {
        "activity": "Authentication method removed",
        "modified_property": "Authentication Method",
        "old_value": "Microsoft Authenticator",
        "new_value": "",
        "details": "Removed Microsoft Authenticator from previous phone",
    },
    {
        "activity": "MFA disabled",
        "modified_property": "MFA Status",
        "old_value": "Enabled",
        "new_value": "Disabled",
        "details": "Changed default MFA method to SMS (weaker factor)",
    },
    {
        "activity": "Recovery email changed",
        "modified_property": "Recovery Email",
        "old_value": "user@democorp.com",
        "new_value": "attacker@mail.ru",
        "details": "Updated recovery email to external address attacker@mail.ru",
    },
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
    *,
    modified_property: str = "",
    old_value: str = "",
    new_value: str = "",
    role_name: str = "",
) -> dict:
    return {
        "Timestamp": timestamp,
        "Actor": actor,
        "Activity": activity,
        "TargetUser": target,
        "Result": result,
        "ModifiedProperty": modified_property,
        "OldValue": old_value,
        "NewValue": new_value,
        "RoleName": role_name,
        "Details": details,
        "ScenarioTag": scenario_tag,
    }


def _make_role_assignment(
    timestamp: str,
    actor: str,
    target: str,
    role_name: str,
    details: str,
    scenario_tag: str,
) -> dict:
    return _make_audit(
        timestamp,
        actor,
        "Add member to role",
        target,
        "Success",
        details,
        scenario_tag,
        role_name=role_name,
    )


def _helpdesk_actor(users: list[dict], admins: list[dict]) -> dict:
    it_staff = [u for u in users if u["department"] == "IT"]
    return random.choice(it_staff) if it_staff else random.choice(admins)


def _random_auth_method(exclude: str | None = None) -> str:
    options = [method for method in AUTH_METHODS if method != exclude]
    return random.choice(options) if options else random.choice(AUTH_METHODS)


def generate_baseline_audit(users: list[dict], base_date: datetime) -> list[dict]:
    """Routine audit events spread across the 30-day window (more frequent than attacks)."""
    logs = []
    admins = [u for u in users if u["role"] in ("Global Administrator", "Security Administrator")]
    standard_users = [u for u in users if u["role"] == "User"]

    if not admins or not standard_users:
        return logs

    primary_admin = next(u for u in users if u["role"] == "Global Administrator")
    sec_admins = [u for u in admins if u["role"] == "Security Administrator"]
    hr_users = [u for u in users if u["department"] == "HR"]

    for day in range(DAYS_OF_HISTORY):
        for _ in range(random.randint(2, 5)):
            event_type = random.choice([
                "password_reset",
                "mfa_enroll",
                "auth_remove",
                "mfa_enable",
                "mfa_disable",
                "recovery_phone",
                "recovery_email",
                "role_assign",
                "group_add",
                "group_remove",
                "profile_update",
                "license_assign",
                "license_remove",
                "security_group",
            ])
            ts = random_baseline_audit_timestamp(base_date, day)
            target = random.choice(standard_users)

            if event_type == "password_reset":
                actor = _helpdesk_actor(users, admins)
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Reset user password",
                    target["user_principal_name"],
                    "Success",
                    f"Password reset initiated by IT helpdesk per user request (ticket #"
                    f"{random.randint(10000, 99999)})",
                    "baseline",
                    modified_property="Password",
                    old_value="(redacted)",
                    new_value="(reset)",
                ))

            elif event_type == "mfa_enroll":
                enroll_user = random.choice(users)
                new_method = _random_auth_method()
                logs.append(_make_audit(
                    ts,
                    enroll_user["user_principal_name"],
                    "Authentication method added",
                    enroll_user["user_principal_name"],
                    "Success",
                    f"User registered {new_method} for MFA",
                    "baseline",
                    modified_property="Authentication Method",
                    old_value="",
                    new_value=new_method,
                ))

            elif event_type == "auth_remove":
                user = random.choice(users)
                removed_method = _random_auth_method()
                logs.append(_make_audit(
                    ts,
                    user["user_principal_name"],
                    "Authentication method removed",
                    user["user_principal_name"],
                    "Success",
                    f"Removed {removed_method} after device upgrade",
                    "baseline",
                    modified_property="Authentication Method",
                    old_value=removed_method,
                    new_value="",
                ))

            elif event_type == "mfa_enable":
                user = random.choice(users)
                logs.append(_make_audit(
                    ts,
                    user["user_principal_name"],
                    "MFA enabled",
                    user["user_principal_name"],
                    "Success",
                    "User completed MFA registration",
                    "baseline",
                    modified_property="MFA Status",
                    old_value="Disabled",
                    new_value="Enabled",
                ))

            elif event_type == "mfa_disable":
                user = random.choice(users)
                logs.append(_make_audit(
                    ts,
                    _helpdesk_actor(users, admins)["user_principal_name"],
                    "MFA disabled",
                    user["user_principal_name"],
                    "Success",
                    "MFA disabled per approved exception request",
                    "baseline",
                    modified_property="MFA Status",
                    old_value="Enabled",
                    new_value="Disabled",
                ))

            elif event_type == "recovery_phone":
                user = random.choice(users)
                new_phone = random.choice(["+1-555-0188", "+1-555-0234", "+44-7700-900123"])
                logs.append(_make_audit(
                    ts,
                    user["user_principal_name"],
                    "Recovery phone changed",
                    user["user_principal_name"],
                    "Success",
                    "User updated account recovery phone number",
                    "baseline",
                    modified_property="Recovery Phone",
                    old_value="+1-555-0100",
                    new_value=new_phone,
                ))

            elif event_type == "recovery_email":
                user = random.choice(users)
                logs.append(_make_audit(
                    ts,
                    user["user_principal_name"],
                    "Recovery email changed",
                    user["user_principal_name"],
                    "Success",
                    "User updated account recovery email address",
                    "baseline",
                    modified_property="Recovery Email",
                    old_value=user["user_principal_name"],
                    new_value=f"recovery.{user['user_principal_name']}",
                ))

            elif event_type == "role_assign":
                actor = random.choice(admins)
                role_name = random.choice(BASELINE_APPROVED_ROLES)
                logs.append(_make_role_assignment(
                    ts,
                    actor["user_principal_name"],
                    target["user_principal_name"],
                    role_name,
                    f"Assigned role '{role_name}' to {target['display_name']} (approved change request)",
                    "baseline",
                ))

            elif event_type == "group_add":
                actor = random.choice(admins + hr_users) if hr_users else random.choice(admins)
                group = random.choice(SECURITY_GROUPS)
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Add member to group",
                    target["user_principal_name"],
                    "Success",
                    f"Added user to '{group}' group",
                    "baseline",
                    modified_property="Group Membership",
                    old_value="",
                    new_value=group,
                ))

            elif event_type == "group_remove":
                actor = random.choice(admins + sec_admins) if sec_admins else random.choice(admins)
                group = random.choice(SECURITY_GROUPS)
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Remove member from group",
                    target["user_principal_name"],
                    "Success",
                    f"Removed user from '{group}' group (role change / offboarding step)",
                    "baseline",
                    modified_property="Group Membership",
                    old_value=group,
                    new_value="",
                ))

            elif event_type == "profile_update":
                actor = random.choice(hr_users) if hr_users else primary_admin
                field_key = random.choice(list(PROFILE_FIELDS.keys()))
                prop_name, sample_values = PROFILE_FIELDS[field_key]
                old_val = random.choice(sample_values) if sample_values else "Previous Value"
                new_val = random.choice(sample_values) if sample_values else "Updated Value"
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Update user",
                    target["user_principal_name"],
                    "Success",
                    f"Updated user profile: changed {field_key} per HR request",
                    "baseline",
                    modified_property=prop_name,
                    old_value=old_val,
                    new_value=new_val,
                ))

            elif event_type == "license_assign":
                actor = _helpdesk_actor(users, admins)
                sku = random.choice(LICENSE_SKUS)
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Assign license",
                    target["user_principal_name"],
                    "Success",
                    f"Assigned license '{sku}' to {target['display_name']}",
                    "baseline",
                    modified_property="License",
                    old_value="",
                    new_value=sku,
                ))

            elif event_type == "license_remove":
                actor = _helpdesk_actor(users, admins)
                sku = random.choice(LICENSE_SKUS)
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    "Remove license",
                    target["user_principal_name"],
                    "Success",
                    f"Removed license '{sku}' from {target['display_name']} (license reclamation)",
                    "baseline",
                    modified_property="License",
                    old_value=sku,
                    new_value="",
                ))

            elif event_type == "security_group":
                actor = random.choice(sec_admins) if sec_admins else random.choice(admins)
                group = random.choice([
                    "Security-Operations",
                    "Privileged-Access-Reviewers",
                    "Conditional-Access-Exclusions",
                ])
                action = random.choice(["Add member to group", "Remove member from group"])
                is_add = action == "Add member to group"
                logs.append(_make_audit(
                    ts,
                    actor["user_principal_name"],
                    action,
                    target["user_principal_name"],
                    "Success",
                    f"{'Added user to' if is_add else 'Removed user from'} '{group}' security group",
                    "baseline",
                    modified_property="Security Group",
                    old_value="" if is_add else group,
                    new_value=group if is_add else "",
                ))

    return logs


def generate_auth_change_attacks(
    users: list[dict],
    base_date: datetime,
    timeline: dict,
) -> list[dict]:
    """
    Technique 3: Authentication Changes
    Attacker modifies MFA and recovery info, shortly after a suspicious sign-in.
    """
    logs = []
    victim = random.choice([u for u in users if u["role"] == "User"])
    actor = victim["user_principal_name"]

    change_count = random.randint(1, len(AUTH_ATTACK_OPTIONS))
    selected_indices = sorted(random.sample(range(len(AUTH_ATTACK_OPTIONS)), change_count))

    for slot, idx in enumerate(selected_indices):
        option = AUTH_ATTACK_OPTIONS[idx]
        ts = format_ts(timeline["auth_change_times"][slot])
        logs.append(_make_audit(
            ts,
            actor,
            option["activity"],
            actor,
            "Success",
            option["details"],
            "auth_change_attack",
            modified_property=option["modified_property"],
            old_value=option["old_value"],
            new_value=option["new_value"],
        ))

    return logs


def generate_privileged_role_attacks(
    users: list[dict],
    base_date: datetime,
    timeline: dict,
) -> list[dict]:
    """
    Technique 4: Privileged Role Assignment
    Unusual actor grants privileged roles shortly after compromise.
    """
    logs = []
    standard_users = [u for u in users if u["role"] == "User"]
    victim = random.choice(standard_users)
    mode = random.choice(["self", "accomplice", "both"])

    if mode in ("self", "both"):
        logs.append(_make_role_assignment(
            format_ts(timeline["privileged_role_times"][0]),
            victim["user_principal_name"],
            victim["user_principal_name"],
            "Global Administrator",
            "User assigned to privileged directory role — initiated by non-admin account",
            "privileged_role_self_elevation",
        ))

    if mode in ("accomplice", "both"):
        accomplice = random.choice([u for u in standard_users if u != victim])
        accomplice_role = random.choice([
            "Security Administrator",
            "Privileged Role Administrator",
        ])
        time_slot = 1 if mode == "both" else 0
        logs.append(_make_role_assignment(
            format_ts(timeline["privileged_role_times"][time_slot]),
            victim["user_principal_name"],
            accomplice["user_principal_name"],
            accomplice_role,
            f"User assigned to privileged directory role ({accomplice_role})",
            "privileged_role_accomplice",
        ))

    real_admin = next(u for u in users if u["role"] == "Global Administrator")
    logs.append(_make_role_assignment(
        format_ts(timeline["privileged_baseline_time"]),
        real_admin["user_principal_name"],
        next(u for u in users if u["department"] == "Security")["user_principal_name"],
        "Security Administrator",
        "Assigned role during planned security team expansion",
        "baseline",
    ))

    return logs


def generate_all_audit_logs(users: list[dict] | None = None, seed: int = 42) -> list[dict]:
    """Combine baseline and attack audit logs, sorted by timestamp."""
    random.seed(seed)
    if users is None:
        users = _load_users()

    base_date = datetime.utcnow().replace(microsecond=0)
    timeline = plan_attack_timeline(base_date, seed)

    logs = []
    logs.extend(generate_baseline_audit(users, base_date))
    logs.extend(generate_auth_change_attacks(users, base_date, timeline))
    logs.extend(generate_privileged_role_attacks(users, base_date, timeline))

    logs.sort(key=lambda x: x["Timestamp"])
    return logs


def save_audit_logs(logs: list[dict]) -> None:
    """Write audit logs to CSV and JSON."""
    os.makedirs(os.path.dirname(AUDIT_CSV), exist_ok=True)

    with open(AUDIT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=AUDIT_FIELDNAMES)
        writer.writeheader()
        writer.writerows(logs)

    with open(AUDIT_JSON, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    print(f"Saved {len(logs)} audit records to {AUDIT_CSV} and {AUDIT_JSON}")


if __name__ == "__main__":
    audit_logs = generate_all_audit_logs()
    save_audit_logs(audit_logs)
