"""
Plan and generate correlated cloud identity attack scenarios for DemoCorp.

Scenarios chain techniques using natural log fields (UserPrincipalName, Actor,
TargetUser, IPAddress, Timestamp, etc.) — no artificial correlation IDs.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from config import ATTACKER_IPS, DAYS_OF_HISTORY, format_ts
from user_baseline import (
    generate_unfamiliar_device,
    get_baseline,
    maybe_apply_off_hours,
    pick_unfamiliar_country,
    pick_unfamiliar_ip,
)

SUSPICIOUS_VIOLATION_ORDER = [
    "new_country",
    "unknown_device",
    "tor_exit",
    "vpn_proxy",
]

SUSPICIOUS_VIOLATION_TAGS = {
    "new_country": "suspicious_new_country",
    "unknown_device": "suspicious_unknown_device",
    "tor_exit": "suspicious_tor_exit",
    "vpn_proxy": "suspicious_vpn_proxy",
}

SPRAY_FAILURE_RISKS = ["none", "low", "low", "medium"]
SPRAY_SUCCESS_RISKS = ["medium", "medium", "high"]
SUSPICIOUS_RISK_BY_VIOLATION = {
    "new_country": ["low", "medium", "medium", "high"],
    "unknown_device": ["none", "low", "low", "medium"],
    "tor_exit": ["medium", "medium", "high"],
    "vpn_proxy": ["low", "medium", "high"],
}

AUTH_ATTACK_OPTIONS = [
    {
        "activity": "Authentication method added",
        "modified_property": "Authentication Method",
        "old_value": "",
        "new_value": "FIDO2 Security Key",
        "details": "Registered a new FIDO2 Security Key.",
        "failure_details": "Authentication method change blocked by Conditional Access policy.",
    },
    {
        "activity": "Authentication method removed",
        "modified_property": "Authentication Method",
        "old_value": "Microsoft Authenticator",
        "new_value": "",
        "details": "Removed Microsoft Authenticator after device replacement.",
        "failure_details": "Authentication method removal denied: MFA registration lock active.",
    },
    {
        "activity": "MFA disabled",
        "modified_property": "MFA Status",
        "old_value": "Enabled",
        "new_value": "Disabled",
        "details": "MFA disabled for the account.",
        "failure_details": "MFA disable request rejected: security policy requires MFA.",
    },
    {
        "activity": "Recovery email changed",
        "modified_property": "Recovery Email",
        "old_value": "user@democorp.com",
        "new_value": "attacker@mail.ru",
        "details": "Updated recovery email address to attacker@mail.ru.",
        "failure_details": "Recovery email change blocked: external domain not permitted.",
    },
    {
        "activity": "Recovery phone changed",
        "modified_property": "Recovery Phone",
        "old_value": "+97336001000",
        "new_value": "+79991234567",
        "details": "Updated recovery phone number to +79991234567.",
        "failure_details": "Recovery phone change blocked: external number not permitted.",
    },
]

ROLE_DENIED_DETAILS = [
    "Role assignment denied: insufficient privileges.",
    "Operation blocked by authorization policy.",
]

PRIVILEGED_ACTOR_ROLES = ("Global Administrator", "Security Administrator")

SCENARIO_TEMPLATES = {
    "credential_attack": {
        "techniques": ["password_spray"],
        "spray_compromise": False,
    },
    "initial_access": {
        "techniques": ["password_spray", "suspicious_signin"],
        "spray_compromise": True,
    },
    "persistence": {
        "techniques": ["suspicious_signin", "auth_change"],
    },
    "privilege_escalation": {
        "techniques": ["suspicious_signin", "privileged_role"],
    },
    "full_takeover": {
        "techniques": ["password_spray", "suspicious_signin", "auth_change", "privileged_role"],
        "spray_compromise": True,
    },
    "spray_to_signin": {
        "techniques": ["password_spray", "suspicious_signin"],
        "spray_compromise": True,
    },
    "spray_to_auth": {
        "techniques": ["password_spray", "auth_change"],
        "spray_compromise": True,
    },
    "signin_to_auth": {
        "techniques": ["suspicious_signin", "auth_change"],
    },
    "signin_to_role": {
        "techniques": ["suspicious_signin", "privileged_role"],
    },
    "auth_only": {
        "techniques": ["auth_change"],
    },
    "role_only": {
        "techniques": ["privileged_role"],
    },
    "signin_only": {
        "techniques": ["suspicious_signin"],
    },
}

DEFAULT_SCENARIO_SEQUENCE = [
    "full_takeover",
    "initial_access",
    "persistence",
    "privilege_escalation",
    "spray_to_signin",
    "spray_to_auth",
    "signin_to_auth",
    "signin_to_role",
    "credential_attack",
    "signin_only",
    "auth_only",
    "role_only",
]


@dataclass
class AttackScenario:
    """One plausible identity attack storyline in the dataset."""

    template: str
    techniques: list[str]
    victim: dict
    anchor: datetime
    spray_compromise: bool = False
    spray_target_count: int = 8
    suspicious_violations: list[str] = field(default_factory=list)
    auth_option_indices: list[int] = field(default_factory=list)
    auth_results: list[str] = field(default_factory=list)
    role_mode: str = "self"
    role_compromised_success: bool = False
    role_compromised_actor: dict | None = None
    accomplice: dict | None = None
    attacker_ip: str = ATTACKER_IPS["password_spray"]
    spray_targets: list[dict] = field(default_factory=list)


def _advance(rng: random.Random, moment: datetime, min_min: int, max_min: int) -> datetime:
    return moment + timedelta(
        minutes=rng.randint(min_min, max_min),
        seconds=rng.randint(5, 55),
    )


def _standard_users(users: list[dict]) -> list[dict]:
    return [user for user in users if user["role"] == "User"]


def _pick_anchor(rng: random.Random, base_date: datetime) -> datetime:
    days_ago = rng.randint(2, DAYS_OF_HISTORY - 2)
    hour = rng.choice([0, 1, 2, 3, 4, 5, 22, 23])
    return (base_date - timedelta(days=days_ago)).replace(
        hour=hour,
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )


def plan_attack_scenarios(
    users: list[dict],
    base_date: datetime,
    seed: int,
) -> list[AttackScenario]:
    """Build a deterministic set of correlated and independent attack scenarios."""
    rng = random.Random(seed + 9001)
    candidates = _standard_users(users)
    rng.shuffle(candidates)
    victim_pool = list(candidates)

    scenarios: list[AttackScenario] = []
    scenario_victims: list[dict] = []

    for template_name in DEFAULT_SCENARIO_SEQUENCE:
        if not victim_pool:
            victim_pool = list(candidates)
            rng.shuffle(victim_pool)

        template = SCENARIO_TEMPLATES[template_name]
        victim = victim_pool.pop()
        scenario_victims.append(victim)
        techniques = list(template["techniques"])
        spray_compromise = bool(template.get("spray_compromise", False))

        violation_count = rng.randint(1, 2) if "suspicious_signin" in techniques else 0
        violations = (
            sorted(
                rng.sample(SUSPICIOUS_VIOLATION_ORDER, violation_count),
                key=SUSPICIOUS_VIOLATION_ORDER.index,
            )
            if violation_count
            else []
        )

        auth_count = rng.randint(2, 4) if "auth_change" in techniques else 0
        auth_indices = (
            sorted(rng.sample(range(4), min(auth_count, 4)))
            if auth_count
            else []
        )

        auth_results: list[str] = []
        if auth_indices:
            if template_name in ("persistence", "signin_to_auth") and rng.random() < 0.35:
                auth_results = [
                    "Success" if rng.random() < 0.55 else "Failure"
                    for _ in auth_indices
                ]
            else:
                auth_results = ["Success"] * len(auth_indices)

        if "auth_change" in techniques and auth_indices:
            phone_rng = random.Random(seed + 8800 + len(scenarios))
            if phone_rng.random() < 0.4:
                slot = phone_rng.randrange(len(auth_indices))
                auth_indices[slot] = 4
                if slot < len(auth_results):
                    auth_results[slot] = "Success"
            paired = sorted(zip(auth_indices, auth_results), key=lambda item: item[0])
            auth_indices = [index for index, _ in paired]
            auth_results = [result for _, result in paired]

        if template_name == "role_only":
            role_mode = rng.choice(["self", "accomplice", "both"])
        elif template_name in ("privilege_escalation", "signin_to_role", "full_takeover"):
            role_mode = rng.choice(["self", "accomplice", "both"])
        elif "privileged_role" in techniques:
            role_mode = rng.choice(["self", "accomplice"])
        else:
            role_mode = "self"

        role_compromised_success = False
        role_compromised_actor = None
        if "privileged_role" in techniques:
            privileged_actors = [
                user for user in users
                if user["role"] in PRIVILEGED_ACTOR_ROLES
            ]
            if privileged_actors and template_name in (
                "full_takeover", "privilege_escalation", "signin_to_role", "role_only"
            ):
                if rng.random() < 0.65:
                    role_compromised_success = True
                    role_compromised_actor = rng.choice(privileged_actors)

        accomplice = None
        if role_mode in ("accomplice", "both"):
            others = [user for user in candidates if user != victim]
            accomplice = rng.choice(others) if others else None
            if accomplice is None:
                role_mode = "self"

        spray_targets: list[dict] = []
        if "password_spray" in techniques:
            target_count = rng.randint(6, min(14, len(candidates)))
            decoy_candidates = [
                user for user in candidates
                if user not in scenario_victims or user == victim
            ]
            decoy_count = min(target_count - 1, len(decoy_candidates))
            spray_targets = [victim] + rng.sample(decoy_candidates, k=decoy_count)

        scenarios.append(AttackScenario(
            template=template_name,
            techniques=techniques,
            victim=victim,
            anchor=_pick_anchor(rng, base_date),
            spray_compromise=spray_compromise,
            spray_target_count=len(spray_targets) if spray_targets else rng.randint(6, min(14, len(candidates))),
            suspicious_violations=violations,
            auth_option_indices=auth_indices,
            auth_results=auth_results,
            role_mode=role_mode,
            role_compromised_success=role_compromised_success,
            role_compromised_actor=role_compromised_actor,
            accomplice=accomplice,
            spray_targets=spray_targets,
        ))

    return scenarios


def _build_suspicious_signin(rng: random.Random, violation: str, baseline: dict) -> dict:
    risk = rng.choice(SUSPICIOUS_RISK_BY_VIOLATION[violation])

    if violation == "new_country":
        return {
            "ip": ATTACKER_IPS["suspicious_country"],
            "country": pick_unfamiliar_country(baseline["known_countries"]),
            "device": baseline["primary_device"],
            "risk": risk,
            "tag": SUSPICIOUS_VIOLATION_TAGS["new_country"],
        }

    if violation == "unknown_device":
        return {
            "ip": pick_unfamiliar_ip(baseline["common_ips"]),
            "country": rng.choice(baseline["known_countries"]),
            "device": generate_unfamiliar_device(baseline["primary_device"]),
            "risk": risk,
            "tag": SUSPICIOUS_VIOLATION_TAGS["unknown_device"],
        }

    if violation == "tor_exit":
        return {
            "ip": ATTACKER_IPS["tor_exit"],
            "country": pick_unfamiliar_country(baseline["known_countries"]),
            "device": generate_unfamiliar_device(baseline["primary_device"]),
            "risk": risk,
            "tag": SUSPICIOUS_VIOLATION_TAGS["tor_exit"],
        }

    return {
        "ip": ATTACKER_IPS["vpn_proxy"],
        "country": pick_unfamiliar_country(baseline["known_countries"]),
        "device": generate_unfamiliar_device(baseline["primary_device"]),
        "risk": risk,
        "tag": SUSPICIOUS_VIOLATION_TAGS["vpn_proxy"],
    }


def _make_signin(
    timestamp: str,
    user: dict,
    ip: str,
    country: str,
    device: str,
    result: str,
    risk: str,
    scenario_tag: str,
) -> dict:
    return {
        "Timestamp": timestamp,
        "UserPrincipalName": user["user_principal_name"],
        "IPAddress": ip,
        "Country": country,
        "Device": device,
        "AuthenticationResult": result,
        "RiskLevel": risk,
        "ScenarioTag": scenario_tag,
    }


def _make_audit(
    timestamp: str,
    actor: str,
    activity: str,
    target: str,
    result: str,
    details: str,
    scenario_tag: str,
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
    *,
    result: str = "Success",
    old_value: str = "User",
) -> dict:
    return _make_audit(
        timestamp,
        actor,
        "Add member to role",
        target,
        result,
        details,
        scenario_tag,
        modified_property="Role Assignment",
        old_value=old_value,
        new_value=role_name if result == "Success" else old_value,
        role_name=role_name,
    )


def generate_scenario_events(
    scenarios: list[AttackScenario],
    users: list[dict],
    seed: int,
) -> tuple[list[dict], list[dict]]:
    """Generate correlated sign-in and audit events for all scenarios in one pass."""
    signins: list[dict] = []
    audits: list[dict] = []
    candidates = _standard_users(users)

    for index, scenario in enumerate(scenarios):
        rng = random.Random(seed + 10000 + index)
        cursor = scenario.anchor

        if "password_spray" in scenario.techniques:
            spray_targets = scenario.spray_targets
            compromised_upn = (
                scenario.victim["user_principal_name"] if scenario.spray_compromise else None
            )
            elapsed = timedelta(0)

            for user in spray_targets:
                ts = format_ts(cursor + elapsed)
                succeeded = user["user_principal_name"] == compromised_upn
                spray_risk = (
                    rng.choice(SPRAY_SUCCESS_RISKS)
                    if succeeded
                    else rng.choice(SPRAY_FAILURE_RISKS)
                )
                signins.append(_make_signin(
                    ts,
                    user,
                    scenario.attacker_ip,
                    "Netherlands",
                    "UNKNOWN-DEVICE",
                    "Success" if succeeded else "Failure",
                    spray_risk,
                    "password_spray",
                ))
                elapsed += timedelta(
                    minutes=rng.randint(1, 4),
                    seconds=rng.randint(5, 55),
                )

            cursor = cursor + elapsed

        if "suspicious_signin" in scenario.techniques:
            baseline = get_baseline(scenario.victim)
            cursor = _advance(rng, cursor, 8, 25)
            violations = scenario.suspicious_violations or [rng.choice(SUSPICIOUS_VIOLATION_ORDER)]

            for violation in violations:
                event = _build_suspicious_signin(rng, violation, baseline)
                event_time = maybe_apply_off_hours(cursor, baseline["typical_hours"])
                signins.append(_make_signin(
                    format_ts(event_time),
                    scenario.victim,
                    event["ip"],
                    event["country"],
                    event["device"],
                    "Success",
                    event["risk"],
                    event["tag"],
                ))
                cursor = _advance(rng, event_time, 6, 18)

        if "auth_change" in scenario.techniques:
            actor = scenario.victim["user_principal_name"]
            cursor = _advance(rng, cursor, 12, 35)
            indices = scenario.auth_option_indices or sorted(
                rng.sample(range(4), rng.randint(2, 3))
            )
            results = scenario.auth_results or ["Success"] * len(indices)

            for idx, result in zip(indices, results):
                option = AUTH_ATTACK_OPTIONS[idx]
                old_value = option["old_value"]
                if option["activity"] == "Recovery email changed":
                    old_value = actor

                details = option["details"] if result == "Success" else option["failure_details"]
                audits.append(_make_audit(
                    format_ts(cursor),
                    actor,
                    option["activity"],
                    actor,
                    result,
                    details,
                    "auth_change_attack",
                    modified_property=option["modified_property"],
                    old_value=old_value,
                    new_value=option["new_value"] if result == "Success" else old_value,
                ))
                cursor = _advance(rng, cursor, 4, 12)

        if "privileged_role" in scenario.techniques:
            victim_upn = scenario.victim["user_principal_name"]
            cursor = _advance(rng, cursor, 15, 40)

            if scenario.role_mode in ("self", "both"):
                audits.append(_make_role_assignment(
                    format_ts(cursor),
                    victim_upn,
                    victim_upn,
                    "Global Administrator",
                    rng.choice(ROLE_DENIED_DETAILS),
                    "privileged_role_self_elevation",
                    result="Failure",
                ))
                cursor = _advance(rng, cursor, 10, 22)

            if scenario.role_mode in ("accomplice", "both") and scenario.accomplice:
                accomplice = scenario.accomplice
                role_name = rng.choice([
                    "Security Administrator",
                    "Privileged Role Administrator",
                ])
                audits.append(_make_role_assignment(
                    format_ts(cursor),
                    victim_upn,
                    accomplice["user_principal_name"],
                    role_name,
                    rng.choice(ROLE_DENIED_DETAILS),
                    "privileged_role_accomplice",
                    result="Failure",
                ))
                cursor = _advance(rng, cursor, 10, 22)

            if scenario.role_compromised_success and scenario.role_compromised_actor:
                actor = scenario.role_compromised_actor
                actor_upn = actor["user_principal_name"]
                if scenario.role_mode in ("self", "both"):
                    target = scenario.victim
                    role_name = "Global Administrator"
                elif scenario.accomplice:
                    target = scenario.accomplice
                    role_name = (
                        "Security Administrator"
                        if actor["role"] == "Global Administrator"
                        else "Privileged Role Administrator"
                    )
                else:
                    target = scenario.victim
                    role_name = "Security Administrator"

                audits.append(_make_role_assignment(
                    format_ts(cursor),
                    actor_upn,
                    target["user_principal_name"],
                    role_name,
                    f"Assigned {role_name} to {target['display_name']}.",
                    "privileged_role_accomplice",
                    result="Success",
                    old_value=target.get("role", "User"),
                ))

    return signins, audits


def generate_benign_lookalike_signins(
    users: list[dict],
    base_date: datetime,
    seed: int,
) -> list[dict]:
    """Legitimate activity that resembles attacks — supports false-positive tuning."""
    rng = random.Random(seed + 4400)
    logs: list[dict] = []
    candidates = _standard_users(users)
    rng.shuffle(candidates)

    lookalikes = [
        "travel",
        "corporate_vpn",
        "new_laptop",
        "password_typos",
        "remote_worker",
    ]

    for lookalike in lookalikes:
        user = rng.choice(candidates)
        baseline = get_baseline(user)
        day = rng.randint(3, DAYS_OF_HISTORY - 3)
        moment = (base_date - timedelta(days=day)).replace(
            hour=rng.randint(8, 18),
            minute=rng.randint(0, 59),
            second=rng.randint(0, 59),
            microsecond=0,
        )

        if lookalike == "travel":
            country = pick_unfamiliar_country(baseline["known_countries"])
            logs.append(_make_signin(
                format_ts(moment),
                user,
                rng.choice(baseline["common_ips"]),
                country,
                baseline["primary_device"],
                "Success",
                "low",
                "baseline",
            ))

        elif lookalike == "corporate_vpn":
            logs.append(_make_signin(
                format_ts(moment),
                user,
                ATTACKER_IPS["vpn_proxy"],
                rng.choice(baseline["known_countries"]),
                baseline["primary_device"],
                "Success",
                "low",
                "baseline",
            ))

        elif lookalike == "new_laptop":
            logs.append(_make_signin(
                format_ts(moment),
                user,
                rng.choice(baseline["common_ips"]),
                rng.choice(baseline["known_countries"]),
                f"SURFACE-PRO-{rng.randint(10, 99)}",
                "Success",
                "none",
                "baseline",
            ))

        elif lookalike == "password_typos":
            ip = rng.choice(baseline["common_ips"])
            country = rng.choice(baseline["known_countries"])
            device = baseline["primary_device"]
            for attempt in range(rng.randint(3, 5)):
                logs.append(_make_signin(
                    format_ts(moment + timedelta(minutes=attempt * rng.randint(1, 3))),
                    user,
                    ip,
                    country,
                    device,
                    "Failure",
                    "low",
                    "baseline",
                ))
            logs.append(_make_signin(
                format_ts(moment + timedelta(minutes=rng.randint(8, 12))),
                user,
                ip,
                country,
                device,
                "Success",
                "none",
                "baseline",
            ))

        elif lookalike == "remote_worker":
            logs.append(_make_signin(
                format_ts(moment),
                user,
                pick_unfamiliar_ip(baseline["common_ips"]),
                rng.choice(baseline["known_countries"]),
                baseline["primary_device"],
                "Success",
                "none",
                "baseline",
            ))

    return logs


def generate_benign_lookalike_audit(
    users: list[dict],
    base_date: datetime,
    seed: int,
) -> list[dict]:
    """Approved admin and self-service changes that resemble attack audit events."""
    rng = random.Random(seed + 5500)
    logs: list[dict] = []
    standard_users = _standard_users(users)
    admins = [
        user for user in users
        if user["role"] in ("Global Administrator", "Security Administrator")
    ]
    if not admins or not standard_users:
        return logs

    primary_admin = next(user for user in users if user["role"] == "Global Administrator")
    helpdesk = next((user for user in users if user["department"] == "IT"), primary_admin)
    new_hire = rng.choice(standard_users)

    day = rng.randint(5, DAYS_OF_HISTORY - 5)
    onboard_time = (base_date - timedelta(days=day)).replace(
        hour=rng.randint(9, 11),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )

    logs.append(_make_role_assignment(
        format_ts(onboard_time),
        primary_admin["user_principal_name"],
        new_hire["user_principal_name"],
        "Security Administrator",
        f"Assigned role during planned security team expansion for {new_hire['display_name']}",
        "baseline",
    ))

    user = rng.choice(standard_users)
    auth_time = onboard_time + timedelta(days=rng.randint(2, 8), hours=rng.randint(1, 4))
    logs.append(_make_audit(
        format_ts(auth_time),
        user["user_principal_name"],
        "Authentication method added",
        user["user_principal_name"],
        "Success",
        "Registered a new Microsoft Authenticator.",
        "baseline",
        modified_property="Authentication Method",
        old_value="",
        new_value="Microsoft Authenticator",
    ))

    mfa_reset_time = auth_time + timedelta(days=rng.randint(3, 6), hours=rng.randint(2, 5))
    reset_target = rng.choice(standard_users)
    logs.append(_make_audit(
        format_ts(mfa_reset_time),
        helpdesk["user_principal_name"],
        "MFA disabled",
        reset_target["user_principal_name"],
        "Success",
        f"MFA disabled for the account per helpdesk ticket #{rng.randint(10000, 99999)}.",
        "baseline",
        modified_property="MFA Status",
        old_value="Enabled",
        new_value="Disabled",
    ))

    logs.append(_make_audit(
        format_ts(mfa_reset_time + timedelta(minutes=rng.randint(30, 90))),
        reset_target["user_principal_name"],
        "MFA enabled",
        reset_target["user_principal_name"],
        "Success",
        "User re-registered MFA after helpdesk-assisted reset",
        "baseline",
        modified_property="MFA Status",
        old_value="Disabled",
        new_value="Enabled",
    ))

    recovery_user = rng.choice(standard_users)
    logs.append(_make_audit(
        format_ts(mfa_reset_time + timedelta(days=1, hours=rng.randint(1, 3))),
        recovery_user["user_principal_name"],
        "Recovery email changed",
        recovery_user["user_principal_name"],
        "Success",
        "Updated recovery email address for the account.",
        "baseline",
        modified_property="Recovery Email",
        old_value=recovery_user["user_principal_name"],
        new_value=f"recovery.{recovery_user['user_principal_name']}",
    ))

    return logs
