"""
Generate synthetic Azure AD-style sign-in logs for DemoCorp.

Includes:
  - Baseline successful and failed sign-ins from known locations/devices
  - Attack simulations: password spraying, suspicious sign-in activity
"""

import csv
import json
import os
import random
from datetime import datetime, timedelta

from config import (
    ATTACKER_IPS,
    DAYS_OF_HISTORY,
    SIGNINS_CSV,
    SIGNINS_JSON,
    USERS_FILE,
)
from timestamps import format_ts, plan_attack_timeline
from user_baseline import (
    assign_baseline_profiles,
    generate_unfamiliar_device,
    get_baseline,
    maybe_apply_off_hours,
    pick_unfamiliar_country,
    pick_unfamiliar_ip,
    random_baseline_signin_timestamp,
)

# Violation types mapped to existing ScenarioTag values
SUSPICIOUS_VIOLATION_ORDER = [
    "new_country",
    "unknown_device",
    "tor_exit",
    "vpn_proxy",
]


def _load_users(path: str = USERS_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _ensure_user_baselines(users: list[dict], seed: int) -> list[dict]:
    if users and "_baseline" not in users[0]:
        return assign_baseline_profiles(users, seed)
    return users


def _build_suspicious_signin(violation: str, baseline: dict) -> dict:
    """Build one suspicious sign-in by violating part of the user's baseline."""
    if violation == "new_country":
        return {
            "ip": ATTACKER_IPS["suspicious_country"],
            "country": pick_unfamiliar_country(baseline["known_countries"]),
            "device": baseline["primary_device"],
            "risk": "high",
            "tag": "suspicious_new_country",
        }

    if violation == "unknown_device":
        return {
            "ip": pick_unfamiliar_ip(baseline["common_ips"]),
            "country": random.choice(baseline["known_countries"]),
            "device": generate_unfamiliar_device(baseline["primary_device"]),
            "risk": "medium",
            "tag": "suspicious_unknown_device",
        }

    if violation == "tor_exit":
        return {
            "ip": ATTACKER_IPS["tor_exit"],
            "country": pick_unfamiliar_country(baseline["known_countries"]),
            "device": generate_unfamiliar_device(baseline["primary_device"]),
            "risk": "high",
            "tag": "suspicious_tor_exit",
        }

    return {
        "ip": ATTACKER_IPS["vpn_proxy"],
        "country": pick_unfamiliar_country(baseline["known_countries"]),
        "device": generate_unfamiliar_device(baseline["primary_device"]),
        "risk": "high",
        "tag": "suspicious_vpn_proxy",
    }


def _make_signin(
    timestamp: str,
    user: dict,
    ip: str,
    country: str,
    device: str,
    result: str,
    risk: str,
    scenario_tag: str = "baseline",
) -> dict:
    return {
        "Timestamp": timestamp,
        "UserPrincipalName": user["user_principal_name"],
        "IPAddress": ip,
        "Country": country,
        "Device": device,
        "AuthenticationResult": result,
        "RiskLevel": risk,
        "ScenarioTag": scenario_tag,  # Helps learners find attack rows in the dataset
    }


def generate_baseline_signins(users: list[dict], base_date: datetime) -> list[dict]:
    """Create normal daily sign-in activity that follows each user's baseline."""
    logs = []

    for day in range(DAYS_OF_HISTORY):
        day_date = base_date - timedelta(days=day)
        is_weekend = day_date.weekday() >= 5

        for user in users:
            baseline = get_baseline(user)

            if random.random() < (0.25 if is_weekend else 0.12):
                continue

            sessions = random.choices([1, 2, 3], weights=[0.45, 0.4, 0.15])[0]

            for _ in range(sessions):
                country = random.choice(baseline["known_countries"])
                device = baseline["primary_device"]
                ip = random.choice(baseline["common_ips"])
                ts = random_baseline_signin_timestamp(
                    base_date,
                    day,
                    baseline["typical_hours"],
                    is_weekend=is_weekend,
                )

                logs.append(_make_signin(
                    ts, user, ip, country, device, "Success", "none", "baseline"
                ))

            if random.random() < 0.14:
                country = random.choice(baseline["known_countries"])
                device = baseline["primary_device"]
                ip = random.choice(baseline["common_ips"])
                fail_ts = random_baseline_signin_timestamp(
                    base_date,
                    day,
                    baseline["typical_hours"],
                    is_weekend=is_weekend,
                )
                logs.append(_make_signin(
                    fail_ts, user, ip, country, device, "Failure", "low", "baseline"
                ))

    return logs


def generate_suspicious_signins(
    users: list[dict],
    base_date: datetime,
    timeline: dict,
) -> list[dict]:
    """
    Technique 2: Suspicious Sign-In Activity
    One or two baseline violations per attack for a randomly selected user.
    """
    logs = []
    victim = random.choice([u for u in users if u["role"] == "User"])
    baseline = get_baseline(victim)

    indicator_count = random.randint(1, 2)
    selected_violations = sorted(
        random.sample(SUSPICIOUS_VIOLATION_ORDER, indicator_count),
        key=SUSPICIOUS_VIOLATION_ORDER.index,
    )

    for slot, violation in enumerate(selected_violations):
        event = _build_suspicious_signin(violation, baseline)
        event_time = maybe_apply_off_hours(
            timeline["suspicious_signin_times"][slot],
            baseline["typical_hours"],
        )
        ts = format_ts(event_time)
        logs.append(_make_signin(
            ts,
            victim,
            event["ip"],
            event["country"],
            event["device"],
            "Success",
            event["risk"],
            event["tag"],
        ))

    return logs


def generate_password_spray(
    users: list[dict],
    base_date: datetime,
    timeline: dict,
) -> list[dict]:
    """
    Technique 1: Password Spraying
    One IP tries many accounts in a short window; 0–2 accounts may be compromised.
    """
    logs = []
    attacker_ip = ATTACKER_IPS["password_spray"]

    targets = [u for u in users if u["role"] == "User"]
    target_count = random.randint(5, min(15, len(targets)))
    spray_targets = random.sample(targets, k=target_count)

    compromise_count = random.randint(0, 2)
    compromised_upns = (
        {u["user_principal_name"] for u in random.sample(spray_targets, compromise_count)}
        if compromise_count
        else set()
    )

    base_ts = timeline["password_spray_start"]
    elapsed = timedelta(0)

    for user in spray_targets:
        ts = format_ts(base_ts + elapsed)
        succeeded = user["user_principal_name"] in compromised_upns
        logs.append(_make_signin(
            ts, user, attacker_ip, "Netherlands", "UNKNOWN-DEVICE",
            "Success" if succeeded else "Failure",
            "high" if succeeded else "medium",
            "password_spray",
        ))
        elapsed += timedelta(
            minutes=random.randint(1, 5),
            seconds=random.randint(5, 55),
        )

    return logs


def generate_all_signins(users: list[dict] | None = None, seed: int = 42) -> list[dict]:
    """Combine baseline and attack sign-in logs, sorted by timestamp."""
    random.seed(seed)
    if users is None:
        users = _load_users()

    users = _ensure_user_baselines(users, seed)
    base_date = datetime.utcnow().replace(microsecond=0)
    timeline = plan_attack_timeline(base_date, seed)

    logs = []
    logs.extend(generate_baseline_signins(users, base_date))
    logs.extend(generate_password_spray(users, base_date, timeline))
    logs.extend(generate_suspicious_signins(users, base_date, timeline))

    logs.sort(key=lambda x: x["Timestamp"])
    return logs


def save_signins(logs: list[dict]) -> None:
    """Write sign-in logs to CSV and JSON."""
    os.makedirs(os.path.dirname(SIGNINS_CSV), exist_ok=True)

    fieldnames = [
        "Timestamp", "UserPrincipalName", "IPAddress", "Country",
        "Device", "AuthenticationResult", "RiskLevel", "ScenarioTag",
    ]

    with open(SIGNINS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)

    with open(SIGNINS_JSON, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    print(f"Saved {len(logs)} sign-in records to {SIGNINS_CSV} and {SIGNINS_JSON}")


if __name__ == "__main__":
    signins = generate_all_signins()
    save_signins(signins)
