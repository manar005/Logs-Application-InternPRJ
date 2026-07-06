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
    KNOWN_COUNTRIES,
    SIGNINS_CSV,
    SIGNINS_JSON,
    SUSPICIOUS_COUNTRIES,
    USERS_FILE,
)

# Office IP ranges used for normal employee sign-ins
OFFICE_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.2.20",
    "172.16.0.5", "172.16.0.6", "192.168.1.100",
]

# Home/remote IPs for normal remote work
REMOTE_IPS = [
    "73.45.120.10", "98.118.45.22", "81.2.69.100",
    "142.250.80.10", "24.6.88.55",
]

RISK_LEVELS = ["none", "low", "medium", "high"]


def _load_users(path: str = USERS_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _random_timestamp(base: datetime, day_offset: int, hour_range: tuple[int, int] = (8, 18)) -> str:
    """Return an ISO timestamp on a given day within business hours."""
    hour = random.randint(hour_range[0], hour_range[1])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = (base - timedelta(days=day_offset)).replace(hour=hour, minute=minute, second=second)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


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
    """Create normal daily sign-in activity for all employees."""
    logs = []

    for day in range(DAYS_OF_HISTORY):
        # Not every user signs in every day
        active_users = random.sample(users, k=random.randint(len(users) // 2, len(users)))

        for user in active_users:
            country = random.choice(user["known_countries"])
            device = user["primary_device"] if random.random() > 0.15 else random.choice(
                [u["primary_device"] for u in users]
            )
            ip = random.choice(OFFICE_IPS if random.random() > 0.3 else REMOTE_IPS)
            ts = _random_timestamp(base_date, day)

            logs.append(_make_signin(
                ts, user, ip, country, device, "Success", "none", "baseline"
            ))

            # Occasional typo-style failed login (wrong password once)
            if random.random() < 0.05:
                fail_ts = _random_timestamp(base_date, day, (8, 18))
                logs.append(_make_signin(
                    fail_ts, user, ip, country, device, "Failure", "low", "baseline"
                ))

    return logs


def generate_password_spray(users: list[dict], base_date: datetime) -> list[dict]:
    """
    Technique 1: Password Spraying
    One IP tries many accounts in a short window; optional success at the end.
    """
    logs = []
    attacker_ip = ATTACKER_IPS["password_spray"]
    spray_day = 3  # Recent enough to stand out in queries
    spray_hour = 2  # Off-hours

    # Target 12 random users (not admins ideally)
    targets = [u for u in users if u["role"] == "User"]
    spray_targets = random.sample(targets, k=min(12, len(targets)))

    base_ts = (base_date - timedelta(days=spray_day)).replace(
        hour=spray_hour, minute=0, second=0
    )

    for i, user in enumerate(spray_targets):
        ts = (base_ts + timedelta(minutes=i * 2, seconds=random.randint(0, 30))).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        logs.append(_make_signin(
            ts, user, attacker_ip, "Netherlands", "UNKNOWN-DEVICE",
            "Failure", "medium", "password_spray"
        ))

    # Attacker succeeds on one account after the spray
    victim = spray_targets[-1]
    success_ts = (base_ts + timedelta(minutes=len(spray_targets) * 2 + 5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    logs.append(_make_signin(
        success_ts, victim, attacker_ip, "Netherlands", "UNKNOWN-DEVICE",
        "Success", "high", "password_spray"
    ))

    return logs


def generate_suspicious_signins(users: list[dict], base_date: datetime) -> list[dict]:
    """
    Technique 2: Suspicious Sign-In Activity
    New country, unknown device, TOR exit, VPN/proxy.
    """
    logs = []
    victim = random.choice([u for u in users if u["role"] == "User"])
    day = 2

    scenarios = [
        # Sign-in from a country the user has never used
        {
            "ip": ATTACKER_IPS["suspicious_country"],
            "country": random.choice(SUSPICIOUS_COUNTRIES),
            "device": victim["primary_device"],
            "risk": "high",
            "tag": "suspicious_new_country",
        },
        # Unfamiliar device from a known country
        {
            "ip": random.choice(REMOTE_IPS),
            "country": victim["known_countries"][0],
            "device": "LINUX-KALI-UNKNOWN",
            "risk": "medium",
            "tag": "suspicious_unknown_device",
        },
        # TOR exit node
        {
            "ip": ATTACKER_IPS["tor_exit"],
            "country": "Germany",
            "device": "TOR-BROWSER",
            "risk": "high",
            "tag": "suspicious_tor_exit",
        },
        # Anonymous proxy / VPN-like IP
        {
            "ip": ATTACKER_IPS["vpn_proxy"],
            "country": "Singapore",
            "device": "CHROME-HEADLESS",
            "risk": "high",
            "tag": "suspicious_vpn_proxy",
        },
    ]

    for i, s in enumerate(scenarios):
        ts = (base_date - timedelta(days=day, hours=5 - i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(_make_signin(
            ts, victim, s["ip"], s["country"], s["device"],
            "Success", s["risk"], s["tag"]
        ))

    return logs


def generate_all_signins(users: list[dict] | None = None, seed: int = 42) -> list[dict]:
    """Combine baseline and attack sign-in logs, sorted by timestamp."""
    random.seed(seed)
    if users is None:
        users = _load_users()

    base_date = datetime.utcnow().replace(microsecond=0)

    logs = []
    logs.extend(generate_baseline_signins(users, base_date))
    logs.extend(generate_password_spray(users, base_date))
    logs.extend(generate_suspicious_signins(users, base_date))

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
