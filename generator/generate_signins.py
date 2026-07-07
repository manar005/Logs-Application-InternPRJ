"""
Generate synthetic Azure AD-style sign-in logs for DemoCorp.

Includes:
  - Baseline successful and failed sign-ins from known locations/devices
  - Benign lookalike sign-ins for false-positive tuning
  - Scenario-based attack sign-ins (correlated multi-step chains)
"""

import csv
import json
import os
import random
from datetime import datetime, timedelta

from attack_scenarios import generate_benign_lookalike_signins
from config import DAYS_OF_HISTORY, SIGNINS_CSV, SIGNINS_JSON, USERS_FILE
from user_baseline import assign_baseline_profiles, get_baseline, random_baseline_signin_timestamp


def _load_users(path: str = USERS_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _ensure_user_baselines(users: list[dict], seed: int) -> list[dict]:
    if users and "_baseline" not in users[0]:
        return assign_baseline_profiles(users, seed)
    return users


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
        "ScenarioTag": scenario_tag,
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

                success_risk = "low" if random.random() < 0.04 else "none"
                logs.append(_make_signin(
                    ts, user, ip, country, device, "Success", success_risk, "baseline"
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


def generate_all_signins(
    users: list[dict] | None = None,
    seed: int = 42,
    *,
    base_date: datetime | None = None,
    scenario_signins: list[dict] | None = None,
) -> list[dict]:
    """Combine baseline, benign lookalikes, and scenario attack sign-ins."""
    random.seed(seed)
    if users is None:
        users = _load_users()

    users = _ensure_user_baselines(users, seed)
    if base_date is None:
        base_date = datetime.utcnow().replace(microsecond=0)
    if scenario_signins is None:
        from attack_scenarios import generate_scenario_events, plan_attack_scenarios

        scenarios = plan_attack_scenarios(users, base_date, seed)
        scenario_signins, _ = generate_scenario_events(scenarios, users, seed)

    logs = []
    logs.extend(generate_baseline_signins(users, base_date))
    logs.extend(generate_benign_lookalike_signins(users, base_date, seed))
    logs.extend(scenario_signins)

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
