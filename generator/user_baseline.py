"""
In-memory user sign-in baselines for realistic log generation.

Baseline profiles are attached during generation to guide normal and suspicious
sign-in events. They are stripped before users.json is saved and never appear in
exported sign-in or audit logs.
"""

import random
from datetime import datetime, timedelta

from config import KNOWN_COUNTRIES, SUSPICIOUS_COUNTRIES, format_ts

# IP pools used to build per-user common sign-in addresses
OFFICE_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.2.20",
    "172.16.0.5", "172.16.0.6", "192.168.1.100",
]

REMOTE_IPS = [
    "73.45.120.10", "98.118.45.22", "81.2.69.100",
    "142.250.80.10", "24.6.88.55",
]

ALL_USER_IPS = OFFICE_IPS + REMOTE_IPS

UNFAMILIAR_DEVICE_PREFIXES = [
    "WINDOWS-DESKTOP",
    "LINUX-KALI",
    "MACBOOK",
    "ANDROID",
    "IOS",
]


def assign_baseline_profiles(users: list[dict], seed: int = 42) -> list[dict]:
    """Attach a sign-in baseline to each user and export common_ips in the profile."""
    rng = random.Random(seed + 100)
    enriched = []

    for user in users:
        if "common_ips" in user:
            common_ips = list(user["common_ips"])
        else:
            common_ips = rng.sample(ALL_USER_IPS, k=rng.randint(1, 3))

        baseline = {
            "known_countries": list(user["known_countries"]),
            "primary_device": user["primary_device"],
            "typical_hours": (rng.randint(7, 9), rng.randint(16, 18)),
            "common_ips": common_ips,
        }
        enriched.append({**user, "common_ips": common_ips, "_baseline": baseline})

    return enriched


def strip_baseline_for_export(user: dict) -> dict:
    """Remove internal baseline metadata while keeping exported profile fields."""
    return {
        key: value
        for key, value in user.items()
        if key != "_baseline"
    }


def get_baseline(user: dict) -> dict:
    """Return the in-memory baseline profile for a user."""
    baseline = user["_baseline"]
    if "common_ips" in user:
        return {**baseline, "common_ips": list(user["common_ips"])}
    return baseline


def random_baseline_signin_timestamp(
    base_date: datetime,
    day_offset: int,
    typical_hours: tuple[int, int],
    *,
    is_weekend: bool = False,
) -> str:
    """Generate a sign-in time that mostly follows the user's normal hours."""
    start_hour, end_hour = typical_hours
    day_date = base_date - timedelta(days=day_offset)

    if is_weekend:
        if random.random() < 0.35:
            hour_range = (start_hour, end_hour)
        elif random.random() < 0.7:
            hour_range = (18, 22)
        else:
            hour_range = (5, 7) if random.random() < 0.5 else (22, 23)
    elif random.random() < 0.85:
        hour_range = (start_hour, end_hour)
    elif random.random() < 0.7:
        hour_range = (end_hour + 1, min(end_hour + 4, 22))
    else:
        hour_range = (max(5, start_hour - 3), start_hour - 1)

    hour = random.randint(hour_range[0], hour_range[1])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    dt = day_date.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return format_ts(dt)


def pick_unfamiliar_country(known_countries: list[str]) -> str:
    """Choose a plausible country outside the user's normal sign-in countries."""
    options = [
        country for country in (KNOWN_COUNTRIES + SUSPICIOUS_COUNTRIES)
        if country not in known_countries
    ]
    return random.choice(options) if options else random.choice(SUSPICIOUS_COUNTRIES)


def generate_unfamiliar_device(primary_device: str) -> str:
    """Generate a device name that clearly differs from the user's primary device."""
    while True:
        prefix = random.choice(UNFAMILIAR_DEVICE_PREFIXES)
        device = f"{prefix}-{random.randint(10, 9999)}"
        if device != primary_device:
            return device


def pick_unfamiliar_ip(common_ips: list[str]) -> str:
    """Choose an IP address outside the user's common sign-in ranges."""
    unfamiliar = [ip for ip in ALL_USER_IPS if ip not in common_ips]
    return random.choice(unfamiliar) if unfamiliar else random.choice(REMOTE_IPS)


def maybe_apply_off_hours(dt: datetime, typical_hours: tuple[int, int]) -> datetime:
    """Occasionally shift a timestamp outside the user's normal working hours."""
    if random.random() > 0.2:
        return dt

    start_hour, end_hour = typical_hours
    off_hours = [hour for hour in range(24) if hour < start_hour or hour > end_hour]
    if not off_hours:
        return dt

    return dt.replace(
        hour=random.choice(off_hours),
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
    )
