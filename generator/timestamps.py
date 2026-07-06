"""
Shared timestamp helpers for realistic DemoCorp log generation.

Attack anchors are planned deterministically from the generator seed so sign-in
and audit logs stay aligned (e.g. auth changes shortly after suspicious sign-ins).
"""

import random
from datetime import datetime, timedelta

from config import DAYS_OF_HISTORY


def format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def random_signin_timestamp(
    base_date: datetime,
    day_offset: int,
    *,
    is_weekend: bool = False,
    is_office: bool = True,
) -> str:
    """Pick a believable sign-in time — mostly business hours, some after-hours."""
    roll = random.random()
    if is_weekend:
        if roll < 0.30:
            hour_range = (7, 18)
        elif roll < 0.70:
            hour_range = (18, 22)
        else:
            hour_range = (5, 7) if random.random() < 0.5 else (22, 23)
    elif is_office:
        if roll < 0.80:
            hour_range = (7, 18)
        elif roll < 0.93:
            hour_range = (18, 22)
        else:
            hour_range = (5, 7) if random.random() < 0.5 else (22, 23)
    else:
        if roll < 0.65:
            hour_range = (7, 18)
        elif roll < 0.88:
            hour_range = (18, 22)
        else:
            hour_range = (6, 7) if random.random() < 0.5 else (22, 23)

    hour = random.randint(hour_range[0], hour_range[1])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    dt = (base_date - timedelta(days=day_offset)).replace(
        hour=hour, minute=minute, second=second, microsecond=0
    )
    return format_ts(dt)


def random_baseline_audit_timestamp(base_date: datetime, day_offset: int) -> str:
    """Pick a believable admin/audit time spread across the day."""
    day_date = base_date - timedelta(days=day_offset)
    is_weekend = day_date.weekday() >= 5
    roll = random.random()

    if is_weekend:
        hour_range = (9, 17) if roll < 0.5 else (17, 21)
    elif roll < 0.82:
        hour_range = (8, 17)
    elif roll < 0.95:
        hour_range = (17, 20)
    else:
        hour_range = (6, 8) if random.random() < 0.5 else (20, 22)

    hour = random.randint(hour_range[0], hour_range[1])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    dt = day_date.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return format_ts(dt)


def plan_attack_timeline(base_date: datetime, seed: int) -> dict:
    """
    Deterministic attack anchors shared by sign-in and audit generators.
    Randomizes placement within the window while preserving intra-attack sequencing.
    """
    rng = random.Random(seed + 9001)

    spray_days_ago = rng.randint(2, 14)
    spray_start = (base_date - timedelta(days=spray_days_ago)).replace(
        hour=rng.choice([0, 1, 2, 3, 4, 5, 22, 23]),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )

    susp_days_ago = rng.randint(1, 20)
    susp_start = (base_date - timedelta(days=susp_days_ago)).replace(
        hour=rng.randint(0, 23),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )
    suspicious_times = [susp_start]
    t = susp_start
    for _ in range(3):
        t = t + timedelta(minutes=rng.randint(6, 22), seconds=rng.randint(8, 55))
        suspicious_times.append(t)

    auth_start = susp_start + timedelta(
        minutes=rng.randint(25, 50),
        seconds=rng.randint(5, 45),
    )
    auth_times = [auth_start]
    t = auth_start
    for _ in range(3):
        t = t + timedelta(minutes=rng.randint(4, 13), seconds=rng.randint(5, 50))
        auth_times.append(t)

    priv_days_ago = rng.randint(1, 18)
    priv_start = (base_date - timedelta(days=priv_days_ago)).replace(
        hour=rng.randint(0, 5) if rng.random() < 0.65 else rng.randint(21, 23),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )
    priv_second = priv_start + timedelta(
        minutes=rng.randint(10, 20),
        seconds=rng.randint(6, 48),
    )

    contrast_days_ago = rng.randint(16, max(17, DAYS_OF_HISTORY - 2))
    contrast_day = base_date - timedelta(days=contrast_days_ago)
    contrast_time = contrast_day.replace(
        hour=rng.randint(8, 16),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=0,
    )

    return {
        "password_spray_start": spray_start,
        "suspicious_signin_times": suspicious_times,
        "auth_change_times": auth_times,
        "privileged_role_times": [priv_start, priv_second],
        "privileged_baseline_time": contrast_time,
    }
