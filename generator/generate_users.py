"""
Generate fictional DemoCorp employee accounts.

Each user has a department, role, known sign-in countries, and a primary device.
This file is run first; sign-in and audit log generators read users.json.
"""

import json
import os
import random

from config import (
    COMPANY_DOMAIN,
    DATA_DIR,
    DEPARTMENTS,
    KNOWN_COUNTRIES,
    KNOWN_DEVICES,
    NUM_EMPLOYEES,
    USERS_FILE,
)
from user_baseline import assign_baseline_profiles, strip_baseline_for_export

# First names and last names for realistic-looking accounts
FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery",
    "Quinn", "Blake", "Cameron", "Drew", "Emery", "Finley", "Harper", "Logan",
    "Parker", "Reese", "Sage", "Skyler", "Dana", "Elliot", "Frankie", "Hayden",
    "Jesse", "Kai", "Lane", "Micah", "Noel", "Rowan",
]

LAST_NAMES = [
    "Anderson", "Bennett", "Campbell", "Davis", "Edwards", "Foster", "Garcia",
    "Hughes", "Irving", "Johnson", "Kim", "Lopez", "Martinez", "Nguyen", "O'Brien",
    "Patel", "Quinn", "Roberts", "Singh", "Thompson", "Upton", "Vasquez", "Walker",
    "Young", "Zimmerman",
]

# Role distribution: most users are standard; a few hold privileged roles
ROLES = ["User"] * 20 + ["Security Administrator"] * 4 + ["Global Administrator"] * 1


def _make_upn(first: str, last: str) -> str:
    """Build a UserPrincipalName like alex.anderson@democorp.com."""
    return f"{first.lower()}.{last.lower()}@{COMPANY_DOMAIN}"


def generate_users(seed: int = 42) -> list[dict]:
    """
    Create NUM_EMPLOYEES users spread across departments.

    Returns a list of user dictionaries ready to save as JSON.
    """
    random.seed(seed)

    # Flatten department counts into a list we can assign one-by-one
    dept_list = []
    for dept, count in DEPARTMENTS.items():
        dept_list.extend([dept] * count)

    if len(dept_list) != NUM_EMPLOYEES:
        raise ValueError(
            f"DEPARTMENTS must sum to NUM_EMPLOYEES ({NUM_EMPLOYEES}), got {len(dept_list)}"
        )

    random.shuffle(dept_list)
    random.shuffle(ROLES)

    used_names = set()
    users = []

    for i in range(NUM_EMPLOYEES):
        # Pick a unique name combination
        while True:
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            if (first, last) not in used_names:
                used_names.add((first, last))
                break

        department = dept_list[i]
        role = ROLES[i] if i < len(ROLES) else "User"

        # Each user has 1-2 familiar countries and one primary device
        home_countries = random.sample(KNOWN_COUNTRIES, k=random.randint(1, 2))
        primary_device = random.choice(KNOWN_DEVICES)

        users.append({
            "display_name": f"{first} {last}",
            "user_principal_name": _make_upn(first, last),
            "department": department,
            "role": role,
            "known_countries": home_countries,
            "primary_device": primary_device,
            "employee_id": f"EMP-{1000 + i:04d}",
        })

    return assign_baseline_profiles(users, seed)


def save_users(users: list[dict], path: str = USERS_FILE) -> None:
    """Write users to JSON and ensure the data directory exists."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    export_users = [strip_baseline_for_export(user) for user in users]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export_users, f, indent=2)
    print(f"Saved {len(export_users)} users to {path}")


if __name__ == "__main__":
    users = generate_users()
    save_users(users)
