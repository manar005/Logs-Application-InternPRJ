# DemoCorp Cloud Identity Security Detection Lab

A beginner-friendly lab for learning **cloud identity security detection engineering** and practicing **Microsoft Sentinel KQL** queries.

This is **not** a production application. It generates **realistic synthetic logs** for a fictional company called **DemoCorp**, including both normal activity and simulated attacks.

## What You Get

| Component | Description |
|-----------|-------------|
| **User generator** | 25 employees across HR, Finance, IT, Sales, Security |
| **Sign-in logs** | Successful/failed sign-ins + 4 attack techniques |
| **Audit logs** | Normal admin activity + auth changes & role assignments |
| **Dashboard** | Web UI to browse, filter, and export logs |
| **Documentation** | Attack scenarios with example KQL queries |

## Project Structure

```
/data
  signins.csv          # Generated sign-in logs (CSV)
  signins.json         # Generated sign-in logs (JSON)
  auditlogs.csv        # Generated audit logs (CSV)
  auditlogs.json       # Generated audit logs (JSON)
  users.json           # DemoCorp employee directory

/generator
  config.py            # Shared settings (company name, IPs, counts)
  generate_users.py    # Create fictional employees
  generate_signins.py  # Create sign-in + attack events
  generate_audit_logs.py
  generate.py          # Regenerate all log data

run.py                 # Start the dashboard (only way to run the app)
app.py                 # Flask routes and API (do not run directly)

/dashboard
  templates/           # HTML dashboard
  static/              # CSS and JavaScript

/docs
  attack_scenarios.md  # Attack details + KQL examples
```

## Quick Start

### Prerequisites

- Python 3.10 or newer
- pip

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate synthetic logs

```bash
python generator/generate.py
```

This creates all files in the `/data` folder.

### 3. Start the dashboard

```bash
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

## How Logs Are Generated

### Users (`generate_users.py`)

Creates 25 DemoCorp employees with:

- **Departments:** HR, Finance, IT, Sales, Security
- **Roles:** User (most), Security Administrator (4), Global Administrator (1)
- **Known countries** and **primary devices** for baseline sign-in behavior

### Sign-In Logs (`generate_signins.py`)

Generates ~30 days of activity:

**Baseline (normal):**
- Daily successful sign-ins from office/remote IPs
- Occasional failed sign-ins (typos)
- Known countries and familiar devices

**Attack simulations:**

| Technique | ScenarioTag | What to detect |
|-----------|-------------|----------------|
| Password Spraying | `password_spray` | One IP, many users, rapid failures |
| New country sign-in | `suspicious_new_country` | Geo anomaly |
| Unknown device | `suspicious_unknown_device` | Device anomaly |
| TOR exit | `suspicious_tor_exit` | Malicious IP |
| VPN/proxy | `suspicious_vpn_proxy` | Anonymous infrastructure |

### Audit Logs (`generate_audit_logs.py`)

**Baseline:**
- Onboarding role assignment
- MFA enrollment
- Helpdesk password reset

**Attack simulations:**

| Technique | ScenarioTag | What to detect |
|-----------|-------------|----------------|
| Auth method changes | `auth_change_attack` | MFA tampering after compromise |
| Self-elevation | `privileged_role_self_elevation` | User grants self Global Admin |
| Accomplice elevation | `privileged_role_accomplice` | Security Admin assigned by attacker |

## Log Schemas

### Sign-In Logs

| Field | Description |
|-------|-------------|
| Timestamp | ISO 8601 UTC |
| UserPrincipalName | user@democorp.com |
| IPAddress | Source IP |
| Country | Sign-in country |
| Device | Client device name |
| AuthenticationResult | Success or Failure |
| RiskLevel | none, low, medium, high |
| ScenarioTag | baseline or attack identifier |

### Audit Logs

| Field | Description |
|-------|-------------|
| Timestamp | ISO 8601 UTC |
| Actor | Who performed the action |
| Activity | Action type |
| TargetUser | Affected account |
| Result | Success or Failure |
| Details | Human-readable description |
| ScenarioTag | baseline or attack identifier |

## Dashboard Features

- **Sign-In Logs** tab — browse authentication events
- **Audit Logs** tab — browse identity/admin events
- **Search & filter** by user, IP, country, result, activity, risk level
- **Export to CSV** — download filtered results

## Using Data for KQL Practice

1. Upload CSV files to Azure Log Analytics as custom logs, or
2. Use the [Log Analytics demo experience](https://learn.microsoft.com/azure/sentinel/quickstart-get-visibility) and adapt field names, or
3. Practice query logic in the dashboard first, then port to Sentinel

See **[docs/attack_scenarios.md](docs/attack_scenarios.md)** for:

- Detailed attack narratives
- Indicator tables
- Copy-paste KQL examples per technique
- Suggested detection engineering workflow

## Extending the Lab

All generators are intentionally simple Python scripts with comments. To add a new attack:

1. Add a function in `generate_signins.py` or `generate_audit_logs.py`
2. Use a unique `ScenarioTag` value
3. Call your function from `generate_all_signins()` or `generate_all_audit_logs()`
4. Document the scenario in `docs/attack_scenarios.md`
5. Re-run `python generator/generate.py`

Edit `generator/config.py` to change employee count, date range, or attacker IPs.

## Disclaimer

All data is **synthetic**. User names, IPs (mostly RFC 5737 ranges), and events are fictional. Do not use this lab as a template for production security controls.
