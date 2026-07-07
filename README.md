# DemoCorp Cloud Identity Security Detection Lab

A beginner-friendly lab for learning **cloud identity security detection engineering** and practicing **Microsoft Sentinel KQL** queries.

This is **not** a production application. It generates **realistic synthetic logs** for a fictional company called **DemoCorp**, including both normal activity and simulated attacks.

## What You Get

| Component | Description |
|-----------|-------------|
| **User generator** | 25 employees across HR, Finance, IT, Sales, Security |
| **Sign-in logs** | Rich baseline sign-in activity + 4 attack techniques |
| **Audit logs** | Frequent normal admin/identity activity + auth changes & role assignments |
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
  attack_scenarios.py  # Scenario planner and correlated attack events
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
- High-volume successful sign-ins across the 30-day window (office and remote work)
- Occasional failed sign-ins from normal user mistakes
- Activity spread across users, departments, devices, IPs, and known countries

**Benign lookalikes (false positives):**
- Employee travel to new countries
- Corporate VPN sign-ins (same IP as attack infrastructure, but `baseline` tag)
- New corporate laptop sign-ins
- Password typo bursts (multiple failures then success from same IP)

**Scenario-based attacks** (`attack_scenarios.py`):
- 12 correlated or independent attack scenarios per run
- Multi-step chains (e.g. spray → sign-in → auth changes → role assignment)
- Partial chains and standalone techniques
- Natural correlation via `UserPrincipalName`, `IPAddress`, `Timestamp`, `Actor`, `TargetUser`

| Technique | ScenarioTag | What to detect |
|-----------|-------------|----------------|
| Password Spraying | `password_spray` | One IP, many users, rapid failures |
| New country sign-in | `suspicious_new_country` | Geo anomaly |
| Unknown device | `suspicious_unknown_device` | Device anomaly |
| TOR exit | `suspicious_tor_exit` | Malicious IP |
| VPN/proxy | `suspicious_vpn_proxy` | Anonymous infrastructure |

### Audit Logs (`generate_audit_logs.py`)

**Baseline:**
- Frequent routine events across 30 days, tagged `baseline`, including:
  - Helpdesk password resets
  - MFA and authentication method enrollment or removal
  - Approved role assignments
  - Group and security group membership updates
  - User profile updates
  - License assignment and removal
- Baseline audit volume is intentionally higher than attack events so threats blend into normal noise

**Benign lookalikes (false positives):**
- Approved administrator onboarding
- Helpdesk-assisted MFA reset with re-enrollment
- Legitimate recovery email updates (internal domain)

**Scenario-based attacks:**
- Correlated with sign-in scenarios when techniques chain together
- Some auth changes and role assignments may have `Result = Failure`
- Actor/target relationships vary (self-service, self-elevation, accomplice)

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
| RiskLevel | Supporting signal: none, low, medium, high (do not rely on this alone) |
| ScenarioTag | Lab validation only — baseline or attack identifier |

### Audit Logs

| Field | Description |
|-------|-------------|
| Timestamp | ISO 8601 UTC |
| Actor | Who performed the action |
| Activity | Action type |
| TargetUser | Affected account |
| Result | Success or Failure |
| ModifiedProperty | Changed attribute (e.g. Authentication Method, MFA Status, Role Assignment) |
| OldValue | Value before the change |
| NewValue | Value after the change |
| RoleName | Directory role for role-assignment events |
| Details | Human-readable description |
| ScenarioTag | Lab validation only — baseline or attack identifier |

## Dashboard Features

- **Sign-In Logs** tab — browse authentication events
- **Audit Logs** tab — browse identity/admin events
- **Search & filter** by user, IP, country, result, activity, risk level
- **Export to CSV** — download filtered results

## Using Data for KQL Practice

Detection queries should be written from **behavior-based fields** (`IPAddress`, `Country`, `Device`, `Activity`, `RoleName`, `ModifiedProperty`, etc.). `RiskLevel` is a supporting enrichment signal with varied values across normal and suspicious events. Use `ScenarioTag` only to validate that your query found the intended lab attack rows — not in final detection logic.

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

1. Add a scenario template in `generator/attack_scenarios.py`
2. Use existing `ScenarioTag` values for the techniques involved
3. Add the template to `DEFAULT_SCENARIO_SEQUENCE` if it should appear each run
4. Document the scenario in `docs/attack_scenarios.md`
5. Re-run `python generator/generate.py`

Edit `generator/config.py` to change employee count, date range, or attacker IPs.

## Disclaimer

All data is **synthetic**. User names, IPs (mostly RFC 5737 ranges), and events are fictional. Do not use this lab as a template for production security controls.
