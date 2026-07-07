# Attack Scenarios — DemoCorp Detection Lab

This document describes each simulated attack technique, what to look for in the logs, and example KQL queries you can adapt for Microsoft Sentinel.

> **Note:** These queries target the synthetic field names in this lab. In real Sentinel, map fields to `SigninLogs` and `AuditLogs` table columns (e.g. `UserPrincipalName`, `IPAddress`, `LocationDetails.countryOrRegion`).

---

## Detection Philosophy

Write detections from **observable behavior**, not from pre-labeled attack metadata.

| Field | Role in detection engineering |
|-------|-------------------------------|
| `IPAddress`, `Country`, `Device`, `AuthenticationResult`, `Timestamp`, `UserPrincipalName` | **Primary** sign-in indicators — use these in production-style queries |
| `Activity`, `ModifiedProperty`, `OldValue`, `NewValue`, `RoleName`, `Actor`, `TargetUser` | **Primary** audit indicators |
| `RiskLevel` | **Supporting signal only** — varies across normal and suspicious events; do not make it the main filter |
| `ScenarioTag` | **Validation only** — use after writing a query to confirm true positives in this lab; do not use in final detection logic |

`RiskLevel` values in this dataset include `none`, `low`, `medium`, and `high`. Suspicious activity may appear as `low` or `medium`, and some normal sign-ins may occasionally be `low`. Build rules that would still fire without `RiskLevel` present.

---

## How to Validate Attack Rows

Every generated record includes a `ScenarioTag` column for **lab validation only**:

| ScenarioTag | Technique | Log Type |
|-------------|-----------|----------|
| `baseline` | Normal activity | Sign-in / Audit |
| `password_spray` | Password Spraying | Sign-in |
| `suspicious_new_country` | Suspicious Sign-In | Sign-in |
| `suspicious_unknown_device` | Suspicious Sign-In | Sign-in |
| `suspicious_tor_exit` | Suspicious Sign-In | Sign-in |
| `suspicious_vpn_proxy` | Suspicious Sign-In | Sign-in |
| `auth_change_attack` | Authentication Changes | Audit |
| `privileged_role_self_elevation` | Privileged Role Assignment | Audit |
| `privileged_role_accomplice` | Privileged Role Assignment | Audit |

After you write a behavior-based query, filter by `ScenarioTag` in the dashboard or CSV/JSON export to confirm you found the intended attack rows.

---

## Scenario-Based Attack Generation

The generator produces **12 realistic attack scenarios** per dataset run. Each scenario represents a plausible identity incident — not a random mix of techniques.

Events within a scenario are correlated naturally using existing fields:

- Same `UserPrincipalName` for spray compromise, suspicious sign-in, and follow-on audit actions
- `Actor` / `TargetUser` relationships for self-service auth changes and role assignments
- `IPAddress` reuse across spray and post-compromise activity
- `Timestamp` sequencing — correlated steps occur minutes apart on the same day

There are **no** artificial correlation fields (`AttackID`, `CorrelationID`, `ChainID`).

### Scenario Catalog

| Scenario | Techniques | Description |
|----------|------------|-------------|
| Credential Attack | Password Spray | Spray with no successful compromise |
| Initial Access | Spray → Suspicious Sign-In | Compromise followed by risky sign-in |
| Persistence | Suspicious Sign-In → Auth Changes | Post-compromise MFA/recovery tampering |
| Privilege Escalation | Suspicious Sign-In → Role Assignment | Risky sign-in then privileged role grant |
| Full Account Takeover | Spray → Sign-In → Auth → Role | Complete compromise chain |
| Spray → Sign-In | Spray → Suspicious Sign-In | Partial chain after spray success |
| Spray → Auth | Spray → Auth Changes | Persistence without separate suspicious sign-in tag |
| Sign-In → Auth | Suspicious Sign-In → Auth Changes | Partial chain from risky sign-in |
| Sign-In → Role | Suspicious Sign-In → Role Assignment | Escalation after risky sign-in |
| Sign-In Only | Suspicious Sign-In | Risky sign-in with no follow-up |
| Auth Only | Auth Changes | Standalone authentication tampering |
| Role Only | Role Assignment | Standalone privileged role attempt |

### Failed Attacks

Some scenarios include realistic failures:

- Password spray with **no** successful login (`credential_attack`)
- Authentication changes with `Result = Failure` (Conditional Access blocked)
- Privileged role assignment with `Result = Failure` (insufficient privileges)

These support detection tuning and understanding partial compromise attempts.

### Benign Lookalikes (False Positives)

The dataset also includes **baseline** activity that resembles attacks:

| Resembles | Benign Example | ScenarioTag |
|-----------|----------------|-------------|
| Suspicious country sign-in | Employee travelling abroad | `baseline` |
| VPN/proxy IP sign-in | Corporate VPN access | `baseline` |
| Unknown device | New corporate laptop (`SURFACE-PRO-*`) | `baseline` |
| Password spray pattern | User mistypes password several times, then succeeds | `baseline` |
| Auth changes | Helpdesk MFA reset, user re-enrolls Authenticator | `baseline` |
| Role assignment | Approved admin onboarding during team expansion | `baseline` |

Use these events to practice suppression logic and reduce false positives.

### Multi-Event Correlation Example (KQL)

```kql
// Users with suspicious sign-in followed by auth changes within 2 hours
let RiskySignIns = SigninLogs
    | where ScenarioTag startswith "suspicious_"
    | project SignInTime = Timestamp, UserPrincipalName, SignInIP = IPAddress;
RiskySignIns
| join kind=inner (
    AuditLogs
    | where Activity in (
        "Authentication method added", "Authentication method removed",
        "MFA disabled", "Recovery email changed"
      )
    | where Result == "Success"
    | project AuthTime = Timestamp, UserPrincipalName = TargetUser, Activity, Result
  ) on UserPrincipalName
| where AuthTime between (SignInTime .. SignInTime + 2h)
| project UserPrincipalName, SignInTime, SignInIP, AuthTime, Activity
```

```kql
// Full chain: spray success → suspicious sign-in → privileged role (same user, same day)
let SpraySuccess = SigninLogs
    | where ScenarioTag == "password_spray" and AuthenticationResult == "Success"
    | project SprayTime = Timestamp, UserPrincipalName, SprayIP = IPAddress;
let Suspicious = SigninLogs
    | where ScenarioTag startswith "suspicious_"
    | project SuspiciousTime = Timestamp, UserPrincipalName;
SpraySuccess
| join kind=inner Suspicious on UserPrincipalName
| join kind=inner (
    AuditLogs
    | where ScenarioTag in ("privileged_role_self_elevation", "privileged_role_accomplice")
    | project RoleTime = Timestamp, UserPrincipalName = Actor, RoleName, Result
  ) on UserPrincipalName
| where SuspiciousTime between (SprayTime .. SprayTime + 3h)
| where RoleTime between (SuspiciousTime .. SuspiciousTime + 3h)
| project UserPrincipalName, SprayTime, SprayIP, SuspiciousTime, RoleTime, RoleName, Result
```

---

## Technique 1: Password Spraying

### What Happens

A single external IP (`203.0.113.45`) attempts failed authentication against many DemoCorp user accounts within a short time window (off-hours). After the spray, one account succeeds — simulating a guessed password.

### Indicators

- Same `IPAddress` across many distinct `UserPrincipalName` values
- `AuthenticationResult` = `Failure` for most attempts
- Clustered `Timestamp` values (minutes apart)
- Optional `Success` from the same IP shortly after failures
- Shared unfamiliar `Device` (e.g. `UNKNOWN-DEVICE`) and external `Country` (e.g. `Netherlands`)
- `RiskLevel` may be `none`, `low`, or `medium` on failures; optional success may be `medium` or `high`

### Example KQL (Sign-In Logs)

```kql
// Password spray: one IP, many users, multiple failures in 1 hour
SigninLogs
| where Timestamp > ago(7d)
| where AuthenticationResult == "Failure"
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(UserPrincipalName),
    FirstAttempt = min(Timestamp),
    LastAttempt = max(Timestamp)
  by IPAddress
| where FailedAttempts >= 5 and TargetUsers >= 5
| order by FailedAttempts desc
```

```kql
// Same IP targets many accounts, then one success (spray + compromise pattern)
SigninLogs
| where IPAddress == "203.0.113.45"
| summarize
    Users = dcount(UserPrincipalName),
    Failures = countif(AuthenticationResult == "Failure"),
    Successes = countif(AuthenticationResult == "Success")
  by IPAddress
| where Users >= 5 and Failures >= 4 and Successes >= 1
```

```kql
// Lab validation only — confirm spray rows after your detection fires
SigninLogs
| where ScenarioTag == "password_spray"
| order by Timestamp asc
```

---

## Technique 2: Suspicious Sign-In Activity

### What Happens

A compromised user account signs in from:

1. A **new country** never seen for that user (e.g. Russia, Nigeria)
2. An **unfamiliar device** (e.g. `LINUX-KALI-1234`, `ANDROID-9889`)
3. A **TOR exit node** IP (`198.51.100.77`)
4. A **VPN/proxy-like** IP (`192.0.2.88`)

### Indicators

- `Country` outside the user's normal sign-in pattern (compare against historical sign-ins)
- Unknown `Device` name that does not match corporate naming (e.g. `LINUX-KALI-*`, `ANDROID-*`, `UNKNOWN-DEVICE`)
- Known malicious infrastructure `IPAddress` values (TOR, VPN/proxy, suspicious-country source)
- Sign-in `Timestamp` may fall outside normal working hours
- `AuthenticationResult` = `Success` (attacker gained access)
- `RiskLevel` may be `low`, `medium`, or `high` — treat as enrichment, not the primary rule condition

### Example KQL (Sign-In Logs)

```kql
// Sign-ins from TOR exit node (lab IP)
SigninLogs
| where IPAddress == "198.51.100.77"
| project Timestamp, UserPrincipalName, IPAddress, Country, Device, AuthenticationResult, RiskLevel
```

```kql
// Sign-ins from VPN/proxy or suspicious-country infrastructure
SigninLogs
| where IPAddress in ("192.0.2.88", "203.0.113.99")
| where AuthenticationResult == "Success"
| project Timestamp, UserPrincipalName, IPAddress, Country, Device
```

```kql
// Unfamiliar device names (behavior-based, no RiskLevel filter)
SigninLogs
| where Device matches regex @"(LINUX-KALI|ANDROID|IOS|WINDOWS-DESKTOP)-\d+"
    or Device == "UNKNOWN-DEVICE"
| where AuthenticationResult == "Success"
| order by Timestamp desc
```

```kql
// Sign-in from suspicious countries
SigninLogs
| where Country in ("Russia", "Nigeria", "North Korea", "Brazil")
| where AuthenticationResult == "Success"
| project Timestamp, UserPrincipalName, Country, IPAddress, Device
```

---

## Technique 3: Authentication Changes

### What Happens

Shortly after a suspicious sign-in (typically 25–50 minutes later in the dataset), a user account undergoes rapid authentication changes:

- Authentication method added (FIDO2 key)
- Authentication method removed (Authenticator app)
- MFA disabled (`MFA Status`: Enabled → Disabled)
- Recovery email updated to external address (`attacker@mail.ru`)

### Indicators

- Multiple auth-related `Activity` values for the same `TargetUser` in a short window
- Same `Actor` and `TargetUser` (self-service changes by the compromised account)
- `ModifiedProperty` values such as `Authentication Method`, `MFA Status`, `Recovery Email`
- `OldValue` / `NewValue` show weakening controls (e.g. MFA disabled, external recovery email)
- Changes follow suspicious sign-in chronologically (same day, short offset)

### Example KQL (Audit Logs)

```kql
// Multiple auth changes for one user in 1 hour
AuditLogs
| where Activity in (
    "Authentication method added",
    "Authentication method removed",
    "MFA disabled",
    "Recovery email changed"
  )
| summarize ChangeCount = count(), Activities = make_set(Activity) by TargetUser, bin(Timestamp, 1h)
| where ChangeCount >= 3
```

```kql
// MFA disabled via self-service change
AuditLogs
| where Activity == "MFA disabled"
| where ModifiedProperty == "MFA Status"
| where OldValue == "Enabled" and NewValue == "Disabled"
| where Actor == TargetUser
| project Timestamp, Actor, TargetUser, Activity, ModifiedProperty, OldValue, NewValue
```

```kql
// Recovery email changed to external domain
AuditLogs
| where Activity == "Recovery email changed"
| where ModifiedProperty == "Recovery Email"
| where NewValue endswith "mail.ru" or NewValue !endswith "democorp.com"
| project Timestamp, Actor, TargetUser, OldValue, NewValue, Details
```

```kql
// Lab validation only
AuditLogs
| where ScenarioTag == "auth_change_attack"
| order by Timestamp asc
```

---

## Technique 4: Privileged Role Assignment

### What Happens

1. A **standard user** assigns themselves **Global Administrator** (unusual actor)
2. The same compromised account assigns **Security Administrator** to an accomplice
3. A **baseline** comparison: legitimate admin assigns Security Admin during planned expansion

### Indicators

- `Activity` = `Add member to role`
- `RoleName` is a privileged role (`Global Administrator`, `Security Administrator`, `Privileged Role Administrator`)
- `ModifiedProperty` = `Role Assignment` with `NewValue` showing the privileged role
- `Actor` is a standard user account (not a known Global Administrator)
- Self-elevation: `Actor` == `TargetUser` with `RoleName` = `Global Administrator`
- Accomplice pattern: standard user assigns privileged role to another user

### Example KQL (Audit Logs)

```kql
// Privileged role assignments by role name
AuditLogs
| where Activity == "Add member to role"
| where RoleName in (
    "Global Administrator",
    "Security Administrator",
    "Privileged Role Administrator"
  )
| project Timestamp, Actor, TargetUser, RoleName, ModifiedProperty, OldValue, NewValue, Details
```

```kql
// Self-elevation: non-admin assigns Global Administrator to themselves
AuditLogs
| where Activity == "Add member to role"
| where RoleName == "Global Administrator"
| where Actor == TargetUser
| where ModifiedProperty == "Role Assignment"
| project Timestamp, Actor, TargetUser, RoleName, OldValue, NewValue
```

```kql
// Privileged role granted by a standard user (actor is not the directory admin)
let KnownAdmins = AuditLogs
    | where RoleName == "Global Administrator" and Actor != TargetUser
    | summarize by Actor;
AuditLogs
| where Activity == "Add member to role"
| where RoleName in ("Global Administrator", "Security Administrator", "Privileged Role Administrator")
| where Actor !in (KnownAdmins)
| project Timestamp, Actor, TargetUser, RoleName
```

```kql
// Correlate privileged role change after suspicious sign-in (behavior-based join)
let SuspiciousSignIns = SigninLogs
    | where IPAddress in ("198.51.100.77", "192.0.2.88", "203.0.113.99")
        or Device matches regex @"(LINUX-KALI|ANDROID|IOS|WINDOWS-DESKTOP)-\d+"
    | distinct UserPrincipalName;
AuditLogs
| where Activity == "Add member to role"
| where RoleName in ("Global Administrator", "Security Administrator", "Privileged Role Administrator")
| where Actor in (SuspiciousSignIns) or TargetUser in (SuspiciousSignIns)
| order by Timestamp desc
```

```kql
// Lab validation only
AuditLogs
| where ScenarioTag in ("privileged_role_self_elevation", "privileged_role_accomplice")
| order by Timestamp asc
```

---

## Suggested Detection Engineering Workflow

1. **Ingest** `signins.csv` and `auditlogs.csv` into a Log Analytics workspace (Custom Logs or upload for practice).
2. **Explore** baseline noise — understand normal sign-in volume, countries, devices, and admin activity.
3. **Write** a behavior-based detection query for one technique using `IPAddress`, `Device`, `Activity`, `RoleName`, etc.
4. **Validate** against `ScenarioTag` only to confirm true positives in the lab data — remove `ScenarioTag` from the production query.
5. **Tune** thresholds (failure counts, time windows) to reduce false positives.
6. **Extend** the generators in `/generator` to add new attack patterns and re-test.

---

## Attacker Infrastructure Reference

| IP Address | Purpose |
|------------|---------|
| `203.0.113.45` | Password spray source |
| `198.51.100.77` | TOR exit node |
| `192.0.2.88` | VPN / anonymous proxy |
| `203.0.113.99` | Suspicious country sign-in |

These use RFC 5737 documentation ranges where possible for safe lab use.
