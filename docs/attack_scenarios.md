# Attack Scenarios — DemoCorp Detection Lab

This document describes each simulated attack technique, what to look for in the logs, and example KQL queries you can adapt for Microsoft Sentinel.

> **Note:** These queries target the synthetic field names in this lab. In real Sentinel, map fields to `SigninLogs` and `AuditLogs` table columns (e.g. `UserPrincipalName`, `IPAddress`, `LocationDetails.countryOrRegion`).

---

## How to Find Attack Rows

Every generated record includes a `ScenarioTag` column:

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

Use the dashboard or filter CSV/JSON by `ScenarioTag` to validate detections.

---

## Technique 1: Password Spraying

### What Happens

A single external IP (`203.0.113.45`) attempts failed authentication against many DemoCorp user accounts within a short time window (off-hours). After the spray, one account succeeds — simulating a guessed password.

### Indicators

- Same `IPAddress` across many distinct `UserPrincipalName` values
- `AuthenticationResult` = `Failure` for most attempts
- Clustered `Timestamp` values (minutes apart)
- Optional `Success` from the same IP shortly after failures
- `ScenarioTag` = `password_spray`

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
// Lab dataset: filter known spray IP
SigninLogs
| where IPAddress == "203.0.113.45"
| where ScenarioTag == "password_spray"
| order by Timestamp asc
```

---

## Technique 2: Suspicious Sign-In Activity

### What Happens

A compromised user account signs in from:

1. A **new country** never seen for that user (e.g. Russia, Nigeria)
2. An **unfamiliar device** (`LINUX-KALI-UNKNOWN`)
3. A **TOR exit node** IP (`198.51.100.77`)
4. A **VPN/proxy-like** IP (`192.0.2.88`)

### Indicators

- `Country` not in user's historical pattern
- Unknown `Device` name
- Known malicious infrastructure IPs
- Elevated `RiskLevel` (`medium` or `high`)
- `ScenarioTag` starts with `suspicious_`

### Example KQL (Sign-In Logs)

```kql
// Sign-ins from TOR exit node (lab IP)
SigninLogs
| where IPAddress == "198.51.100.77"
| project Timestamp, UserPrincipalName, IPAddress, Country, Device, RiskLevel, ScenarioTag
```

```kql
// High-risk sign-ins from unfamiliar devices
SigninLogs
| where RiskLevel in ("high", "medium")
| where Device has "UNKNOWN" or Device has "TOR"
| order by Timestamp desc
```

```kql
// Sign-in from suspicious countries
SigninLogs
| where Country in ("Russia", "Nigeria", "North Korea")
| where AuthenticationResult == "Success"
```

---

## Technique 3: Authentication Changes

### What Happens

Shortly after a suspicious sign-in (~2 days ago in the dataset), a user account undergoes rapid authentication changes:

- Authentication method added (FIDO2 key)
- Authentication method removed (Authenticator app)
- MFA settings changed (default switched to SMS)
- Recovery email updated to external address

### Indicators

- Multiple `Activity` values related to auth in a short window
- Same `Actor` and `TargetUser` (self-service changes)
- Changes follow suspicious sign-in chronologically
- `ScenarioTag` = `auth_change_attack`

### Example KQL (Audit Logs)

```kql
// Multiple auth changes for one user in 1 hour
AuditLogs
| where Activity in (
    "Authentication method added",
    "Authentication method removed",
    "MFA settings changed",
    "Recovery information updated"
  )
| summarize ChangeCount = count(), Activities = make_set(Activity) by TargetUser, bin(Timestamp, 1h)
| where ChangeCount >= 3
```

```kql
// Lab dataset: auth change attack chain
AuditLogs
| where ScenarioTag == "auth_change_attack"
| order by Timestamp asc
```

```kql
// Recovery info changed to external domain
AuditLogs
| where Activity == "Recovery information updated"
| where Details has "mail.ru" or Details has "external"
```

---

## Technique 4: Privileged Role Assignment

### What Happens

1. A **standard user** assigns themselves **Global Administrator** (unusual actor)
2. The same compromised account assigns **Security Administrator** to an accomplice
3. A **baseline** comparison: legitimate admin assigns Security Admin during planned expansion

### Indicators

- `Activity` = `Add member to role`
- `Details` mentions `Global Administrator` or `Security Administrator`
- `Actor` is not a known admin account
- Role change shortly after suspicious sign-in / auth changes
- `ScenarioTag` = `privileged_role_self_elevation` or `privileged_role_accomplice`

### Example KQL (Audit Logs)

```kql
// Privileged role assignments
AuditLogs
| where Activity == "Add member to role"
| where Details has "Global Administrator" or Details has "Security Administrator"
| project Timestamp, Actor, TargetUser, Details, ScenarioTag
```

```kql
// Role assignment by non-admin actor (lab: actor == target for self-elevation)
AuditLogs
| where ScenarioTag == "privileged_role_self_elevation"
```

```kql
// Correlate privileged role change after risky sign-in (conceptual join)
let RiskyUsers = SigninLogs
    | where RiskLevel == "high"
    | distinct UserPrincipalName;
AuditLogs
| where Activity == "Add member to role"
| where TargetUser in (RiskyUsers)
| order by Timestamp desc
```

---

## Suggested Detection Engineering Workflow

1. **Ingest** `signins.csv` and `auditlogs.csv` into a Log Analytics workspace (Custom Logs or upload for practice).
2. **Explore** baseline noise — understand normal sign-in volume and countries.
3. **Write** a detection query for one technique using the examples above.
4. **Validate** against `ScenarioTag` to confirm true positives in the lab data.
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
