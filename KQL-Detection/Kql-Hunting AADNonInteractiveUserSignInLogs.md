---
date: 2026-05-12
title: Untitled
table: "AADNonInteractiveUserSignInLogs"
schema: "Sentinel"
mitre: ""
tactic: ""
technique: ""
status: Deployed
promoted_to_rule: true
mde_rule_name: "Hunting - NonInteractive Sign-ins by Account"
sentinel_rule_id: ""
tags:
  - "#detection/hunting"
  - "#status/deployed"
  
---

# Hunting - NonInteractive Sign-ins by Account

---

**Table:** | **Schema:** Advanced Hunting
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** 2026-05-12 | **Status:** `Deployed`

---

## Purpose
- Sign-ins from IPs inconsistent with the user's normal work location
- Regular `HoursSincePrev` intervals — automated refresh often occurs every 60–72 hours on a schedule
- `OutsideBusinessHours == true` combined with `IsCompliant != true`
- Location jumps that are geographically impossible in the time elapsed

---

## Query

```kql
// Table: AADNonInteractiveUserSignInLogs

// Schema: Sentinel / Log Analytics
// Purpose: Build complete sign-in timeline for compromised account over 5-month window

AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| where ResultType == 0
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend DeviceOS = tostring(DeviceDetailParsed.operatingSystem)
| extend IsCompliant = tostring(DeviceDetailParsed.isCompliant)
| extend IsManaged = tostring(DeviceDetailParsed.isManaged)
| extend TrustType = tostring(DeviceDetailParsed.trustType)
| extend DeviceId = tostring(DeviceDetailParsed.deviceId)
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 14 or HourOfDay > 24
| extend Weekend = DayOfWeek == 0d or DayOfWeek == 6d
| sort by TimeGenerated asc
| serialize
| extend HoursSincePrev = datetime_diff("hour", TimeGenerated, prev(TimeGenerated))
| project
    TimeGenerated,
    UserDisplayName,
    UserPrincipalName,
    AppDisplayName,
    ClientAppUsed,
    IPAddress,
    Location,
    HourOfDay,
    OutsideBusinessHours,
    Weekend,
    HoursSincePrev,
    IsCompliant,
    IsManaged,
    TrustType,
    DeviceId,
    DeviceOS,
    RiskLevelDuringSignIn,
    RiskDetail,
    ConditionalAccessStatus,
    AuthenticationDetails
| order by TimeGenerated asc
```

---

## Validated Columns
- [x] 
- [x] 

---

## Test Results


---

## Deployment

> Despite being a Sentinel table, I deployed this to Advanced Hunting. Shared Queries > Hunting. 

### MDE Custom Detection Rule

- **Rule Name:** Hunting - NonInteractive Sign-ins by Account
- Shared Query > Hunting
  
- **Deployed:** [Yes ]



---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-12 | Created |
