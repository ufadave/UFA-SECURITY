---
date: 2026-05-20
title: SSPR Followed By Sign-In From New Country Or Unregistered Device
table: "AuditLogs, SigninLogs"
schema: "Sentinel / Log Analytics"
mitre: "T1078.004"
tactic: "Initial Access"
technique: "Valid Accounts: Cloud Accounts"
status: "Active"
promoted_to_rule: True
mde_rule_name: ""
sentinel_rule_id: "6df40404-f6b6-4185-937f-01d5788a978f"
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/Done"
  - "#identity"
  - "#cloud"
---

# KQL -- SSPR Followed By Sign-In From New Country Or Unregistered Device

---

**Table:** AuditLogs + SigninLogs | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1078.004 | **Tactic:** Initial Access | **Technique:** Valid Accounts: Cloud Accounts
**Created:** 2026-05-20 | **Status:** Active

---

## Purpose

Detects a completed SSPR (Self-Service Password Reset) followed within one hour by a successful
MFA-satisfied sign-in from either a country not previously seen for that user, or an unregistered
device (no DeviceId in SigninLogs). Targets the Storm-2949 attack chain: attacker initiates SSPR
for a targeted account, social engineers the victim into approving MFA prompts during the reset
flow, then authenticates from a different location or device using the newly reset credentials.

**Triage checklist before escalating:**
1. Is the sign-in IP a known corporate egress, VPN endpoint, or registered device location?
2. Does the user have a travel or remote work request on file for that country?
3. Was the SSPR self-initiated (InitiatedBy UPN matches TargetUPN) or initiated externally?
4. Is `RiskLevelDuringSignIn` elevated in Entra ID Identity Protection?

If all four check out as benign, document and close. If the IP is unrecognised or the SSPR was
not self-initiated, treat as suspected account compromise and escalate immediately.

**Hardening note:** Privileged accounts (admin-* naming convention) should be excluded from SSPR
entirely. Admin credential resets should be IT-assisted via a break-glass process. The
admin-CJones2 SSPR event observed during validation (2026-05-20) highlights this gap --
raise as a separate hardening action independent of this detection.
Ben is planning to address privileged accounts and SSPR when he does the Conditional Access Policies refactoring. 
**Prerequisite:** AuditLogs and SigninLogs must be ingested into Sentinel via the Microsoft
Entra ID Diagnostic Settings connector.

---

## Query

```kql
let SSPRWindow = 1h;
let NewLocationLookback = 14d;
let DetectionLookback = 1d;
// Step 1 -- collect completed SSPR events
let SSPREvents = AuditLogs
| where TimeGenerated > ago(DetectionLookback)
| where OperationName == "Reset password (self-service)"
| where Result == "success"
| extend
    TargetUPN = tostring(TargetResources[0].userPrincipalName),
    TargetObjectId = tostring(TargetResources[0].id),
    SSPRInitiatedBy = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
    SSPRSourceIP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress),
    MFAMethod = tostring(parse_json(tostring(AdditionalDetails))[0].value)
| project SSPRTime = TimeGenerated, TargetUPN, TargetObjectId,
    SSPRInitiatedBy, SSPRSourceIP, MFAMethod;
// Step 2 -- collect MFA-satisfied sign-ins in the window after each SSPR event
let PostSSPRSignins = SSPREvents
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(DetectionLookback + SSPRWindow)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | project
        SigninTime = TimeGenerated,
        UserPrincipalName,
        UserId,
        IPAddress,
        Country = tostring(LocationDetails.countryOrRegion),
        City = tostring(LocationDetails.city),
        DeviceId = tostring(DeviceDetail.deviceId),
        DeviceDisplayName = tostring(DeviceDetail.displayName),
        IsCompliant = tostring(DeviceDetail.isCompliant),
        AppDisplayName,
        ClientAppUsed,
        ConditionalAccessStatus,
        RiskLevelDuringSignIn,
        RiskLevelAggregated
) on $left.TargetUPN == $right.UserPrincipalName
| where SigninTime between (SSPRTime .. (SSPRTime + SSPRWindow));
// Step 3 -- build known-country baseline per user from prior 14 days
let KnownCountries = SigninLogs
| where TimeGenerated between (ago(DetectionLookback + NewLocationLookback) .. ago(DetectionLookback))
| where ResultType == 0
| summarize KnownCountrySet = make_set(tostring(LocationDetails.countryOrRegion))
    by UserPrincipalName;
// Step 4 -- flag new country or unregistered device
PostSSPRSignins
| join kind=leftouter KnownCountries on UserPrincipalName
| extend IsNewCountry = not(set_has_element(KnownCountrySet, Country))
| extend IsNewDevice = isempty(DeviceId) or DeviceId == ""
| extend SelfInitiated = (SSPRInitiatedBy == TargetUPN)
| where IsNewCountry or IsNewDevice
| project
    SSPRTime,
    SigninTime,
    MinutesSinceSSPR = datetime_diff('minute', SigninTime, SSPRTime),
    UserPrincipalName,
    SelfInitiated,
    SSPRInitiatedBy,
    SSPRSourceIP,
    MFAMethod,
    IPAddress,
    Country,
    City,
    IsNewCountry,
    KnownCountrySet,
    DeviceId,
    DeviceDisplayName,
    IsCompliant,
    IsNewDevice,
    AppDisplayName,
    ClientAppUsed,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated
| order by SSPRTime desc
```

---

## Validated Columns

- [x] `OperationName` -- `Reset password (self-service)` confirmed in AuditLogs (lowercase `success`)
- [x] `Result` -- value is `success` (lowercase) in this tenant -- filter accordingly
- [x] `TargetResources[0].userPrincipalName` -- confirmed populated for SSPR completion events
- [x] `InitiatedBy` -- JSON field; parsed via `parse_json(tostring(...))` to extract UPN and IP
- [x] `AdditionalDetails` -- JSON array; index 0 contains MFA method on successful reset
- [x] `ResultType == 0` -- confirmed as successful sign-in filter in SigninLogs
- [x] `AuthenticationRequirement` -- `multiFactorAuthentication` confirmed in SigninLogs
- [x] `LocationDetails.countryOrRegion` -- confirmed populated
- [x] `DeviceDetail.deviceId` -- empty string on unregistered devices (not null) -- `isempty()` required
- [x] `RiskLevelDuringSignIn` -- confirmed present; populated by Entra ID Identity Protection

---

## Test Results

**30-day validation -- 2026-04-20 to 2026-05-20**

| Date | Account | SSPR Result | Post-SSPR Sign-in | Flagged | Disposition |
|------|---------|-------------|-------------------|---------|-------------|
| 2026-05-20 15:40 | admin-CJones2 | success (4th attempt, 3x hr=80230619 failures) | Not flagged | No | Self-initiated, single IP throughout, mobile app MFA, AADConnect writeback. Benign -- password history policy initially blocked reuse. Admin account using SSPR is a hardening gap (separate item). |

Post-threshold result: **0 alerts in 30 days** after join with new-country/unregistered-device filter.
19 SSPR completions confirmed in AuditLogs. No suspicious post-SSPR sign-ins detected.

**SSPR operation names confirmed in this tenant:**
- `User started password reset`
- `Self-service password reset flow activity progress`
- `Reset password (self-service)` ← anchor event used in this query
- `Change password (self-service)` ← excluded (authenticated user changing own password)
- `Unlock user account (self-service)`

---

## Deployment

<!-- Advanced Hunting does not support AuditLogs or SigninLogs -- Sentinel only -->
<!-- MDE Custom Detection section inactive: Log Analytics schema -->

### MDE Custom Detection Rule
<!-- INACTIVE: AuditLogs and SigninLogs are Log Analytics sources -- not available in Advanced Hunting -->

### Sentinel Analytics Rule
- **Rule Name:** SSPR Followed By Sign-In From New Country Or Unregistered Device
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:**Medium
- **Deployed:** [ Y]
- **Rule GUID:** 6df40404-f6b6-4185-937f-01d5788a978f

---

## Hardening Control Pair
- **Control:** [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18]]
- [[KQL-OneDrive-Bulk-File-Download-Detection]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-20 | Created -- promoted from Storm-2949 intel note; 30-day validated, 0 alerts post-join |
| 2026-05-20 | SSPRInitiatedBy and SelfInitiated fields added to output -- distinguishes self-initiated vs externally-triggered SSPR |
| 2026-05-20 | MFAMethod extracted from AdditionalDetails for triage context |
