---
date: 2026-05-21
title: Sign-In From Unregistered Device
table: "SigninLogs"
schema: "Sentinel / Log Analytics"
mitre: "T1078.004"
tactic: "Initial Access"
technique: "Valid Accounts: Cloud Accounts"
status: "Deferred"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
deferred_reason: "CA policy refactor in progress — query logic depends on stable device compliance posture"
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#identity"
  - "#north-korea"
---

# KQL -- Sign-In From Unregistered Device

---

**Table:** SigninLogs | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1078.004 | **Tactic:** Initial Access | **Technique:** Valid Accounts: Cloud Accounts
**Created:** 2026-05-21 | **Status:** `Draft`

---

## Purpose

Detects successful MFA-satisfied sign-ins where the authenticating device is unregistered
in Entra ID -- no DeviceId in SigninLogs. Targets two distinct threat scenarios:

1. **Jasper Sleet / North Korean IT worker infiltration** -- operatives use personal or
   laptop-farm devices routed through residential proxies, none of which are registered
   in the target tenant. Bulk data access from unregistered devices early in a user's
   tenure is a strong indicator.

2. **Post-compromise account use** -- a compromised account used from an attacker-controlled
   machine (no corporate device registration) on any MFA-satisfied sign-in, consistent
   with Storm-2949 and AiTM session theft scenarios.

Scoped to MFA-satisfied sign-ins only -- unregistered devices that fail MFA are not
actionable and would generate significant noise.

**Known false positive patterns:**
- New employee onboarding before device is registered -- sign-ins from personal devices
  during the first few days before Intune enrollment completes
- Approved BYOD scenarios where devices are intentionally not Intune-enrolled
- Mobile devices using browser sign-in rather than the Authenticator app (may not
  populate DeviceDetail)
- Break-glass or emergency access accounts signing in from secure admin workstations
  not enrolled in Intune

**Tuning lever:** Scope to accounts with tenure > N days to exclude legitimate onboarding
activity. Requires `AccountCreatedTime` or a join to AuditLogs account creation events.

---

## Query

> ⚠️ **DEFERRED — Query requires rewrite before use.**
>
> Validation (2026-05-21) showed that filtering on empty `DeviceDetail.deviceId` catches
> all browser-based sign-ins (Azure Portal, Teams Web, SharePoint, etc.) because Entra ID
> does not populate device context for browser sessions by design. This produces ~795 rows
> per day of legitimate activity, making the query unusable as-is.
>
> **Query must be rewritten once the CA policy refactor is complete.** The correct approach
> depends on the final CA device compliance posture:
> - If CA enforces compliant device for all apps: detect sign-ins where CA succeeded but
>   device compliance is absent (browser exclusions may still apply per app)
> - If CA is app-scoped: scope detection to specific high-value apps (Azure Portal, M365
>   admin) where unregistered device sign-in is unexpected
> - Consider scoping to `ClientAppUsed != "Browser"` where device registration is
>   unambiguously expected (desktop clients, mobile apps)
>
> Do not promote this query until rewritten and revalidated.

```kql
// Table: SigninLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect MFA-satisfied sign-ins from unregistered devices
// Jasper Sleet and post-compromise account use both produce this pattern
// ⚠️ DEFERRED -- see note above before running

let LookbackWindow = 1d;
let NewAccountGraceDays = 7;  // exclude accounts < 7 days old -- onboarding FP
// Step 1 -- recent account creation dates for exclusion
let NewAccounts = AuditLogs
| where TimeGenerated > ago(LookbackWindow + totimespan(NewAccountGraceDays * 1d))
| where OperationName == "Add user"
| where Result == "success"
| extend NewUserUPN = tostring(TargetResources[0].userPrincipalName),
    AccountCreatedTime = TimeGenerated
| project NewUserUPN, AccountCreatedTime;
// Step 2 -- MFA-satisfied sign-ins from unregistered devices
SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
// Unregistered device -- DeviceId empty or missing
| where isempty(tostring(DeviceDetail.deviceId))
    or tostring(DeviceDetail.deviceId) == ""
// Exclude guest accounts -- typically sign in from unmanaged devices by design
| where UserType != "Guest"
// Exclude known service accounts and break-glass accounts
| where UserPrincipalName !startswith "svc-"
    and UserPrincipalName !startswith "breakglass"
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    ASN = tostring(AutonomousSystemNumber),
    ISP = tostring(NetworkLocationDetails),
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceDisplayName = tostring(DeviceDetail.displayName),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    TrustType = tostring(DeviceDetail.trustType)
// Step 3 -- exclude recently created accounts (onboarding grace period)
| join kind=leftanti NewAccounts on $left.UserPrincipalName == $right.NewUserUPN
| project
    TimeGenerated,
    UserPrincipalName,
    UserDisplayName,
    IPAddress,
    Country,
    City,
    ASN,
    DeviceId,
    DeviceDisplayName,
    IsCompliant,
    TrustType,
    AppDisplayName,
    ClientAppUsed,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    UserType
| order by TimeGenerated desc
```

---

## Validated Columns

- [ ] `DeviceDetail.deviceId` -- confirm empty string vs null on unregistered devices
- [ ] `DeviceDetail.trustType` -- confirm populated; values: AzureAD, ServerAD, Workplace
- [ ] `AuthenticationRequirement` -- `multiFactorAuthentication` confirmed in SigninLogs
- [ ] `ResultType == 0` -- confirmed as successful sign-in
- [ ] `UserType` -- confirm `Guest` is the correct value for external guest accounts
- [ ] `AutonomousSystemNumber` -- confirm field name; may be in NetworkLocationDetails JSON
- [ ] `AuditLogs OperationName == "Add user"` -- confirm operation name for account creation events

---

## Test Results

**30-day validation attempt — 2026-05-21**

Query returned 795 rows — all browser-based sign-ins. Root cause: Entra ID does not
populate `DeviceDetail` fields for browser sessions by design. Filtering on empty
`DeviceDetail.deviceId` is not a valid signal for unregistered devices when browser
clients are in scope.

**Result: Query deferred. Rewrite required after CA policy refactor completes.**

See rewrite guidance in `## Query` section above.

---

## Deployment

<!-- SigninLogs is a Log Analytics source -- Sentinel only, not Advanced Hunting -->

### MDE Custom Detection Rule
<!-- INACTIVE: SigninLogs is a Log Analytics / Sentinel source only -->

### Sentinel Analytics Rule
- **Rule Name:** Sign-In From Unregistered Device
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** Medium
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[HARD-Require-Compliant-Device-Conditional-Access]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-Jasper-Sleet-North-Korean-IT-Worker-Infiltration-Detection-2026-04-21]]
- [[KQL-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device]]
- [[INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-21 | Created -- Jasper Sleet detection gap identified via David Coombe referral |
| 2026-05-21 | Deferred -- 30-day validation returned 795 rows of browser sign-ins; DeviceDetail not populated for browser sessions by design; query requires rewrite after CA policy refactor completes |
