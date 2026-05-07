---
title: "App-Only Non-Interactive Sign-In from Unknown Application (SigninLogs)"
date: 2026-05-03
source_intel: "[[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]"
schema: AADNonInteractiveUserSignInLogs / SigninLogs
context: Sentinel (Log Analytics)
mitre_tactics:
  - Initial Access
  - Persistence
mitre_techniques:
  - T1528 (Steal Application Access Token)
  - T1078.004 (Valid Accounts: Cloud Accounts)
status: candidate
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection/analytics-rule"
  - "#cloud"
  - "#identity"
  - "#status/draft"
  - "#action-required"
---

# KQL — App-Only Non-Interactive Sign-In from Unknown Application

## Purpose

Detects a non-interactive (app-only) authentication against Entra ID by an application that is not in your established allowlist of known service principals — a potential indicator of a compromised OAuth app credential or a newly registered malicious application being used for the first time.

M365Pwned requires a valid application credential (client secret, certificate thumbprint, or raw access token) to authenticate. The authentication event surfaces in `AADNonInteractiveUserSignInLogs` (preferred — lower noise than `SigninLogs` for this scenario) or `SigninLogs` filtered to non-interactive logons.

**This rule is allowlist-dependent.** Its value is directly proportional to the quality of `known_good_app_ids`. Plan to populate this from your Entra ID app registrations audit before deployment.

> **Schema note from stub:** Original stub used `SigninLogs | where IsInteractive == false`. This works but `AADNonInteractiveUserSignInLogs` is a dedicated table for non-interactive sign-ins and is typically lower volume and more focused. Both approaches are provided below. The stub also used `count_ > 50` as a volume threshold — this is a weak signal on its own. The refined query focuses on **unknown app identity** as the primary signal, with volume as a secondary enrichment field.

---

## Schema

### Primary: AADNonInteractiveUserSignInLogs (recommended)

| Field | Type | Notes |
|---|---|---|
| `AppId` | `string` | OAuth app GUID of the authenticating application |
| `AppDisplayName` | `string` | Display name of the app |
| `ResourceDisplayName` | `string` | Resource being accessed (e.g. "Microsoft Graph") |
| `IPAddress` | `string` | Source IP of the authentication request |
| `UserPrincipalName` | `string` | UPN of the user context (may be service account UPN for app-only) |
| `ServicePrincipalId` | `string` | Object ID of the service principal |
| `ServicePrincipalName` | `string` | Service principal name |
| `ResultType` | `string` | `"0"` = success |
| `ConditionalAccessStatus` | `string` | Whether CA policies were evaluated |
| `AuthenticationRequirement` | `string` | `"singleFactorAuthentication"` typical for app-only |
| `TimeGenerated` | `datetime` | Sentinel timestamp |

### Alternate: SigninLogs (if AADNonInteractiveUserSignInLogs not connected)

| Field | Type | Notes |
|---|---|---|
| `IsInteractive` | `bool` | `false` for app-only / non-interactive |
| `AppId` | `string` | OAuth app GUID |
| `AppDisplayName` | `string` | App name |

> **Confirm which table is connected:** In Sentinel → Data Connectors → Azure Active Directory — check whether `AADNonInteractiveUserSignInLogs` is enabled alongside standard `SigninLogs`. Both require the Entra ID data connector. `AADNonInteractiveUserSignInLogs` requires Azure AD P1 or higher (covered by your E5).

---

## Query

### Primary (AADNonInteractiveUserSignInLogs)
```kql
// ---------------------------------------------------------------
// App-Only Non-Interactive Sign-In from Unknown Application
// Table: AADNonInteractiveUserSignInLogs (Sentinel Log Analytics)
// ---------------------------------------------------------------

// Populate from Entra ID → App Registrations + Enterprise Applications
// Include both first-party Microsoft apps and your registered apps
let known_good_app_ids = dynamic([
    // Microsoft first-party — common non-interactive authenticators
    "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
    "00000002-0000-0ff1-ce00-000000000000",  // Exchange Online
    "1b730954-1685-4b74-9bfd-dac224a7b894",  // Azure AD PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",  // Microsoft Azure PowerShell
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  // Microsoft Office
    "00000006-0000-0ff1-ce00-000000000000",  // Microsoft Office 365 Portal
    "c1c74fed-04c9-4704-80dc-9f79a2e515cb",  // Azure Security Center
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3",  // Microsoft Docs
    // --- Add your registered app IDs below ---
    // "your-app-id-here"
]);

let lookback = 1h;

AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == "0"                          // Successful authentication only
| where ResourceDisplayName has_any (
    "Microsoft Graph",
    "Microsoft 365",
    "Office 365 Exchange Online",
    "Office 365 SharePoint Online"
)                                                   // Scope to M365 resource access
| where AppId !in (known_good_app_ids)
| summarize
    AuthCount         = count(),
    DistinctUPNs      = dcount(UserPrincipalName),
    SourceIPs         = make_set(IPAddress, 5),
    Resources         = make_set(ResourceDisplayName, 5),
    FirstSeen         = min(TimeGenerated),
    LastSeen          = max(TimeGenerated)
    by AppId, AppDisplayName, ServicePrincipalId, ServicePrincipalName
| extend
    IsHighVolume = AuthCount > 100,
    IsMultiUser  = DistinctUPNs > 5
| project
    FirstSeen,
    AppId,
    AppDisplayName,
    ServicePrincipalId,
    ServicePrincipalName,
    AuthCount,
    DistinctUPNs,
    IsHighVolume,
    IsMultiUser,
    SourceIPs,
    Resources,
    LastSeen
| order by AuthCount desc
```

### Alternate (SigninLogs — if AADNonInteractiveUserSignInLogs unavailable)
```kql
let known_good_app_ids = dynamic([/* same list as above */]);
let lookback = 1h;

SigninLogs
| where TimeGenerated >= ago(lookback)
| where IsInteractive == false
| where ResultType == "0"
| where AppId !in (known_good_app_ids)
| summarize
    AuthCount  = count(),
    SourceIPs  = make_set(IPAddress, 5),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated)
    by AppId, AppDisplayName, UserPrincipalName
| order by AuthCount desc
```

---

## Validated Columns

- [ ] `AADNonInteractiveUserSignInLogs` — confirm table exists and is populated in your Sentinel workspace (`AADNonInteractiveUserSignInLogs | take 1`)
- [ ] `AADNonInteractiveUserSignInLogs.AppId` — confirm string GUID, matches Entra app registration Application (client) ID
- [ ] `AADNonInteractiveUserSignInLogs.ResultType` — confirm `"0"` string (not integer `0`) represents success
- [ ] `AADNonInteractiveUserSignInLogs.ServicePrincipalId` — confirm populated for app-only authentications
- [ ] `AADNonInteractiveUserSignInLogs.ResourceDisplayName` — confirm values match the `has_any` list above in your environment
- [ ] `SigninLogs.IsInteractive` — confirm `bool` type; `false` filters to non-interactive
- [ ] `known_good_app_ids` — **must be populated before deployment** — see pre-deployment steps below

### Pre-Deployment: Build the Known-Good List
Run this to enumerate all app IDs currently authenticating non-interactively in your tenant over 30 days:
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(30d)
| where ResultType == "0"
| summarize AuthCount = count() by AppId, AppDisplayName
| order by AuthCount desc
```
Review the output with your app catalogue. Everything on this list that is legitimate goes into `known_good_app_ids`. Everything you don't recognise is a starting investigation point.

---

## Exclusion Rationale

| Exclusion | Reason |
|---|---|
| `known_good_app_ids` | Core allowlist — rule is entirely dependent on this being accurate. Incomplete list = high FP rate. |
| `ResultType == "0"` | Focus on successful authentications — failed app auth attempts are covered by brute-force/spray rules |
| `ResourceDisplayName` scope | Limits to M365 data-access resources; removes Azure management plane noise |

---

## Sentinel Analytics Rule Config

| Setting | Value |
|---|---|
| Rule Name | App-Only Non-Interactive Sign-In from Unknown Application |
| Severity | Medium (elevate to High if `IsMultiUser == true` or `AuthCount > 100`) |
| Query Frequency | 1h |
| Query Period | 1h |
| Trigger Threshold | Count > 0 |
| Entity Mapping | Account → AppDisplayName; IP → SourceIPs |
| MITRE Tactics | Initial Access, Persistence |
| MITRE Techniques | T1528, T1078.004 |
| Suppression | 24h per AppId after first alert — prevents repeat alerts for same unknown app during investigation |

---

## Test Results

- [ ] `AADNonInteractiveUserSignInLogs` table confirmed populated
- [ ] Pre-deployment 30d app enumeration query run
- [ ] `known_good_app_ids` list populated and reviewed
- [ ] `ResultType == "0"` confirmed as success string
- [ ] `ResourceDisplayName` values validated against your environment
- [ ] False positive rate acceptable after allowlist populated
- [ ] Deployed to Sentinel

---

## Operational Notes

*(Populate post-deployment)*

---

## Related Notes
- [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] — source intel
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]] — companion rule (bulk access)
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] — companion rule (permissions grant)
- [[HARD-Entra-App-Registration-Permissions-Audit]]
- [[PROJ-M365-Hardening]]
- [[CLAUDE-KQL-Promotion-Workflow]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Stage 1 (Candidate) — promoted from INTEL-M365Pwned stub. Primary table changed from SigninLogs to AADNonInteractiveUserSignInLogs (more precise). Detection logic reframed around unknown app identity as primary signal rather than volume threshold. Known-good list pre-population made an explicit pre-deployment requirement. |
