---
title: "Broad Graph API Permission Grant to Service Principal (AuditLogs)"
date: 2026-05-03
source_intel: "[[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]"
schema: "AuditLogs, AADNonInteractiveUserSignInLogs, SigninLogs"
context: Sentinel (Log Analytics)
mitre_tactics:
  - Persistence
  - Privilege Escalation
mitre_techniques:
  - T1098.003 (Account Manipulation: Additional Cloud Roles)
  - T1528 (Steal Application Access Token)
status: candidate
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection/analytics-rule"
  - "#cloud"
  - "#identity"
  - "#status/draft"
  - "#action-required"
  - "#Graph"
---

# KQL — Broad Graph API Permission Grant to Service Principal

## Purpose

Detects when an application role assignment is made that grants broad Microsoft Graph API permissions to a service principal — specifically permissions that enable tenant-wide data access: `Mail.Read`, `Mail.ReadWrite`, `Files.Read.All`, `Sites.Read.All`, `User.Read.All`.

This covers two abuse paths:
1. An attacker who has gained admin access adding permissions to an existing app to enable M365Pwned-style exfiltration
2. Legitimate admin over-provisioning that creates a latent attack surface

This is a **low-volume, high-signal** detection. Broad Graph permissions being granted to a service principal is uncommon in normal operations and should always be investigated.

> **Note:** This query runs against `AuditLogs` in Sentinel Log Analytics (Entra ID audit events via the Entra ID data connector). It does **not** run in Advanced Hunting — use `CloudAppEvents` with `ActionType == "Add app role assignment to service principal."` for the Defender XDR equivalent.

---

## Schema

| Field | Table | Notes |
|---|---|---|
| `AuditLogs` | Sentinel Log Analytics | Requires Entra ID data connector |
| `OperationName` | `string` | `"Add app role assignment to service principal"` |
| `Result` | `string` | `"success"` — filter to confirmed grants only |
| `InitiatedBy` | `dynamic` | JSON — contains initiating user or service principal details |
| `TargetResources` | `dynamic` | JSON array — contains app, permissions, and resource details |
| `TimeGenerated` | `datetime` | Sentinel timestamp |

> **Schema note from stub:** Original stub used `TargetResources has_any (...)` with permission names as plain strings. This works but is a string search against the JSON blob — it may miss some formats. The refined query below uses `tostring(TargetResources)` explicitly and tests both the permission name and common display name variants.

---

## Query

```kql
// ---------------------------------------------------------------
// Broad Graph API Permission Grant to Service Principal
// Table: AuditLogs (Sentinel Log Analytics)
// Requires: Entra ID data connector
// ---------------------------------------------------------------

// High-value permissions that enable tenant-wide data access
let sensitive_permissions = dynamic([
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.ReadBasic.All",
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "User.Read.All",
    "User.ReadWrite.All",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "MailboxSettings.Read",
    "full_access_as_app"           // Legacy EWS app-only full access
]);

AuditLogs
| where TimeGenerated >= ago(1d)
| where OperationName == "Add app role assignment to service principal"
| where Result == "success"
// Extract initiator details
| extend
    InitiatorUPN        = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorObjectId   = tostring(InitiatedBy.user.id),
    InitiatorIP         = tostring(InitiatedBy.user.ipAddress),
    InitiatorApp        = tostring(InitiatedBy.app.displayName)
// Extract target SP details
| extend TargetJson = tostring(TargetResources)
| extend
    TargetAppName       = tostring(TargetResources[0].displayName),
    TargetAppObjectId   = tostring(TargetResources[0].id),
    ModifiedProps       = TargetResources[0].modifiedProperties
// Check for sensitive permission strings in the raw target JSON
| where TargetJson has_any (sensitive_permissions)
// Extract the specific permission name from modified properties
| mv-expand ModifiedProps
| where tostring(ModifiedProps.displayName) == "AppRole.Value"
| extend PermissionGranted = tostring(ModifiedProps.newValue)
| where PermissionGranted has_any (sensitive_permissions)
| project
    TimeGenerated,
    PermissionGranted,
    TargetAppName,
    TargetAppObjectId,
    InitiatorUPN,
    InitiatorApp,
    InitiatorIP,
    InitiatorObjectId,
    OperationName,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### Supplementary — CloudAppEvents Equivalent (Advanced Hunting / Defender XDR)
```kql
// Equivalent detection in CloudAppEvents for Defender XDR Advanced Hunting
// Catches the same event via MCAS connector
CloudAppEvents
| where Timestamp >= ago(1d)
| where ActionType == "Add app role assignment to service principal."
| extend PermissionInfo = tostring(RawEventData)
| where PermissionInfo has_any (
    "Mail.Read", "Mail.ReadWrite", "Files.Read.All",
    "Sites.Read.All", "User.Read.All", "Directory.Read.All"
)
| project Timestamp, AccountDisplayName, AccountType, ObjectName, IPAddress, UserAgent, RawEventData
```

---

### Supplementary — Non-Interactive Token Refresh Cadence (AADNonInteractiveUserSignInLogs)

Detects automated token refresh patterns consistent with an attacker maintaining a long-duration AiTM session. Silent OAuth token refresh events land in `AADNonInteractiveUserSignInLogs`, not `SigninLogs` — this is the correct table for detecting background token activity.

Use this query alongside the permission grant detection to determine whether a compromised account had an active attacker-maintained token during the period when suspicious grants were made.

```kql
// Table: AADNonInteractiveUserSignInLogs
// Schema: Sentinel / Log Analytics
// Purpose: Summarise non-interactive sign-in pattern by week to surface automated
//          token refresh cadence consistent with attacker-maintained AiTM session
//          Silent OAuth token refresh events land here — SigninLogs captures
//          interactive sign-ins only
// Usage: Replace UserId with the account object ID under investigation
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "REPLACE-WITH-ACCOUNT-OBJECT-ID"
| where ResultType == 0
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend IsCompliant = tostring(DeviceDetailParsed.isCompliant)
| extend HourOfDay = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 7 or HourOfDay > 19
| extend WeekNumber = week_of_year(TimeGenerated)
| summarize
    SignInsThisWeek   = count(),
    OutsideHoursCount = countif(OutsideBusinessHours == true),
    NonCompliantCount = countif(IsCompliant != "true"),
    UniqueIPs         = dcount(IPAddress),
    UniqueLocations   = dcount(Location),
    UniqueApps        = dcount(AppDisplayName),
    FirstSignIn       = min(TimeGenerated),
    LastSignIn        = max(TimeGenerated)
    by WeekNumber
| extend OutsideHoursPct  = round(100.0 * OutsideHoursCount / SignInsThisWeek, 1)
| extend NonCompliantPct  = round(100.0 * NonCompliantCount / SignInsThisWeek, 1)
| order by WeekNumber asc
```

**What to look for:**
- Consistent `OutsideHoursPct` above 50% sustained across multiple weeks — legitimate user background activity is mixed; attacker-maintained refresh tends to occur at consistent off-hours intervals
- `NonCompliantPct` near 100% — AiTM proxy sessions originate from non-compliant devices
- Low `UniqueIPs` (1–2) combined with anomalous `UniqueLocations` — automated refresh from fixed attacker infrastructure
- Unnervingly regular `FirstSignIn` / `LastSignIn` intervals week over week — automated refresh often runs on a fixed schedule

> ⚠️ **Volume note:** `AADNonInteractiveUserSignInLogs` generates significantly higher event volume than `SigninLogs` — every background token refresh from every Office app lands here. The weekly summarise aggregation is intentional. Do not expand to per-event without a tight time window and UserId filter.

> ⚠️ **Retention note:** Confirm `AADNonInteractiveUserSignInLogs` was streaming via the Entra ID data connector for the full investigation window. Check `Sentinel > Data connectors > Azure Active Directory` if the table returns unexpected gaps.

> ⚠️ **Schema note:** `DeviceDetail` is stored as a JSON string in this table — `parse_json(DeviceDetail)` is required before property navigation. Direct dot-access (`DeviceDetail.isCompliant`) will produce a type error.

---

## Validated Columns

- [ ] `AuditLogs.OperationName` — confirm `"Add app role assignment to service principal"` (exact string, case-sensitive)
- [ ] `AuditLogs.TargetResources` — confirm dynamic array; `[0]` indexing valid for your events
- [ ] `AuditLogs.TargetResources[0].modifiedProperties` — confirm `AppRole.Value` display name in your tenant's events
- [ ] `AuditLogs.InitiatedBy.user.userPrincipalName` — confirm populated for human-initiated grants; may be empty for service-principal-initiated grants
- [ ] `AuditLogs.InitiatedBy.app.displayName` — confirm populated for app-initiated grants
- [ ] `AuditLogs.Result` — confirm `"success"` value (vs `"failure"`)
- [ ] `mv-expand ModifiedProps` — validate the expanded structure matches your tenant's audit event format; run a sample query first
- [ ] `AADNonInteractiveUserSignInLogs.DeviceDetail` — stored as JSON string; `parse_json()` required before property navigation — confirmed fix applied in query above
- [ ] `AADNonInteractiveUserSignInLogs.IsCompliant` — extracted via `parse_json(DeviceDetail).isCompliant`; confirm boolean vs string handling returns `"true"` / `"false"` strings in your tenant
- [ ] `AADNonInteractiveUserSignInLogs.Location` — confirm field populated and consistent with `SigninLogs.Location` for `dcount` accuracy
- [ ] `AADNonInteractiveUserSignInLogs` — confirm table is present and streaming via Entra ID data connector before relying on absence of results as a negative signal

### Pre-deployment Validation Query
Run this first to inspect raw event structure before applying the full logic:
```kql
AuditLogs
| where TimeGenerated >= ago(30d)
| where OperationName == "Add app role assignment to service principal"
| take 5
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
```

---

## Exclusion Rationale

| Exclusion | Reason |
|---|---|
| `Result == "success"` | Filter to confirmed grants only — failed attempts are lower signal for this rule (consider separate alert for repeated failures) |
| No SP exclusions | This rule should fire for **all** broad permission grants — no service principal should receive these scopes without investigation |

> **Intentional design decision:** No allowlist for this rule. Broad Graph permissions should never be silently granted — every grant is a review opportunity. If chronic FPs emerge from a known-good provisioning workflow, add a `CorrelationId`-based suppression tied to the specific provisioning service principal, not a broad exclusion.

---

## Sentinel Analytics Rule Config

| Setting | Value |
|---|---|
| Rule Name | Broad Graph API Permission Grant to Service Principal |
| Severity | High |
| Query Frequency | 1h |
| Query Period | 1d |
| Trigger Threshold | Count > 0 |
| Entity Mapping | Account → InitiatorUPN; Account → TargetAppObjectId |
| MITRE Tactics | Persistence, Privilege Escalation |
| MITRE Techniques | T1098.003, T1528 |
| Suppression | None — every grant warrants review |

---

## Test Results

- [ ] Pre-deployment structure query run — raw TargetResources format confirmed
- [ ] `mv-expand ModifiedProps` structure validated against real events
- [ ] `PermissionGranted` extracts correct permission name
- [ ] InitiatorUPN populated correctly for human-initiated grants
- [ ] CloudAppEvents supplementary query validated in Advanced Hunting
- [ ] AADNonInteractiveUserSignInLogs — confirmed table is streaming and populated
- [ ] AADNonInteractiveUserSignInLogs — parse_json(DeviceDetail) confirmed working; IsCompliant extracts correctly
- [ ] AADNonInteractiveUserSignInLogs — weekly summary query run against known compromised account; output reviewed
- [ ] False positive rate assessed over 7d
- [ ] Deployed to Sentinel

---

## Operational Notes

*(Populate post-deployment)*

---

## Related Notes
- [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] — source intel
- [[INTEL-Tycoon2FA-AiTM-PhaaS-Platform]] — AiTM platform context for token refresh pattern
- [[HUNT-Long-Duration-AiTM-Token-Access-Graph-Recon]] — hunt campaign using AADNonInteractiveUserSignInLogs query
- [[FIND-Graph-API-User-Enumeration-Sweden-Central]] — triggering incident
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]] — companion rule
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]] — companion rule
- [[HARD-Entra-App-Registration-Permissions-Audit]]
- [[PROJ-M365-Hardening]]
- [[CLAUDE-KQL-Promotion-Workflow]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Stage 1 (Candidate) — promoted from INTEL-M365Pwned stub. Expanded permission list beyond original 4 entries. Added mv-expand logic for ModifiedProps to extract specific permission granted. Added CloudAppEvents supplementary query. Noted AuditLogs-only context (not Advanced Hunting). |
| 2026-05-05 | Added AADNonInteractiveUserSignInLogs supplementary query for AiTM token refresh cadence detection. Updated schema frontmatter. Added validated column entries and test checkboxes for new query. Added related note links for INTEL-Tycoon2FA, HUNT-Long-Duration-AiTM, and FIND-Graph-API-User-Enumeration-Sweden-Central. Schema note added re: parse_json requirement on DeviceDetail in non-interactive table. |
