---
title: "Broad Graph API Permission Grant to Service Principal (AuditLogs)"
date: 2026-05-03
source_intel: "[[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]"
schema: AuditLogs
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

## Validated Columns

- [ ] `AuditLogs.OperationName` — confirm `"Add app role assignment to service principal"` (exact string, case-sensitive)
- [ ] `AuditLogs.TargetResources` — confirm dynamic array; `[0]` indexing valid for your events
- [ ] `AuditLogs.TargetResources[0].modifiedProperties` — confirm `AppRole.Value` display name in your tenant's events
- [ ] `AuditLogs.InitiatedBy.user.userPrincipalName` — confirm populated for human-initiated grants; may be empty for service-principal-initiated grants
- [ ] `AuditLogs.InitiatedBy.app.displayName` — confirm populated for app-initiated grants
- [ ] `AuditLogs.Result` — confirm `"success"` value (vs `"failure"`)
- [ ] `mv-expand ModifiedProps` — validate the expanded structure matches your tenant's audit event format; run a sample query first

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
- [ ] False positive rate assessed over 7d
- [ ] Deployed to Sentinel

---

## Operational Notes

*(Populate post-deployment)*

---

## Related Notes
- [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] — source intel
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]] — companion rule
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]] — companion rule
- [[HARD-Entra-App-Registration-Permissions-Audit]]
- [[PROJ-M365-Hardening]]
- [[CLAUDE-KQL-Promotion-Workflow]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Stage 1 (Candidate) — promoted from INTEL-M365Pwned stub. Expanded permission list beyond original 4 entries. Added mv-expand logic for ModifiedProps to extract specific permission granted. Added CloudAppEvents supplementary query. Noted AuditLogs-only context (not Advanced Hunting). |
