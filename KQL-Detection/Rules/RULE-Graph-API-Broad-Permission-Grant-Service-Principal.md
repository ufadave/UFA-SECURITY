---
date: 2026-05-21
title: Graph API Broad Permission Grant to Service Principal
table: "AuditLogs"
schema: "Sentinel / Log Analytics"
mitre: "T1528, T1098.003"
tactic: "Persistence, Privilege Escalation"
technique: "T1528 Steal Application Access Token, T1098.003 Account Manipulation: Additional Cloud Roles"
status: "Validated"
promoted_to_rule: true
mde_rule_name: ""
sentinel_rule_id: "821133bb-b13c-439f-80fb-d2bae6c175ca"
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#cloud"
  - "#identity"
---

# RULE — Graph API Broad Permission Grant to Service Principal

---

**Table:** AuditLogs | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1528, T1098.003 | **Tactic:** Persistence, Privilege Escalation
**Created:** 2026-05-21 | **Status:** `Validated`

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-21 |
| **Deployed To** | Sentinel Analytics Rule |
| **Rule Name** | Graph API Broad Permission Grant to Service Principal |
| **Rule ID** | <!-- Populate sentinel_rule_id in frontmatter when deployed --> |

---

## Purpose

Detects admin consent grants and delegated permission grants that include Microsoft Graph API
scopes capable of enabling tenant-wide data access, privilege escalation, or security control
modification. Covers two abuse paths:

1. An attacker with admin access adding permissions to enable M365Pwned-style tenant-wide
   exfiltration via a compromised or newly created app registration
2. Legitimate admin over-provisioning that creates a latent attack surface

Permissions are tiered by severity. **Critical** tier covers permissions that directly enable
privilege escalation, role manipulation, identity modification, or security control bypass —
any single Critical grant is high-confidence malicious or severely misconfigured. **High** tier
covers broad data access and admin-level read/write permissions — legitimate in specific managed
contexts but always warranting investigation.

> **Schema note:** Runs against `AuditLogs` in Sentinel Log Analytics via the Entra ID data
> connector. Not available in Advanced Hunting. Operation names validated in tenant:
> `"Consent to application"` and `"Add delegated permission grant"`.
> `"Add app role assignment to service principal"` does NOT exist in this tenant — do not use.

---

## Query

```kql
// ─────────────────────────────────────────────────────────────────────────────
// RULE: Graph API Broad Permission Grant to Service Principal
// Table: AuditLogs (Sentinel / Log Analytics — Entra ID data connector required)
// Validated operation names: "Consent to application", "Add delegated permission grant"
// Last validated: 2026-05-21 | 30-day run: 10 events, all investigated
// ─────────────────────────────────────────────────────────────────────────────

// CRITICAL tier — privilege escalation, role/identity/policy manipulation
// Any single grant from this list is high-confidence malicious or severely misconfigured.
let CriticalPermissions = dynamic([
    "RoleManagement.ReadWrite.Directory",       // Direct role assignment to any principal
    "AppRoleAssignment.ReadWrite.All",           // Grant app roles — persistence mechanism
    "Application.ReadWrite.All",                 // Create/modify app registrations — backdooring
    "ServicePrincipal.ReadWrite.All",            // Modify service principals directly
    "Policy.ReadWrite.ConditionalAccess",        // CA policy modification — detection bypass
    "UserAuthenticationMethod.ReadWrite.All",    // MFA manipulation — account takeover enabler
    "Directory.ReadWrite.All",                   // Full tenant directory write access
    "PrivilegedAccess.ReadWrite.AzureAD",        // PIM manipulation
    "IdentityProvider.ReadWrite.All",            // Federated identity manipulation
    "SecurityEvents.ReadWrite.All",              // Suppress/manipulate security signals
    "IdentityRiskEvent.ReadWrite.All",           // Suppress identity risk signals
    "full_access_as_app"                         // Legacy — full mailbox access as app
]);

// HIGH tier — broad data access and admin-level read/write
// Legitimate in specific managed contexts; always warrants investigation.
let HighPermissions = dynamic([
    // Mail
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.ReadBasic.All",                        // Bulk recipient harvesting / BEC recon
    // Files & SharePoint
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.Manage.All",
    "Sites.FullControl.All",
    // Directory & identity
    "Directory.Read.All",
    "User.Read.All",
    "User.ReadWrite.All",                        // Noisy — tune with provisioning app exclusions if needed
    "Group.ReadWrite.All",                       // Noisy — tune if group mgmt apps generate FPs
    // Audit & security visibility
    "AuditLog.Read.All",                         // Attacker reading your detection coverage
    "SecurityEvents.Read.All",
    "IdentityRiskEvent.Read.All",
    // Teams & chat
    "ChannelMessage.Read.All",
    "Chat.Read",
    "Chat.ReadWrite",
    // Device
    "Device.ReadWrite.All",
    // Additional sensitive read
    "Calendars.Read.All",
    "Contacts.Read.All",
    "Notes.Read.All",
    "Tasks.Read.All",
    "Reports.Read.All"
]);

AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where Result == "success"
| extend
    InitiatorUPN      = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorIP       = tostring(InitiatedBy.user.ipAddress),
    InitiatorApp      = tostring(InitiatedBy.app.displayName),
    TargetJson        = tostring(TargetResources)
| extend
    TargetAppName     = tostring(TargetResources[0].displayName),
    TargetAppObjectId = tostring(TargetResources[0].id)
| extend
    IsCritical = TargetJson has_any (CriticalPermissions),
    IsHigh     = TargetJson has_any (HighPermissions)
| where IsCritical or IsHigh
| extend PermissionTier = case(
    IsCritical, "Critical",
    IsHigh,     "High",
    "Unknown"
)
| project
    TimeGenerated,
    PermissionTier,
    OperationName,
    TargetAppName,
    TargetAppObjectId,
    InitiatorUPN,
    InitiatorApp,
    InitiatorIP,
    TargetJson,
    Result,
    CorrelationId
| order by PermissionTier asc, TimeGenerated desc
```

> **Ordering note:** `PermissionTier asc` sorts Critical before High alphabetically.
> If you prefer explicit ordering, replace with:
> `| extend TierSort = case(PermissionTier == "Critical", 0, 1) | order by TierSort asc, TimeGenerated desc`

---

## Validated Columns

- [x] `OperationName` — confirmed in tenant: `"Consent to application"`, `"Add delegated permission grant"`
- [x] `Result` — `"success"` confirmed as string value
- [x] `InitiatedBy.user.userPrincipalName` — present on user-initiated consent events
- [x] `InitiatedBy.user.ipAddress` — present; may be empty on service-initiated events
- [x] `InitiatedBy.app.displayName` — present on app-initiated events; empty on user-initiated
- [x] `TargetResources[0].displayName` — app display name confirmed
- [x] `TargetResources[0].id` — app object ID confirmed
- [ ] `TargetJson has_any (CriticalPermissions)` — string search against JSON blob; validate Critical tier permission names against a real consent event in your tenant before promoting

---

## Test Results

- **30-day validation run (2026-05-21):** 10 events returned, all investigated
- **Notable finding:** ChatGPT tenant-wide admin consent — `Mail.Read` + `Chat.Read` + `ChannelMessage.Read.All` — documented in `[[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]]`
- **Critical tier:** Not yet validated against a real Critical-tier consent event in tenant — flag for first live fire

---

## Sentinel Analytics Rule

- **Rule Name:** Graph API Broad Permission Grant to Service Principal
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** High (override to Critical manually for Critical tier alerts, or use dynamic severity — see tuning note below)
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

> **Tuning note — dynamic severity:** Sentinel Analytics Rules do not natively support
> per-row dynamic severity. Two options:
> 1. Split into two rules — one scoped to `CriticalPermissions` only at Critical severity,
>    one scoped to `HighPermissions` only at High severity
> 2. Keep as a single rule at High severity; triage workflow flags Critical tier manually
>    via the `PermissionTier` column in the alert
>
> Recommendation: start with option 2 (single rule), split if alert volume warrants it.

<!-- INACTIVE — MDE Custom Detection
This rule runs against AuditLogs (Log Analytics only). Not available in Advanced Hunting.
For a device-side complement, see [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]].
-->

---

## Suppression / Tuning Guidance

- If chronic FPs emerge from a known provisioning workflow, add a `CorrelationId`-based suppression scoped to that specific provisioning service principal — do not add broad InitiatorApp exclusions
- `User.ReadWrite.All` and `Group.ReadWrite.All` are the most likely High-tier FP sources — monitor first week post-deployment and tune if needed
- `Chat.ReadWrite` may generate FPs from legitimate Teams bots — scope suppression to known bot app object IDs if required

---

## Hardening Control Pair
- **Control:** [[HARD-Entra-App-Registration-Permissions-Audit]]
- **Linked:** [ ]

---

## Related Notes
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] — source KQL note (pre-promotion)
- [[INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit]] — source intel
- [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]] — real-world finding surfaced during validation
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]] — companion rule (CloudAppEvents)
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]] — companion rule (SigninLogs)
- [[HARD-Entra-App-Registration-Permissions-Audit]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-21 | Created — promoted from [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] |
| 2026-05-21 | Operation name corrected — "Add app role assignment to service principal" does not exist in tenant; replaced with "Consent to application" and "Add delegated permission grant" |
| 2026-05-21 | Chat.Read and ChannelMessage.Read.All added to SensitivePermissions after ChatGPT finding |
| 2026-05-21 | 30-day validation complete — 10 events, all investigated, ChatGPT finding documented |
| 2026-05-22 | Permission list tiered into Critical / High — restructured query with PermissionTier column |
| 2026-05-22 | Critical tier added: RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, Application.ReadWrite.All, ServicePrincipal.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, UserAuthenticationMethod.ReadWrite.All, Directory.ReadWrite.All, PrivilegedAccess.ReadWrite.AzureAD, IdentityProvider.ReadWrite.All, SecurityEvents.ReadWrite.All, IdentityRiskEvent.ReadWrite.All, full_access_as_app |
| 2026-05-22 | High tier expanded: Mail.ReadBasic.All, Files.ReadWrite.All, Sites.ReadWrite.All, Sites.Manage.All, Sites.FullControl.All, Directory.Read.All, User.ReadWrite.All, Group.ReadWrite.All, AuditLog.Read.All, SecurityEvents.Read.All, IdentityRiskEvent.Read.All, Chat.ReadWrite, Device.ReadWrite.All, Calendars.Read.All, Contacts.Read.All, Notes.Read.All, Tasks.Read.All, Reports.Read.All |
| 2026-05-22 | Dropped: Directory.AccessAsUser.All (legacy/deprecated), EduRoster.Read.All, EduAssignments.Read.All (education tenant permissions — not applicable), MailboxSettings.Read, People.Read.All, TeamsAppInstallation.ReadWriteForUser.All (low severity / corroborating signals only — not standalone alert triggers) |
