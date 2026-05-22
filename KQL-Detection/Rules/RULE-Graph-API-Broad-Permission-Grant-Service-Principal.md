---
date: 2026-05-21
title: Graph API Broad Permission Grant to Service Principal
table: "AuditLogs"
schema: "Sentinel / Log Analytics"
mitre: "T1528"
tactic: "Persistence, Privilege Escalation"
technique: "T1528 Steal Application Access Token, T1098.003 Account Manipulation: Additional Cloud Roles"
status: "Validated"
promoted_to_rule: true
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#cloud"
  - "#identity"
---

# RULE -- Graph API Broad Permission Grant to Service Principal

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

Detects admin consent grants and delegated permission grants that include broad Microsoft
Graph API scopes enabling tenant-wide data access — Mail.Read, Files.Read.All,
Sites.Read.All, User.Read.All, and similar. Covers two abuse paths:

1. An attacker with admin access adding permissions to enable M365Pwned-style
   tenant-wide exfiltration via a compromised or newly created app registration
2. Legitimate admin over-provisioning creating a latent attack surface

Low-volume, high-signal detection. Broad Graph permissions being granted is uncommon in
normal operations and should always be investigated. No allowlist is applied — every
grant warrants review.

**Key schema finding:** `"Add app role assignment to service principal"` does not exist
in this tenant. Confirmed operation names are `"Consent to application"` and
`"Add delegated permission grant"`. Original KQL note used the incorrect operation name
and returned zero rows. This note uses the validated operation names.

**Validated real-world example:** On 2026-04-23, ChatGPT was granted tenant-wide admin
consent (AllPrincipals) including Mail.Read, Chat.Read, ChannelMessage.Read.All, and
offline_access via two progressive consent events. Discovered during 30-day validation.
See [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]].

---

## Query

```kql
let SensitivePermissions = dynamic([
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
    "ChannelMessage.Read.All",
    "Chat.Read",
    "Chat.ReadWrite",
    "full_access_as_app"    // Legacy EWS app-only full access
]);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where Result == "success"
| extend
    InitiatorUPN     = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorIP      = tostring(InitiatedBy.user.ipAddress),
    InitiatorApp     = tostring(InitiatedBy.app.displayName),
    TargetJson       = tostring(TargetResources)
| where TargetJson has_any (SensitivePermissions)
| extend
    TargetAppName     = tostring(TargetResources[0].displayName),
    TargetAppObjectId = tostring(TargetResources[0].id)
| project
    TimeGenerated,
    OperationName,
    TargetAppName,
    TargetAppObjectId,
    InitiatorUPN,
    InitiatorApp,
    InitiatorIP,
    TargetJson,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### Supplementary — AADNonInteractiveUserSignInLogs (IR pivot only)

Not part of the scheduled rule. Use during investigations to detect automated token
refresh cadence consistent with an attacker-maintained AiTM session. See source note
[[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] for full query and guidance.

---

## Validated Columns

- [x] `OperationName` -- `"Consent to application"` and `"Add delegated permission grant"` confirmed in this tenant. `"Add app role assignment to service principal"` does NOT exist -- returns zero rows
- [x] `Result` -- `"success"` confirmed as the correct value
- [x] `InitiatedBy.user.userPrincipalName` -- confirmed populated for human-initiated grants
- [x] `InitiatedBy.user.ipAddress` -- confirmed populated
- [x] `TargetResources[0].displayName` -- confirmed populated with app display name (e.g. "ChatGPT")
- [x] `TargetResources[0].id` -- confirmed populated with app object ID
- [x] `tostring(TargetResources) has_any (SensitivePermissions)` -- confirmed as correct approach; permission names appear in raw JSON blob
- [x] `Chat.Read` and `ChannelMessage.Read.All` added to SensitivePermissions -- confirmed relevant after ChatGPT finding

---

## Test Results

**30-day validation -- 2026-04-21 to 2026-05-21**
**Total events:** 10 across two callers

| Date | OperationName | Target App | Initiator | Disposition |
|------|--------------|-----------|-----------|-------------|
| 2026-05-05 | Add delegated permission grant | Microsoft Graph | admin-bogle | Benign -- MDE/Defender XDR integration |
| 2026-05-05 | Add delegated permission grant | WindowsDefenderATP | admin-bogle | Benign -- MDE integration |
| 2026-05-04 | Consent to application | SharePoint - Homestead | admin-bogle | Benign -- SharePoint app provisioning |
| 2026-05-04 | Add delegated permission grant | Office 365 SharePoint Online | admin-bogle | Benign -- SharePoint app provisioning |
| 2026-04-30 | Consent to application | Graph Explorer | admin-GKoerhui | Benign -- Microsoft API testing tool |
| 2026-04-30 | Add delegated permission grant | Microsoft Graph | admin-GKoerhui | Benign -- Graph Explorer setup |
| 2026-04-23 | Consent to application | ChatGPT | admin-GKoerhui | **Investigated** -- tenant-wide admin consent including Mail.Read, Chat.Read, offline_access. Consent confirmed approved; OpenAI for Enterprise in place; 0 CloudAppEvents activity. See [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]] |
| 2026-04-23 | Consent to application | ChatGPT | admin-GKoerhui | **Investigated** -- second consent event adding MailboxSettings.Read. Same finding. |

**Result: 10 events in 30 days, all admin accounts, all investigated and explained.
Noise floor acceptable for Count > 0 deployment.**

---

## Deployment

<!-- INACTIVE: MDE Custom Detection -- AuditLogs is Log Analytics only -->

### Sentinel Analytics Rule
- **Rule Name:** Graph API Broad Permission Grant to Service Principal
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** High
- **Trigger:** Count > 0
- **Entity Mapping:** Account → InitiatorUPN; CloudApplication → TargetAppName
- **MITRE Tactics:** Persistence, Privilege Escalation
- **MITRE Techniques:** T1528, T1098.003
- **Suppression:** None
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

---

## Exclusion Rationale

No allowlist applied. Every broad Graph permission grant warrants review regardless of
the granting account. If chronic false positives emerge from a known provisioning
workflow, add a CorrelationId-based suppression scoped to the specific provisioning
service principal rather than a broad exclusion.

---

## Hardening Control Pair
- **Control:** [[HARD-Entra-App-Registration-Permissions-Audit]]
- **Linked:** [ ]

---

## Related Notes
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] -- source KQL note
- [[INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit]] -- source intel
- [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]] -- real-world example surfaced during validation
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]] -- companion rule
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]] -- companion rule
- [[HARD-Entra-App-Registration-Permissions-Audit]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-21 | Created -- promoted from KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal |
| 2026-05-21 | Operation name corrected -- "Add app role assignment to service principal" does not exist in tenant; replaced with "Consent to application" and "Add delegated permission grant" |
| 2026-05-21 | Chat.Read and ChannelMessage.Read.All added to SensitivePermissions after ChatGPT finding |
| 2026-05-21 | 30-day validation complete -- 10 events, all investigated, ChatGPT finding documented |
