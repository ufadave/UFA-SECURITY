---
title: INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit
date: 2026-04-30
source: https://github.com/OtterHacker/M365Pwned
author: OtterHacker
mitre:
  - T1528
  - T1114.002
  - T1530
  - T1087.004
  - T1567
detection_candidate: true
promoted_to_rule: true
sentinel_rule_id: ""
promoted_kql_notes:
  - "[[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]]"
  - "[[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]]"
  - "[[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]]"
tags:
  - "#intel"
  - "#status/draft"
  - "#action-required"
  - "#cloud"
  - "#identity"
  - "#email"
---

# INTEL — M365Pwned: OAuth Application Token Enumeration & Exfiltration Toolkit

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/OtterHacker/M365Pwned |
| **Author** | OtterHacker (security researcher) |
| **Date Observed** | 2026-04-30 |
| **Date Published** | ~2026-03-09 |
| **Threat Type** | Red team / post-compromise offensive toolkit |
| **Patch Available** | N/A — abuses legitimate Graph API permissions, not a vulnerability |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------| 
| Steal Application Access Token | T1528 | Core mechanism |
| Email Collection: Remote Email Collection | T1114.002 | MailPwned component |
| Data from Cloud Storage | T1530 | SharePwned component |
| Account Discovery: Cloud Account | T1087.004 | User enumeration |
| Exfiltration Over Web Service | T1567 | Graph API exfil path |

---

## Summary

M365Pwned is a publicly released red team toolkit consisting of two PowerShell 5.1 WinForms GUI tools — MailPwned (Exchange Online / Outlook) and SharePwned (SharePoint / OneDrive). Both tools operate using application-level OAuth tokens obtained from a registered Entra ID application with admin-consented permissions, requiring no interactive user session. The toolkit leverages the Microsoft Graph API to enumerate users, search mailbox content, download attachments, browse SharePoint sites, and exfiltrate files across an entire M365 tenant.

Three authentication methods are supported: Client Secret, Certificate Thumbprint, and Raw Access Token (pass-the-token). This is a post-compromise tool — it requires an attacker to have already obtained valid app credentials or a live Graph token, but once they do, the attack surface is the full tenant scope granted to the registered application. Detection footprint is deliberately low: UPN lists can be pre-loaded from OSINT to avoid GET /users enumeration calls, and downloaded HTML emails embed images as data URIs to prevent outbound requests.

---

## Relevance to Environment

High. The environment runs E5 M365 with Exchange Online, SharePoint, and OneDrive. If any registered application in the tenant holds broad permissions (Mail.Read, Files.Read.All, User.Read.All, Sites.Read.All), a compromised app credential or leaked token would enable an adversary to execute this toolkit with no further foothold. Infostealer compromise or a developer workstation breach are realistic entry paths given the active threat model. The ongoing Entra app registration audit (#action-required) directly addresses the attack surface this toolkit requires.

The toolkit is explicitly designed to minimise audit footprint — pre-loading UPN lists bypasses GET /users enumeration, image embedding prevents outbound requests, and operation is fully offline after token acquisition.

---

## Detection Notes

### Key Observables
- Application-only Graph API access from uncommon IPs or outside business hours
- Enumeration of all mailboxes via GET /users followed by per-user GET /users/{id}/messages
- Bulk message read or attachment download events under a single app identity
- SharePoint site enumeration via GET /sites?search=* or GET /drives
- Use of /v1.0/search/query with driveItem entity type at scale

### KQL Stubs

All three stubs below have been promoted to companion KQL notes (2026-05-03). See `## Related Notes` for links. Stubs retained here for reference.

**CloudAppEvents — App-only bulk mailbox access**
→ Promoted to [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]]
> Schema corrections applied on promotion: `ApplicationId != ""` replaced with correct field; `AccountType == "Application"` is not a valid value — only "Regular" and "Admin" exist in this tenant. `OAuthAppId` is the correct OAuth app identifier field. `ActionType == "MailItemsAccessed"` not generated for app-level Graph access — if ObjectType == "Email", ActionTypes are MoveToDeletedItems, Create, SoftDelete, Update. ObjectName for Email is the email subject, not mailbox UPN.

```kql
CloudAppEvents
| where ActionType == "MailItemsAccessed"
| where ApplicationId != ""
| summarize MailboxCount = dcount(AccountObjectId), AccessCount = count()
    by ApplicationId, Application, bin(Timestamp, 1h)
| where MailboxCount > 10
| order by MailboxCount desc
```

**AuditLogs — Broad Graph API permissions granted to service principal**
→ Promoted to [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]]
> Expanded permission list; mv-expand logic added to extract specific permission name from ModifiedProperties.

```kql
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where TargetResources has_any ("Mail.Read", "Files.Read.All", "Sites.Read.All", "User.Read.All", "Mail.ReadWrite")
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

**AADNonInteractiveUserSignInLogs — Application sign-in anomaly**
→ Promoted to [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]]
> Primary table changed to AADNonInteractiveUserSignInLogs. Detection logic reframed around unknown app identity rather than volume threshold.

```kql
AADNonInteractiveUserSignInLogs
| where IsInteractive == false
| where AppId !in (dynamic([]))  // populate with known-good app IDs
| where ResultType == 0
| summarize count() by AppId, AppDisplayName, IPAddress, UserAgent
| where count_ > 50
```

**AuditLogs — Admin consent grants to high-risk Graph scopes**

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend ConsentedPermissions = tostring(AdditionalDetails)
| where ConsentedPermissions has_any ("Mail.Read", "Files.Read.All", "Sites.Read.All", "User.Read.All", "Mail.ReadWrite")
| project TimeGenerated, AppDisplayName, InitiatedBy, ConsentedPermissions
| sort by TimeGenerated desc
```

### Validated Columns
- [x] `AccountType` — only "Regular" and "Admin" exist in this tenant; "Application" is not a valid value
- [x] `ApplicationId` — column exists in CloudAppEvents; note: is int type, use OAuthAppId for OAuth app identifier
- [x] `ObjectName` — represents file path when ObjectType is File; represents email subject when ObjectType is Email
- [x] `ActionType == "MailItemsAccessed"` — not generated for app-level Graph access; Email ObjectType ActionTypes are: MoveToDeletedItems, Create, SoftDelete, Update
- [ ] `AuditLogs` — confirm M365 audit logs are flowing to Sentinel workspace
- [ ] `AADNonInteractiveUserSignInLogs` — confirm table is populated in Sentinel workspace
- [ ] `AuditLogs OperationName == "Add app role assignment to service principal"` — confirm operation name for permission grant events

---

## Hardening Actions

- [ ] **Audit all Entra app registrations** with Mail.Read, Files.Read.All, Sites.Read.All, or User.Read.All application permissions — remove or scope-down any not actively required (#action-required) [[HARD-Entra-App-Registration-Permissions-Audit]]
- [ ] **Review app registration client secrets** — rotate any that are long-lived or have no expiry
- [ ] **Alert on new admin-consented app permissions** — promote AuditLogs consent grant stub to Sentinel analytics rule
- [ ] **Conditional Access for workload identities** — restrict service principals to known IP ranges where possible (Entra Workload Identity Premium required)
- [ ] **Monitor for pass-the-token usage** — raw access token auth (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer) is a detection signal
- [ ] **Confirm M365 Unified Audit Log** is enabled and streaming to Sentinel — required for CloudAppEvents and AuditLogs coverage
- [ ] **Review Defender for Cloud Apps policies** — enable anomaly detection for app-only large-scale data access

## Sentinel Analytics Rule Config
| Setting | Value |
|---------|-------|
| Rule Name | App-Only Bulk Mailbox Enumeration via Graph |
| Severity | High |
| Query Frequency | 1h |
| Query Period | 1h |
| Trigger | Count > 0 |
| MITRE Tactics | Collection, Exfiltration |

---

## Related Notes

- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]]
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]]
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]]
- [[INTEL-Entra-Agent-ID-Administrator-Service-Principal-Hijack]]
- [[HARD-Entra-App-Registration-Permissions-Audit]]
- [[Projects/M365-Hardening/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-30 | Initial note created from inbox triage |
| 2026-05-03 | Three KQL stubs promoted to companion KQL notes |
| 2026-05-05 | Schema validation findings added — AccountType, ActionType, ObjectName behaviour documented from live tenant |
| 2026-05-21 | Merged from three duplicate notes into single canonical note |
