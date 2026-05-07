---
title: INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit
date: 2026-05-05
source: "https://github.com/OtterHacker/M365Pwned"
author: "OtterHacker"
mitre:
  - "T1530"
  - "T1114.002"
  - "T1213.002"
  - "T1528"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#cloud"
  - "#identity"
  - "#email"
---

# INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/OtterHacker/M365Pwned |
| **Author** | OtterHacker |
| **Date Observed** | 2026-05-05 |
| **Date Published** | ~2026-03-09 |
| **Patch Available** | N/A — not a vulnerability; abuses legitimate Graph API permissions |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1530 | Data from Cloud Storage |
| T1114.002 | Email Collection: Remote Email Collection |
| T1213.002 | Data from Information Repositories: SharePoint |
| T1528 | Steal Application Access Token |

---

## Summary

M365Pwned is a publicly released red team toolkit consisting of two PowerShell WinForms GUI tools — `MailPwned-GUI.ps1` (Exchange Online) and `SharePwned-GUI.ps1` (SharePoint/OneDrive) — that use application-level OAuth tokens to enumerate, search, and exfiltrate data from M365 tenants without any user interaction. The toolkit operates via the Microsoft Graph API and requires a registered Entra ID application with admin-consented application permissions (e.g., `Mail.Read`, `Files.Read.All`, `User.Read.All`, `Sites.Read.All`). No new vulnerability is exploited — the attack vector is solely compromised OAuth app credentials or a stolen access token. Detection footprint is deliberately low: UPN lists can be pre-loaded to avoid `GET /users` calls, and downloaded HTML emails embed images as data URIs to prevent outbound requests.

---

## Relevance to Environment

This is directly relevant given the M365 E5 footprint, Exchange Online, SharePoint, and OneDrive exposure. If an attacker compromises an Entra app registration with broad Graph permissions — through credential theft, a supply chain compromise, or a misconfigured app — this toolkit (or similar) could silently enumerate all mailboxes and SharePoint sites and exfiltrate attachments with minimal audit trail. Application-level access bypasses per-user MFA since no user sign-in is required. The recent Entra Agent ID Administrator CVE and ongoing service principal audit work make this directly timely — broad app permissions are the attack surface here. The OAI cybersecurity action plan email (pending review) may also be relevant to this threat category.

---

## Detection Notes

### KQL Stubs

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting (MDE / Defender XDR)
// Purpose: Detect application-only Graph API access to mailboxes or SharePoint at scale
// Note: Validate that 'ApplicationId', 'AccountType', 'ActionType', 'ObjectName' columns exist in your tenant

CloudAppEvents
| where Timestamp > ago(1d)
| where ApplicationId != "" // app-only access
| where AccountType == "Application"
| where ActionType in ("MailItemsAccessed", "FileDownloaded", "FileAccessed", "SearchQueryInitiatedExchange")
| summarize count() by ApplicationId, AccountDisplayName, ActionType, bin(Timestamp, 1h)
| where count_ > 50 // threshold — tune to baseline
| sort by count_ desc
```

```kql
// Table: AuditLogs (Entra / Log Analytics)
// Schema: Sentinel / Log Analytics
// Purpose: Detect admin consent grants to application permissions (Graph scopes)
// Flags new or modified app permission grants — prerequisite for this attack class

AuditLogs
| where OperationName == "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend ConsentedPermissions = tostring(AdditionalDetails)
| where ConsentedPermissions has_any ("Mail.Read", "Files.Read.All", "Sites.Read.All", "User.Read.All", "Mail.ReadWrite")
| project TimeGenerated, AppDisplayName, InitiatedBy, ConsentedPermissions
| sort by TimeGenerated desc
```

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting (MDE / Defender XDR)
// Purpose: Detect bulk mailbox enumeration via application access — M365Pwned MailPwned pattern
// Per-user mailbox iteration (GET /users/{id}/messages) is distinctive at volume

CloudAppEvents
| where Timestamp > ago(4h)
| where AccountType == "Application"
| where ActionType == "MailItemsAccessed"
| summarize DistinctMailboxes = dcount(ObjectName), TotalEvents = count() by ApplicationId, AccountDisplayName, bin(Timestamp, 30m)
| where DistinctMailboxes > 10
| sort by DistinctMailboxes desc
```

### Validated Columns
- [ ] `AccountType` — confirm `"Application"` value in `CloudAppEvents` for app-only access in your tenant
- [ ] `ApplicationId` — confirm column name in `CloudAppEvents` (may be `AppId` in some schemas)
- [ ] `ObjectName` — confirm this reflects mailbox UPN or file path in `CloudAppEvents`
- [ ] `ActionType == "MailItemsAccessed"` — confirm this action type is generated for app-level Graph access (requires M365 Audit enabled)
- [ ] `AuditLogs` — confirm M365 audit logs are flowing to Sentinel workspace

---

## Hardening Actions

- [ ] Audit all Entra app registrations with `Mail.Read`, `Files.Read.All`, `Sites.Read.All`, or `User.Read.All` application permissions — remove or scope-down any that are not actively required (`#action-required`)
- [ ] Review app registration client secrets — rotate any that are long-lived or have no expiry
- [ ] Enable Conditional Access for workload identities where supported (Entra Workload Identity Premium required)
- [ ] Confirm M365 Unified Audit Log is enabled and streaming to Sentinel — required for `CloudAppEvents` and `AuditLogs` coverage
- [ ] Consider alerting on admin consent grants to high-risk Graph scopes as an analytics rule

---

## Related Notes

- [[Hardening/Controls/HARD-Entra-App-Registration-Audit]]
- [[Projects/M365-Hardening/]]
- [[Threat-Hunting/TTPs/INTEL-Entra-SyncJacking]]

---

## Tags

#intel #status/draft #cloud #identity #email #infostealer

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-05 | Created — M365Pwned OAuth toolkit public release |
