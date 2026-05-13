---
title: "M365Pwned — OAuth Application Token Enumeration & Exfiltration Toolkit"
date: 2026-04-30
source: https://github.com/OtterHacker/M365Pwned
type: intel
status: draft
mitre_techniques:
  - T1528 (Steal Application Access Token)
  - T1114.002 (Email Collection: Remote Email Collection)
  - T1530 (Data from Cloud Storage)
  - T1087.004 (Account Discovery: Cloud Account)
detection_candidate: true
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#Enumeration"
  - "#intel"
  - "#cloud"
  - "#identity"
  - "#status/draft"
  - "#action-required"
---

# INTEL — M365Pwned: OAuth Application Token Enumeration & Exfiltration Toolkit

## Source
- **URL:** https://github.com/OtterHacker/M365Pwned
- **Date Reported:** 2026-04-25 (forwarded 2026-04-30)
- **Author/Actor:** OtterHacker (security researcher)
- **Threat Type:** Red team / post-compromise offensive toolkit

## MITRE ATT&CK
| Technique | ID | Relevance |
|---|---|---|
| Steal Application Access Token | T1528 | Core mechanism |
| Remote Email Collection | T1114.002 | MailPwned component |
| Data from Cloud Storage | T1530 | SharePwned component |
| Cloud Account Discovery | T1087.004 | User enumeration |
| Exfiltration Over Web Service | T1567 | Graph API exfil path |

## Summary

M365Pwned is a publicly released red team toolkit consisting of two PowerShell 5.1 WinForms GUI tools — **MailPwned** (Exchange Online / Outlook) and **SharePwned** (SharePoint / OneDrive). Both tools operate using application-level OAuth tokens obtained from a registered Azure AD application with admin-consented permissions, requiring no interactive user session. The toolkit leverages the Microsoft Graph API to enumerate users, search mailbox content, download attachments, browse SharePoint sites, and exfiltrate files across an entire M365 tenant.

Three authentication methods are supported: Client Secret, Certificate Thumbprint, and Raw Access Token (pass-the-token). This is a **post-compromise tool** — it requires an attacker to have already obtained valid app credentials or a live Graph token, but once they do, the attack surface is the full tenant scope granted to the registered application.

## Relevance to Environment

**High.** Your organisation runs E5 M365 with Exchange Online, SharePoint, and OneDrive. If any registered application in your tenant holds broad permissions (`Mail.Read`, `Files.Read.All`, `User.Read.All`, `Sites.Read.All`), a compromised app credential or leaked token would enable an adversary to execute this toolkit with no further foothold. Infostealer compromise or a developer workstation breach are realistic entry paths given your threat model.

The toolkit is explicitly designed to minimize audit footprint by pre-loading UPN lists from OSINT (bypassing `GET /users` enumeration), embedding images as data URIs in downloaded emails, and operating fully offline after token acquisition.

## Detection Notes

### Key Observables
- **Application-only Graph API access** from uncommon IPs or outside business hours
- Enumeration of all mailboxes via `GET /users` followed by per-user `GET /users/{id}/messages`
- Bulk message read or attachment download events under a single app identity
- SharePoint site enumeration via `GET /sites?search=*` or `GET /drives`
- Use of `/v1.0/search/query` with `driveItem` entity type at scale

### KQL Stubs

**Sentinel / CloudAppEvents — App-only bulk mailbox access**
```kql
CloudAppEvents
| where ActionType == "MailItemsAccessed"
| where ApplicationId != "" // app-only — no delegated user
| summarize MailboxCount = dcount(AccountObjectId), AccessCount = count() 
    by ApplicationId, Application, bin(Timestamp, 1h)
| where MailboxCount > 10
| order by MailboxCount desc
```
> **Schema note:** Validate `ApplicationId` and `AccountObjectId` availability in your `CloudAppEvents` table. Column names can vary. Cross-reference with `AuditLogs` (`Microsoft.Graph` category) for Graph-sourced events.

**Sentinel / AuditLogs — Broad Graph API delegated or app permissions granted**
```kql
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where TargetResources has_any ("Mail.Read", "Files.Read.All", "Sites.Read.All", "User.Read.All")
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

**Sentinel / SigninLogs — Application sign-in anomaly (non-interactive)**
```kql
SigninLogs
| where IsInteractive == false
| where AppId !in (known_good_app_ids) // maintain allowlist
| where ResultType == 0
| summarize count() by AppId, AppDisplayName, IPAddress, UserAgent
| where count_ > 50
```

### Validated Columns (to verify in your environment)
- [ ] `CloudAppEvents.ActionType` — confirm "MailItemsAccessed" fires for app-only access
- [ ] `CloudAppEvents.ApplicationId` — present in app-only scenarios
- [ ] `AuditLogs.TargetResources` — confirm Graph permission grant events route here
- [ ] `SigninLogs.IsInteractive` — boolean, confirm available
- [ ] `SigninLogs.AppId` — confirm populated for service principals

### Test Results
- [ ] Tested in environment
- [ ] False positive rate assessed
- [ ] Promoted to analytics rule

## Hardening Actions
1. **Audit registered applications** — enumerate all app registrations in Entra ID with `Mail.Read`, `Files.Read.All`, `Sites.Read.All`, or `User.Read.All` at application-permission level. Remove over-provisioned scopes immediately. [[HARD-Entra-App-Registration-Permissions-Audit]]
2. **Alert on new admin-consented app permissions** — create Sentinel analytics rule on `AuditLogs` for `Add app role assignment to service principal`.
3. **Conditional Access for workload identities** — restrict service principals to known IP ranges where possible.
4. **Monitor for pass-the-token usage** — raw access token auth (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) is a detection signal.
5. **Review Defender for Cloud Apps policies** — enable anomaly detection for app-only large-scale data access.

## Related Notes
- [[INTEL-Entra-Agent-ID-Administrator-Service-Principal-Hijack]]
- [[PROJ-M365-Hardening]]
- [[HARD-Conditional-Access-Policy-Audit]]

## Sentinel Analytics Rule Config
| Setting | Value |
|---|---|
| Rule Name | App-Only Bulk Mailbox Enumeration via Graph |
| Severity | High |
| Query Frequency | 1h |
| Query Period | 1h |
| Trigger | Count > 0 |
| MITRE Tactics | Collection, Exfiltration |

## Changelog
| Date | Change |
|---|---|
| 2026-04-30 | Initial note created from inbox triage |
---
*Detection candidate — KQL stubs require schema validation before promotion.*
