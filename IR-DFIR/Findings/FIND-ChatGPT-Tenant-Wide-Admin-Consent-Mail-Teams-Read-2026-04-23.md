---
title: FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23
date: 2026-05-21
case_id:
alert_id:
severity: Medium
status: done
tags:
  - "#ir"
  - "#finding"
  - "#status/done"
  - "#cloud"
  - "#identity"
  - "#email"
  
---

# FIND — ChatGPT Tenant-Wide Admin Consent: Mail.Read + Teams Chat Access (2026-04-23)

**Date:** 2026-05-21
**Analyst:** Dave
**Severity:** Medium
**Status:** Conditionally Approved

---

## Source

| Field | Value |
|-------|-------|
| **Alert / Signal** | Proactive investigation — AuditLogs permission grant review during M365Pwned detection build |
| **Platform** | Sentinel / AuditLogs |
| **Affected Asset(s)** | All M365 user mailboxes, Teams channels, and calendars (tenant-wide) |
| **Affected User(s)** | All principals (ConsentType: AllPrincipals) |
| **Detection Time** | 2026-05-21 |
| **Triage Time** | 2026-05-21 |

---

## Observation

On 2026-04-23, `admin-GKoerhui@ufa.com` granted admin consent to the ChatGPT application
(ClientId: `35a12b99-a762-4a55-97ce-5bbae696651c`) twice within 39 minutes (21:36 and 22:15
UTC), progressively expanding the scope. The consent applies to all principals in the tenant
(`ConsentType: AllPrincipals`). The second event added `MailboxSettings.Read` to the
already broad first grant.

**Full permission scope granted:**

| Scope | Risk |
|-------|------|
| `Mail.Read` | Read all email in every user's mailbox |
| `Mail.Read.Shared` | Read shared and delegated mailboxes |
| `ChannelMessage.Read.All` | Read all Teams channel messages tenant-wide |
| `Chat.Read` | Read all Teams private chat messages tenant-wide |
| `Calendars.Read` | Read all calendar entries |
| `Calendars.Read.Shared` | Read shared calendar entries |
| `MailboxSettings.Read` | Read mailbox settings for all users |
| `User.Read` | Read user profile information |
| `offline_access` | Maintain persistent access via refresh token — no re-auth required |
| `openid`, `email` | Authentication and identity scopes |

**`offline_access` is the most operationally significant scope** — ChatGPT can silently
refresh its token and maintain persistent read access to all of the above without any
further user interaction or sign-in prompt.

---

## Investigation Notes

### KQL Query Used

```kql
AuditLogs
| where TimeGenerated between (datetime(2026-04-23T21:00:00Z) .. datetime(2026-04-23T23:00:00Z))
| where OperationName == "Consent to application"
| where tostring(TargetResources) has "ChatGPT"
| extend Permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| project TimeGenerated, Permissions
```

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-04-23 21:36 | First admin consent granted — Mail.Read, Chat.Read, ChannelMessage.Read.All, Calendars.Read, offline_access and others. IP: 64.236.152.13 |
| 2026-04-23 22:15 | Second admin consent granted — same scopes plus MailboxSettings.Read added. IP: 172.214.178.187 |
| 2026-05-21 | Discovered during AuditLogs permission grant review |

### Open Questions

- [x] Was this an approved organisational decision? **Confirmed — consent was approved**
- [x] What data has ChatGPT accessed since April 23? **CloudAppEvents returned 0 rows — no tenant data accessed to date**
- [ ] What specific business requirement justified tenant-wide Mail.Read and Chat.Read access? — document for audit record
- [ ] Was the OpenAI for Enterprise DPA reviewed for M365-connected data handling, retention, and model training exclusions?
- [x] Do the two different IPs (64.236.152.13 and 172.214.178.187) represent the same admin session?
- [ ] Has a formal scope review been conducted — specifically whether Chat.Read, ChannelMessage.Read.All, and offline_access are required for the approved use case?

---

## Assessment

**Verdict:** Conditionally Approved — consent confirmed authorised; no data accessed to date; scope reduction recommended

Consent was confirmed as an approved organisational decision. CloudAppEvents returned 0 rows for ChatGPT since April 23, confirming no tenant data has been accessed through these permissions to date. OpenAI for Enterprise agreement is in place, providing baseline data handling protections.

**The core issue is not whether consent was approved, but whether the approver understood what was granted.** Admin consent for `Mail.Read`, `Chat.Read`, and `ChannelMessage.Read.All` on behalf of all principals means every employee's email and Teams messages are readable by ChatGPT — most approvers do not understand this when clicking through the consent flow. The consent should be formally documented with the specific scopes listed and reviewed by the approver with full scope awareness.

**Scope reduction recommendation:**

The following scopes are hard to justify for typical ChatGPT use cases and carry the highest risk:

| Scope | Justification Required |
|-------|----------------------|
| `ChannelMessage.Read.All` | Reads all Teams channel messages tenant-wide — only needed if ChatGPT is being used to summarise or search Teams channels organisation-wide |
| `Chat.Read` | Reads all Teams private chat messages — high sensitivity; only needed for direct chat integration |
| `offline_access` | Maintains persistent access without re-authentication — removes all visibility into ongoing access; revoke unless continuous background access is a documented requirement |
| `Mail.Read.Shared` | Read shared/delegated mailboxes — likely not needed for standard email drafting use case |

Scopes that may be justified for core ChatGPT functionality:
- `Mail.Read` — email context for drafting
- `Calendars.Read` — calendar context for scheduling
- `User.Read` — user identity
- `openid`, `email` — authentication

**Recommended action:** Engage the business owner and OpenAI account team to confirm minimum required scopes, then revoke the consent grant and re-consent with a reduced scope set. This is a standard practice for any third-party M365 integration.

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Technique | T1114.002 — Email Collection: Remote Email Collection |
| Additional | T1530 — Data from Cloud Storage |

---

## Actions Taken

- [x] Permission scopes confirmed via AuditLogs query
- [x] CloudAppEvents reviewed — 0 rows returned, no tenant data accessed to date
- [x] Consent confirmed as approved — OpenAI for Enterprise agreement in place
- [x] **Document formal approval record** — record business justification, approved scopes, approver identity, and review date in a vendor or policy note
- [x] **Review OpenAI Enterprise DPA** — confirm M365-connected data is excluded from model training, data retention limits, and processing location
- [x] **Scope reduction review** — engage business owner and OpenAI account team to confirm minimum required scopes; consider revoking and re-consenting with reduced scope set (remove ChannelMessage.Read.All, Chat.Read, offline_access, Mail.Read.Shared if not required)
- [x] **To revoke individual scopes:** Entra admin centre → Enterprise Applications → ChatGPT → Permissions → remove specific delegated permission grants
- [x] **Add to Entra app registration audit** — document ChatGPT as a reviewed app with broad Graph permissions; note approved status and review date

### CloudAppEvents investigation query

```kql
// Review ChatGPT activity since consent was granted
CloudAppEvents
| where Timestamp >= datetime(2026-04-23T21:00:00Z)
| where OAuthAppId == "35a12b99-a762-4a55-97ce-5bbae696651c"
    or Application has "ChatGPT"
| project Timestamp, AccountDisplayName, ActionType, ObjectName,
    ObjectType, IPAddress, UserAgent, OAuthAppId
| order by Timestamp desc
```

---

## Escalate to Case?

- [ ] Yes — if ChatGPT data access is confirmed in future CloudAppEvents review, or if scope reduction is refused and risk is accepted without formal documentation
- [x] No — consent confirmed approved, no data accessed to date; tracking via actions above

---

## Related Notes

- [[INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit]]
- [[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]]
- [[HARD-Entra-App-Registration-Permissions-Audit]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-21 | Created — discovered during AuditLogs permission grant review; consent scope confirmed via targeted query |
| 2026-05-21 | Updated — consent confirmed approved; CloudAppEvents returned 0 rows (no data accessed); severity reduced to Medium; scope reduction recommendation added; OpenAI for Enterprise agreement noted |
