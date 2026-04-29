---
title: Entra Agent ID Administrator Role — Service Principal Scope Overreach (Patched)
date: 2026-04-28
source: https://cybersecuritynews.com/entra-agent-id-administrator-abused/
source_secondary: https://www.csoonline.com/article/4163708/microsoft-patched-an-agent-only-role-that-was-not.html
tags:
  - "#intel"
  - "#identity"
  - "#cloud"
  - "#status/active"
  - "#action-required"
detection_candidate: true
---

# INTEL — Entra Agent ID Administrator Role: Service Principal Scope Overreach (Patched Apr 9 2026)

## Source
- **Primary:** CybersecurityNews / Silverfort research — 2026-04-26
- **Secondary:** The Hacker News, CSO Online, Hackread
- **Disclosed by:** Silverfort (Noa Ariel, Yoav S) — disclosed to MSRC 2026-03-01, patched 2026-04-09
- **Original email subject:** `[INTEL] Hackers Can Abuse Entra Agent ID Administrator Role to Hijack Service Principals`

## MITRE ATT&CK
| Tactic | Technique |
|--------|-----------|
| Privilege Escalation | T1078.004 — Valid Accounts: Cloud Accounts |
| Persistence | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| Defense Evasion | T1550.001 — Use Alternate Authentication Material |
| Impact | T1548 — Abuse Elevation Control Mechanism |

## Detection Candidate
> ⚠️ **Yes** — audit log events for service principal ownership changes and new credential additions are directly detectable in Sentinel/AuditLogs

## Summary
Silverfort researchers discovered a critical scope overreach in Microsoft's Entra Agent Identity Platform. The newly introduced `Agent ID Administrator` role — designed only to manage AI agent identities — had a boundary breakdown that allowed it to modify ownership of any service principal in the tenant, not just agent-related ones. Once an attacker assigned themselves as owner of a high-privileged service principal, they could generate new client credentials and authenticate as that application. In a tenant where any service principal holds elevated directory roles or high-impact Graph API permissions, this is a full tenant takeover primitive. Silverfort demonstrated successful hijack of a Global Administrator account in a proof-of-concept. ~99% of enterprise tenants have at least one privileged service principal. Microsoft patched the issue across all cloud environments by April 9, 2026 — the Agent ID Administrator role can no longer modify non-agent service principal ownership.

## Technical Detail
- The vulnerability is architectural: Entra AI agent identities are built on standard service principal primitives, so the "agent-only" scope was not enforced at the object-model level
- The Entra UI did not flag `Agent ID Administrator` as a privileged role, increasing the risk of casual assignment by admins
- Attack chain: Assign Agent ID Admin role to attacker account → use it to add self as owner of target service principal → generate new client secret/certificate → authenticate as that SP → inherit its permissions
- The `privileged` indicator discrepancy in the Entra UI will be fixed separately
- Patch confirmed rolled out by MSRC April 9, 2026 — no customer action required for the fix itself

## Relevance to Environment
- **Directly relevant to M365-Hardening project** — this is the service principal abuse gap flagged as an active priority.
- Even though patched, the attack pattern (service principal ownership abuse, credential addition) remains a valid post-compromise technique from ANY route.
- Must verify: does your environment have the `Agent ID Administrator` role assigned anywhere? If so, who holds it and when was it assigned?
- Must audit: all privileged service principals for unexpected owner additions or credentials added around March–April 2026.
- This is the CVE referenced in active security context notes (patched April 9, 2026).

## Detection Notes

### KQL — Service Principal Credential or Owner Changes (Sentinel AuditLogs)
```kql
// Schema: Sentinel — AuditLogs
AuditLogs
| where OperationName in (
    "Add owner to service principal",
    "Add service principal credentials",
    "Update service principal"
)
| where TimeGenerated > ago(90d)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetDisplayName = tostring(TargetResources[0].displayName)
| extend TargetId = tostring(TargetResources[0].id)
| project TimeGenerated, OperationName, InitiatedBy, TargetDisplayName, TargetId, Result
| order by TimeGenerated desc
```

### KQL — Agent ID Administrator Role Assignments (Sentinel AuditLogs)
```kql
// Schema: Sentinel — AuditLogs
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName == "Agent ID Administrator"
| extend AssignedTo = tostring(TargetResources[1].userPrincipalName)
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, RoleName, AssignedTo, AssignedBy, Result
```

### Schema Validation
- [ ] `AuditLogs` — Sentinel Log Analytics table ✓
- [ ] `OperationName` — confirm exact string for "Add owner to service principal" in your tenant — may vary slightly
- [ ] `TargetResources[0]` — standard AuditLogs structure, should be consistent
- [ ] `InitiatedBy.user.userPrincipalName` — parse_json may be required if flattening is not enabled

## Hardening Actions
- [ ] **Immediate:** Run AuditLogs query — check all service principal ownership changes in the past 90 days
- [ ] **Immediate:** Audit who holds the `Agent ID Administrator` role in your tenant
- [ ] **Immediate:** Enumerate all privileged service principals using Azure CLI + Graph API (see Silverfort blog for script)
- [ ] Review all service principals for unexpected credentials added since January 2026
- [ ] Treat all high-privileged service principals as critical infrastructure — apply PIM or equivalent controls where possible
- [ ] Create Sentinel analytics rule on service principal owner/credential additions

## Sentinel Analytics Rule Recommendation
- **Frequency:** Every 5 minutes
- **Lookback:** 5 minutes
- **Severity:** High
- **Alert trigger:** Any ownership or credential addition on a service principal

## Related Notes
- [[Projects/M365-Hardening]] — active priority
- [[Research/Articles]] — Entra Connect SyncJacking note
- [[Detection-KQL/Analytics-Rules]] — create analytics rule from KQL stub

## Validated Columns
- [ ] `OperationName` — AuditLogs — validate exact string in tenant
- [ ] `TargetResources[0].displayName` — may require `tostring()` or `parse_json()`
- [ ] `InitiatedBy.user.userPrincipalName` — confirm via test query in your Sentinel workspace

## Changelog
| Date | Change |
|------|--------|
| 2026-04-28 | Created from inbox triage — links to M365-Hardening active project |
