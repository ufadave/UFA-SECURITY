---
title: Entra Agent ID Administrator — Service Principal Hijack via Scope Gap (Patched Apr 9)
date: 2026-04-26
source: https://cybersecuritynews.com/entra-agent-id-administrator-abused/
author: Silverfort (Noa Ariel, Yoav S)
mitre:
  - T1078.004
  - T1098
  - T1136.003
  - T1550.001
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#identity"
  - "#cloud"
  - "#action-required"
---

# Entra Agent ID Administrator — Service Principal Hijack via Scope Gap

> ⚠️ Patched April 9, 2026 — but post-patch audit of role assignments and SP ownership is required. The patch does not remove previously added owners or credentials.

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://cybersecuritynews.com/entra-agent-id-administrator-abused/ |
| **Research Firm** | Silverfort — Noa Ariel and Yoav S |
| **Date Observed** | 2026-04-26 |
| **Date Published** | 2026-04-25 |
| **Patch Status** | ✅ Fully patched — all cloud environments as of April 9, 2026 |
| **CVE** | Not yet assigned at time of writing |
| **MSRC** | Reported Mar 1, confirmed Mar 26, patched Apr 9 |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1078.004 | Valid Accounts: Cloud Accounts |
| T1098 | Account Manipulation |
| T1098.001 | Account Manipulation: Additional Cloud Credentials |
| T1136.003 | Create Account: Cloud Account |
| T1550.001 | Use Alternate Authentication Material: Application Access Token |

---

## Summary

A critical scope overreach vulnerability in the Microsoft Entra Agent Identity Platform allowed any user assigned the Agent ID Administrator role to take ownership of arbitrary service principals across the entire tenant — including high-privileged ones with no connection to AI agents. The Agent ID Administrator role was introduced to manage AI agent identities (blueprints, agent users), which are technically implemented as service principals. This shared architecture created a boundary gap: the role's ownership permission was not restricted to agent-backed objects, allowing it to silently operate as a shadow Application Administrator. Once ownership was claimed, an attacker could attach new credentials (client secret or certificate) and authenticate as the targeted service principal, inheriting all its permissions including Graph API roles and directory assignments. A Silverfort demo confirmed this path could reach Global Administrator via a privileged service principal. The Entra UI did not flag the role as privileged, increasing the likelihood of inadvertent assignment. The patch blocks the role from modifying non-agent service principal ownership going forward. Previously added owners and credentials are not cleaned up automatically.

---

## Relevance to Environment

**High — action required.** The role is active in tenants using Entra ID AI agent features. The attack path bypasses MFA and Conditional Access because it uses app-only tokens. No sign-in logs alert is generated for this activity in standard SIEM rules. Audit window: any unexpected SP ownership changes between February 24 and April 9, 2026 should be investigated. Priority targets would be service principals with RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, or equivalent high-impact Graph permissions.

---

## Detection Notes

### KQL Stubs

```kql
// Detect service principal ownership changes in AuditLogs
// Table: AuditLogs
// Schema: Log Analytics (Sentinel)
// Purpose: Identify unexpected SP ownership additions — key indicator of exploitation

AuditLogs
| where OperationName =~ "Add owner to service principal"
| where Result =~ "success"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ActorIP = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| mv-expand TargetResources
| extend TargetSP = tostring(TargetResources.displayName)
| project TimeGenerated, Actor, ActorIP, TargetSP, OperationName, Result
| sort by TimeGenerated desc
```

```kql
// Detect new credentials added to service principals
// Table: AuditLogs
// Schema: Log Analytics (Sentinel)
// Purpose: Alert on client secret or certificate additions to service principals

AuditLogs
| where OperationName in~ (
    "Update application – Certificates and secrets management",
    "Add service principal credentials",
    "Update service principal"
)
| where Result =~ "success"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| mv-expand TargetResources
| extend TargetApp = tostring(TargetResources.displayName)
| project TimeGenerated, Actor, TargetApp, OperationName
| sort by TimeGenerated desc
```

```kql
// Detect Agent ID Administrator role assignments
// Table: AuditLogs
// Schema: Log Analytics (Sentinel)
// Purpose: Alert on assignment of Agent ID Administrator role — should be rare

AuditLogs
| where OperationName =~ "Add member to role"
| where Result =~ "success"
| mv-expand TargetResources
| extend RoleName = tostring(TargetResources.displayName)
| where RoleName =~ "Agent ID Administrator"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project TimeGenerated, Actor, RoleName, OperationName
```

### Validated Columns
- [ ] `InitiatedBy.user.userPrincipalName` — AuditLogs nested field, requires `parse_json(tostring(...))` pattern
- [ ] `TargetResources.displayName` — confirm after `mv-expand TargetResources`
- [ ] `OperationName` values — validate exact strings in your Sentinel workspace

---

## Hardening Actions

- [ ] **IMMEDIATE** — Audit all current Agent ID Administrator role assignments: identify who holds it and whether assignment was intentional
- [ ] **IMMEDIATE** — Review AuditLogs for "Add owner to service principal" events between Feb 24 and Apr 9, 2026
- [ ] Enumerate service principals with high-impact Graph permissions (RoleManagement.ReadWrite.Directory, Application.ReadWrite.All)
- [ ] Rotate credentials on any privileged service principals, regardless of whether abuse is confirmed
- [ ] Enable PIM (Privileged Identity Management) for Agent ID Administrator role — convert permanent assignments to JIT
- [ ] Confirm Agent ID Administrator is now flagged as privileged in the Entra UI (Microsoft stated this will be corrected)

---

## Related Notes

- [[Hardening/Controls/]]
- [[Projects/M365-Hardening/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-26 | Created from Gmail [INTEL] triage |
