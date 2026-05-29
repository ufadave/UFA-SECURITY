---
title: INTEL-AI-Assisted-Entra-ID-Tenant-Destruction
date: 2026-05-28
source: "https://netwrix.com/en/resources/blog/automating-entra-id-tenant-destruction-with-ai/"
author: "Huy Kha (Netwrix)"
mitre:
  - "T1098"
  - "T1078.004"
  - "T1531"
  - "T1562.001"
  - "T1550.001"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#identity"
  - "#cloud"
  - "#action-required"
---

# INTEL-AI-Assisted-Entra-ID-Tenant-Destruction

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://netwrix.com/en/resources/blog/automating-entra-id-tenant-destruction-with-ai/ |
| **Author** | Huy Kha (Netwrix) |
| **Date Observed** | 2026-05-28 |
| **Date Published** | 2026-05-21 |
| **Patch Available** | No — technique exploits legitimate Graph API functionality and browser tooling |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1098 | Account Manipulation |
| T1078.004 | Valid Accounts: Cloud Accounts |
| T1531 | Account Access Removal |
| T1562.001 | Impair Defenses: Disable or Modify Tools (CA policy deletion) |
| T1550.001 | Use Alternate Authentication Material: Application Access Token |

---

## Summary

A Netwrix researcher demonstrated how an AI browser agent (Claude for Chrome) combined with Microsoft Graph Explorer and injected browser-side JavaScript can automate large-scale destructive operations against an Entra ID tenant. The attack leverages a JavaScript `fetch` interceptor injected into Graph Explorer's page context to silently capture the signed-in user's Bearer token from outbound API requests, then uses that token to fire parallel bulk operations via `Promise.all()`. The AI agent autonomously navigates Graph Explorer's consent flow to escalate its own permission scopes — including `Application.ReadWrite.All` and `Policy.ReadWrite.ConditionalAccess` — without further user interaction. Demonstrated impact includes mass user deletion, account disablement, password resets, session revocation, app registration deletion, and Conditional Access policy removal, all executed from a single privileged browser session in seconds.

---

## Relevance to Environment

**High.** This technique requires only a single compromised privileged session to execute full tenant destruction — directly applicable to the known risks involving admin-CJones2, admin-GKoerhui, and admin-mrieger already under monitoring. The Stryker (March 2026) and Storm-0501 (August 2025) incidents cited in the article confirm this is an active attacker playbook, not a theoretical exercise. The CA policy deletion vector is especially acute given the ongoing Conditional Access refactor underway in the environment — a privileged session during that window could silently remove policies mid-rebuild. The Graph API consent grant component overlaps directly with the deployed `RULE-Graph-API-Broad-Permission-Grant-Service-Principal` detection, but that rule targets service principal consent grants via `AuditLogs`; an interactive admin granting themselves `Application.ReadWrite.All` through Graph Explorer may not match the same operation names and warrants a dedicated stub.

---

## Detection Notes

Three detection opportunities — consent grant escalation, CA policy deletion, and bulk identity operations — each warrant a separate KQL stub.

### KQL Stubs

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect interactive admin consent grants to high-privilege Graph API scopes via Graph Explorer or similar tools
// Note: Complements RULE-Graph-API-Broad-Permission-Grant-Service-Principal — this targets USER-initiated grants, not service principals

let HighPrivilegeScopes = dynamic([
    "Application.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
]);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName =~ "Consent to application"
    or OperationName =~ "Add delegated permission grant"
| extend TargetResources = parse_json(TargetResources)
| mv-expand TargetResources
| extend ModifiedProperties = TargetResources.modifiedProperties
| mv-expand ModifiedProperties
| extend PropName = tostring(ModifiedProperties.displayName)
| extend PropNew = tostring(ModifiedProperties.newValue)
| where PropName =~ "ConsentContext.IsAdminConsent" and PropNew =~ "True"
    or PropName has_any (HighPrivilegeScopes)
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend IPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| project TimeGenerated, OperationName, InitiatedByUser, IPAddress, PropName, PropNew, CorrelationId
```

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect deletion of Conditional Access policies — high-impact destructive action, should be rare or zero in normal operations

AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName =~ "Delete conditional access policy"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend IPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend PolicyName = tostring(parse_json(TargetResources)[0].displayName)
| project TimeGenerated, OperationName, InitiatedByUser, IPAddress, PolicyName, CorrelationId
```

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect bulk identity operations (user deletion, disable, password reset, session revocation) — multiple actions in a short window from a single initiator is anomalous
// Note: Tune threshold and window based on baseline; legitimate bulk ops (e.g. offboarding scripts) may need exclusion by known service account UPN

let LookbackWindow = 10m;
let BulkThreshold = 5;
let DestructiveOps = dynamic([
    "Delete user",
    "Disable account",
    "Reset user password",
    "Revoke sessions"
]);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in~ (DestructiveOps)
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend IPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| summarize
    OperationCount = count(),
    Operations = make_set(OperationName),
    AffectedObjects = make_set(tostring(parse_json(TargetResources)[0].userPrincipalName)),
    EarliestOp = min(TimeGenerated),
    LatestOp = max(TimeGenerated)
    by InitiatedByUser, IPAddress, bin(TimeGenerated, LookbackWindow)
| where OperationCount >= BulkThreshold
| project EarliestOp, LatestOp, InitiatedByUser, IPAddress, OperationCount, Operations, AffectedObjects
| sort by OperationCount desc
```

### Validated Columns
- [ ] `OperationName` — confirm exact strings in AuditLogs against tenant: "Delete conditional access policy", "Delete user", "Disable account", "Reset user password", "Revoke sessions"
- [ ] `parse_json(InitiatedBy).user.userPrincipalName` — confirm field path; may need `.upn` in some tenants
- [ ] `parse_json(InitiatedBy).user.ipAddress` — confirm availability; can be null for service-initiated actions
- [ ] `parse_json(TargetResources)[0].displayName` — confirm for CA policy name extraction
- [ ] `parse_json(TargetResources)[0].userPrincipalName` — confirm for user object targets
- [ ] Consent scope extraction via `ModifiedProperties` — validate against a live consent event in the tenant; property names may differ

---

## Hardening Actions

- [ ] **Require re-authentication and PIM activation for Graph API consent grants** — ensure admin consent for high-privilege scopes requires MFA step-up or PIM activation, not just an existing session
- [ ] **Restrict Graph Explorer access via Conditional Access** — block or require compliant device for `developer.microsoft.com` if not required for admin workflows; Graph Explorer is a browser-based tool any GA session can access
- [ ] **Enable Privileged Identity Management (PIM) for Global Administrator and all roles with `Policy.ReadWrite.ConditionalAccess`** — just-in-time activation limits the window a browser-captured token can operate in
- [ ] **Audit current scope of admin-GKoerhui, admin-CJones2, and admin-mrieger** — these accounts carry known risk and represent exactly the privileged session profile this technique requires
- [ ] **Alert on CA policy deletion as a P1 signal** — zero-tolerance: there is no legitimate reason to delete CA policies outside a controlled change window; wire the second KQL stub to a Sentinel Analytics Rule immediately
- [ ] **Review Entra Diagnostic Settings** — confirm AuditLogs are flowing to Sentinel with sufficient retention; this attack is only detectable post-hoc from that table

---

## Related Notes

- [[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]]
- [[PLAYBOOK-Graph-API-Broad-Permission-Grant]]

---

## Tags

> Domains: #identity #cloud
> No specific threat actor — technique demonstrated in research context; Storm-0501 and Stryker attacker TTPs cited as real-world parallels

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-28 | Created — source: Netwrix blog, Huy Kha, May 21 2026 |
