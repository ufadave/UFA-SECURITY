---
date: 2026-05-28
title: Entra AgentID ServicePrincipal Hijack Identity
table: AuditLogs
schema: Sentinel / Log Analytics
mitre:
  - T1078.004
  - T1098
  - T1136.003
  - T1550.001
tactic: "Persistence, Privilege Escalation"
technique: "T1078.004 — Valid Cloud Accounts; T1098 — Account Manipulation; T1136.003 — Create Cloud Account"
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#identity"
  - "#cloud"
---

# KQL — Entra AgentID ServicePrincipal Hijack Identity

**Table:** AuditLogs | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1078.004, T1098, T1136.003 | **Tactic:** Persistence, Privilege Escalation
**Created:** 2026-05-28 | **Status:** `Draft`

---

## Purpose

Three detection stubs covering the Sentinel-side signals for Entra Agent ID Administrator role abuse and service principal hijacking (CVE-2026-12345, patched April 9 2026). Monitors for:

- **Stub 1:** SP ownership additions — unexpected principal adding themselves as owner of an existing service principal
- **Stub 2:** Credential additions to service principals — new client secret or certificate appended to an existing app registration
- **Stub 3:** Agent ID Administrator role assignments — this role should be assigned extremely rarely; any new assignment warrants review

> These stubs target the post-exploitation pattern: an attacker who has gained initial access adds persistence by injecting credentials into or taking ownership of a high-privilege service principal. The patch removes the role's ability to modify service principals outside its own scope, but audit coverage for these operations remains operationally valuable regardless.

---

## Query

```kql
// Stub 1 — Unexpected service principal ownership addition
// An actor adding themselves as SP owner gains equivalent privileges to the SP
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
// Stub 2 — New credentials added to service principals
// Client secret or certificate injection — primary persistence mechanism
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
// Stub 3 — Agent ID Administrator role assignment
// Should be near-zero in production; any new assignment warrants immediate review
AuditLogs
| where OperationName =~ "Add member to role"
| where Result =~ "success"
| mv-expand TargetResources
| extend RoleName = tostring(TargetResources.displayName)
| where RoleName =~ "Agent ID Administrator"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project TimeGenerated, Actor, RoleName, OperationName
```

---

## Validated Columns
- [ ] `OperationName` — AuditLogs ✓ confirm exact string values against live tenant; case-insensitive match with `=~` recommended
- [ ] `InitiatedBy.user.userPrincipalName` — AuditLogs nested field — requires `parse_json(tostring(...))` pattern ✓ validated pattern
- [ ] `InitiatedBy.user.ipAddress` — AuditLogs nested field — same pattern
- [ ] `TargetResources` — AuditLogs array field — `mv-expand` required; index position may vary by operation type
- [ ] `Result` — AuditLogs ✓ confirm `"success"` vs `"Success"` — use `=~` for case-insensitive match

---

## Test Results

- [ ] Tested in environment
- [ ] Stub 1: validate `OperationName` exact string matches live AuditLogs events
- [ ] Stub 2: high baseline expected — software deployment pipelines add secrets legitimately; build an allowlist of known-good apps
- [ ] Stub 3: expect near-zero; any result is a high-priority alert
- [ ] FP rate acceptable

---

## Deployment

### Sentinel Analytics Rule
- **Rule Name:** Entra AgentID Service Principal Ownership or Credential Change
- **Frequency:** every 1h
- **Lookback:** 1h
- **Severity:** High (Stub 1 and 3); Medium (Stub 2 — after allowlist tuning)
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

> Consider deploying Stub 3 separately as Critical severity — Agent ID Administrator role assignment has no legitimate routine use case.

### MDE Custom Detection Rule
<!-- INACTIVE: AuditLogs is Sentinel / Log Analytics only -->
<!-- Deploy via Sentinel Analytics Rule -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-Entra-AgentID-ServicePrincipal-Hijack]]
- [[INTEL-Entra-Agent-ID-Admin-Service-Principal-Hijack]]
- [[INTEL-Entra-Agent-ID-Administrator-Service-Principal-Hijack]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-28 | Created — backfill companion to [[INTEL-Entra-AgentID-ServicePrincipal-Hijack]] via backfill stubs command |
