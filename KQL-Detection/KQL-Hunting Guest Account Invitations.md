---
date: 2026-05-12
title: KQL-Hunting Guest Account InvitationsUntitled
table: AuditLogs
schema: Sentinel
mitre: ""
tactic: ""
technique: ""
status: deployed
promoted_to_rule: true
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/done"
  - detection/hunting
---

# KQL — Hunt - Detect guest accounts invited by the compromised account

---

**Table:** AuditLogs| **Schema:** Sentinel (Query saved under Advanced Hunting -> Shared > Hunt)
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** 2026-05-12 | **Status:** `Deployed`

---

## Purpose
Any result here is `Confirmed TTP` until proven otherwise. Guest accounts created during this window that are not operationally justified must be disabled immediately and investigated separately — they are a persistence mechanism that survives all other remediation.
Advanced Hunting rule Created

---

## Query

```kql
// Table: AuditLogs

// Schema: Sentinel / Log Analytics

// Purpose: Detect guest accounts invited by the compromised account during access window

AuditLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-06T00:00:00Z))
| where OperationName in (
    "Invite external user",
    "Add user",
    "Redeem external user invite",
    "Add member to group"
  )
| extend InitiatedByParsed = parse_json(InitiatedBy)
| extend TargetResourcesParsed = parse_json(TargetResources)
| extend InitiatorId = tostring(InitiatedByParsed.user.id)
| extend InitiatorUPN = tostring(InitiatedByParsed.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedByParsed.app.displayName)
| extend TargetUPN = tostring(TargetResourcesParsed[0].userPrincipalName)
| extend TargetType = tostring(TargetResourcesParsed[0].type)
| where InitiatorId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
      or InitiatorUPN == "adam.mussack@barwpetroleum"

| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatorUPN,
    InitiatorId,
    InitiatorApp,
    TargetUPN,
    TargetType,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

---

## Validated Columns
- [ ] 
- [ ] 

---

## Test Results


---

## Deployment

> Default path is MDE Custom Detection. Only use Sentinel Analytics Rule for signals that do not exist in Advanced Hunting — identity (SigninLogs, AuditLogs), cloud (CloudAppEvents), and email (EmailEvents).

### MDE Custom Detection Rule
- **Rule Name:** Hunt - Detect guest accounts invited by the compromised account.
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [yes ]




---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-12 | Created |
