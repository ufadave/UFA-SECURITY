---
title: "Entra Connect SyncJacking — GA Security Hardening Available"
date: 2026-04-24
source: https://cloudbrothers.info/
author: "Fabian Bader"
mitre:
  - T1078.004
  - T1484.002
tactic:
  - "Valid Accounts: Cloud Accounts"
  - "Domain Policy Modification"
detection_candidate: true
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#intel"
  - "#status/active"
  - "#identity"
  - "#cloud"
  - "#action-required"
---

# INTEL — Entra Connect SyncJacking: GA Security Hardening Available

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://cloudbrothers.info/ |
| **Author** | Fabian Bader |
| **Tweet** | https://x.com/fabian_bader/status/2047592114872033624 |
| **Date Observed** | 2026-04-24 |
| **Patch Status** | ✅ GA hardening available — requires explicit opt-in |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1078.004 | Valid Accounts: Cloud Accounts |
| T1484.002 | Domain Policy Modification: Domain Trust Modification |

---

## Summary

Fabian Bader flagged the GA release of Microsoft Entra Connect security hardening specifically targeting SyncJacking — a technique where an attacker with access to the Entra Connect sync account can escalate privileges to Global Admin in the cloud tenant by manipulating synchronised objects or permissions. Microsoft has now GA'd mitigations but organisations need to explicitly apply the hardening. The patch does not auto-apply; it requires deliberate configuration action.

---

## Relevance to Environment

**High — action required.** The environment runs a hybrid Entra Connect configuration. SyncJacking represents a direct path from on-prem compromise to full cloud tenant takeover. If an attacker compromises the AD Connect sync service account, they can potentially gain Global Admin rights in the M365/Entra tenant. This is a high-priority hardening item.

---

## Detection Notes

### KQL Stubs

**1. Entra Connect sync account anomalies**

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect operations by Entra Connect sync accounts outside expected sync activity

AuditLogs
| where InitiatedBy.app.displayName has_any ("MSOL_", "AAD_", "Entra Connect")
    or InitiatedBy.user.userPrincipalName has_any ("MSOL_", "AAD_")
| where OperationName !in (
    "Synchronize directory",
    "Export",
    "Import"
)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

**2. Unexpected Global Admin grants**

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Alert on any new Global Administrator role additions

AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources, RoleName
| order by TimeGenerated desc
```

### Validated Columns

- [ ] `AuditLogs.InitiatedBy.app.displayName` — confirm sync account naming convention in tenant
- [ ] `AuditLogs.OperationName` — confirm expected sync operation names to refine exclusion list
- [ ] `TargetResources[0].modifiedProperties[1].newValue` — confirm index for RoleName in your tenant

---

## Hardening Actions

- [ ] Apply Entra Connect SyncJacking GA hardening — review Microsoft's GA guidance at cloudbrothers.info
- [ ] Audit current permissions of Entra Connect sync service account
- [ ] Verify sync server is hardened and monitored
- [ ] Build Sentinel analytics rule for unexpected Global Admin grants

---

## Related Notes

- [[INTEL-Stryker-Breach-Handala-Intune-Wipe]] — same threat actor cluster, Intune/Entra abuse
- [[INTEL-EntraAgentID-ServicePrincipalHijack-2026-04-26]] — related service principal abuse path

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-24 | Created |
| 2026-05-28 | Renamed from Fabian-Bader-Entra-Connect-SyncJacking.md — added YAML frontmatter, standardised structure |
