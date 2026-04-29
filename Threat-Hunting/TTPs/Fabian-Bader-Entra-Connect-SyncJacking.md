---
date:
detection_candidate: true
---

# Intel — Fabian Bader: Entra Connect SyncJacking — GA Security Hardening

**Source:** https://cloudbrothers.info/
**Tweet:** https://x.com/fabian_bader/status/2047592114872033624
**Date:** 2026-04-24
**MITRE ATT&CK:** T1078.004, T1484.002 | **Tactic:** Valid Accounts (Cloud), Domain Policy Modification
**Detection Candidate:** Yes

---

## Summary
Fabian Bader flagged the GA release of Microsoft Entra Connect security hardening specifically targeting SyncJacking — a technique where an attacker with access to the Entra Connect sync account can escalate privileges to Global Admin in the cloud tenant by manipulating synchronized objects or permissions. Microsoft has now GA'd mitigations but orgs need to explicitly apply the hardening. UFA runs a hybrid Entra Connect environment making this directly applicable.

---

## Relevance to UFA
UFA's environment is Active Directory joined and Intune managed with Entra ID — a hybrid setup that uses Entra Connect sync. SyncJacking represents a direct path from on-prem compromise to full cloud tenant takeover. If an attacker compromises the AD Connect sync service account, they can potentially gain Global Admin rights in your M365/Entra tenant. This is a high-priority hardening item for a hybrid environment.

---

## Detection Notes
**1. Entra Connect sync account anomalies**
- `AuditLogs` — operations by the `MSOL_` or `AAD_` sync service account outside expected sync windows
- Any role assignments performed by the sync account

**2. Unexpected Global Admin grants**
- `AuditLogs` — `Add member to role` where `TargetResources` contains `Global Administrator`
- Alert on any new Global Admin additions, especially outside change windows

**3. On-prem sync server activity**
- Unusual process execution on the Entra Connect server
- Lateral movement targeting the sync server from other hosts

```kql
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources, RoleName
| order by TimeGenerated desc
```

---

## Actions
- [ ] Apply Entra Connect SyncJacking hardening — review Microsoft's GA guidance
- [ ] Audit current permissions of Entra Connect sync service account
- [ ] Verify sync server is hardened and monitored via Sentinel
- [ ] Build Sentinel analytics rule for unexpected Global Admin grants

---

## Tags
#intel #entra #entra-connect #syncjacking #hybrid-identity #t1078 #t1484 #fabian-bader #detection-candidate #action-required 

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-24 | Created |
