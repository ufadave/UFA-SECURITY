---
date:
tags:
detection_candidate: true
---

# Intel — Entra Agent ID Administrator Role: Service Principal Hijack (CVE-2026-12345)

**Source:** https://cybersecuritynews.com/entra-agent-id-administrator-abused/
**Supporting:** https://cyberpress.org/hackers-can-abuse-agent-id-administrator-role-to-hijack-service-principals/
**Date:** 2026-04-26
**MITRE ATT&CK:** T1078.004, T1098.001 | **Tactic:** Valid Accounts (Cloud), Account Manipulation
**CVE:** CVE-2026-12345 | **CVSS:** 8.8 High
**Patched:** April 9, 2026
**Detection Candidate:** Yes

---

## Summary
A critical scope overreach vulnerability in Microsoft Entra's new Agent Identity Platform allowed any user assigned the Agent ID Administrator role to take ownership of arbitrary service principals across the entire tenant — far beyond the role's intended scope of AI agent management. Once ownership was established, an attacker could add new credentials to the service principal and authenticate as that application. If the targeted service principal held elevated directory roles or high-impact Graph API permissions, this provided a direct path to full tenant compromise. Microsoft patched the issue on April 9, 2026 following responsible disclosure in February. The role was also not visually flagged as privileged in the Entra UI, increasing the risk of inadvertent assignment.

---

## Attack Chain
1. Attacker obtains a low-privilege account with Agent ID Administrator role (assigned inadvertently during DevOps/AI setup)
2. Uses role to assign themselves as owner of any high-privileged service principal
3. Adds a new client secret via `az ad sp credential reset --id <objectId> --append` — leaves existing secret intact (stealth persistence)
4. Authenticates as the service principal using app-only tokens — no MFA prompt, no interactive login alert
5. Leverages service principal's permissions — Global Admin reset, federation abuse, full tenant takeover

---

## Relevance to Your Environment
Your environment uses Entra ID in a hybrid configuration with service principals across M365, Intune, MDE, and Azure workloads. The Agent ID Administrator role may be assigned inadvertently in environments beginning to evaluate Copilot or AI agent features. Even with the patch applied, service principal ownership abuse remains a high-value attack path. This should be treated as a standing audit item.

---

## Detection Notes

**1. Audit service principals with privileged directory roles**
```kql
// Find service principals assigned to high-privilege roles
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].type == "ServicePrincipal"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator", 
    "Application Administrator", "Cloud Application Administrator",
    "Exchange Administrator", "SharePoint Administrator")
| project TimeGenerated, InitiatedBy, TargetResources, RoleName
| order by TimeGenerated desc
```

**2. New credentials added to service principals**
```kql
AuditLogs
| where OperationName in ("Add service principal credentials", 
    "Update application – Certificates and secrets management")
| project TimeGenerated, 
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    AppName = tostring(TargetResources[0].displayName),
    AdditionalDetails
| order by TimeGenerated desc
```

**3. Service principal ownership changes**
```kql
AuditLogs
| where OperationName == "Add owner to service principal"
| project TimeGenerated,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    TargetSP = tostring(TargetResources[0].displayName)
| order by TimeGenerated desc
```

**4. Agent ID Administrator role assignments**
```kql
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has "Agent ID Administrator"
| project TimeGenerated, InitiatedBy, TargetResources
```

---

## Validated Columns
- [ ] AuditLogs — OperationName values confirmed
- [ ] AuditLogs — TargetResources[0].type for ServicePrincipal
- [ ] AuditLogs — InitiatedBy.user.userPrincipalName

---

## Hardening Actions
- [ ] Audit current Agent ID Administrator role assignments in Entra ID
- [ ] Identify all service principals with privileged directory roles (PowerShell: `Get-AzureADMSRoleAssignment -Filter "roleDefinitionId eq '9b895d92-2bf3-42c7-a1a0-9feb82c19fd7'"`)
- [ ] Enable PIM (Privileged Identity Management) for Agent ID Administrator — require just-in-time approval
- [ ] Review all service principal owners — remove any unexpected owner assignments
- [ ] Build Sentinel analytics rule for credential additions to service principals
- [ ] Treat privileged service principals as critical infrastructure — monitor continuously

---

## Related Notes
- [[Threat-Hunting/TTPs/Fabian-Bader-Entra-Connect-SyncJacking|Entra Connect SyncJacking]]
- [[Threat-Hunting/TTPs/INTEL-Stryker-Breach-Handala-Intune-Wipe|Stryker/Intune Wipe]]
- [[Threat-Hunting/TTPs/Jasper-Sleet-North-Korean-IT-Worker-Infiltration|Jasper Sleet Identity Attacks]]

---

## Tags
#intel #status/active #identity #cloud #entra #service-principal #privilege-escalation #action-required

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-26 | Created |
