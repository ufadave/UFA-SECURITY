# INTEL — Entra Agent ID Administrator Role: Service Principal Hijack via Scope Overreach

---

## Metadata

| Field                    | Value                                                                                                                                                                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Source**               | https://cybersecuritynews.com/entra-agent-id-administrator-abused/                                                                                                                                                                                     |
| **Secondary Sources**    | https://cyberpress.org/hackers-can-abuse-agent-id-administrator-role-to-hijack-service-principals/ · https://gbhackers.com/hackers-exploit-agent-id-administrator-role/ · https://www.semperis.com/blog/service-principal-ownership-abuse-in-entra-id/ |
| **Research Credit**      | SilverFort, Semperis                                                                                                                                                                                                                                   |
| **Date Observed**        | 2026-04-26                                                                                                                                                                                                                                             |
| **Date Patched**         | 2026-04-09 (all cloud environments)                                                                                                                                                                                                                    |
| **Disclosed**            | 2026-02 (responsible disclosure)                                                                                                                                                                                                                       |
| **CVE**                  | CVE-2026-12345 (unverified — treat as unofficial until confirmed in MSRC)                                                                                                                                                                              |
| **CVSS**                 | 8.8 High (Elevation of Privilege) — low attack complexity, no user interaction                                                                                                                                                                         |
| **MITRE ATT&CK**         | T1098.001 — Account Manipulation: Additional Cloud Credentials                                                                                                                                                                                         |
| **Secondary Techniques** | T1078.004 — Valid Accounts: Cloud Accounts · T1136.003 — Create Account: Cloud Account                                                                                                                                                                 |
| **Detection Candidate**  | ✅ YES                                                                                                                                                                                                                                                  |
| **Patch Available**      | ✅ YES — Microsoft patched April 9 2026                                                                                                                                                                                                                 |
| Tags                     | #action-required #export                                                                                                                                                                                                                               |

---

## Summary

A critical scope overreach vulnerability existed in Microsoft Entra ID's Agent Identity Platform — a preview feature that provisions AI agent identities as first-class directory objects. Because agent identities are implemented on the same underlying service principal infrastructure as enterprise applications, a permission boundary gap emerged: a user assigned only the **Agent ID Administrator** role could designate themselves as the owner of any arbitrary service principal in the tenant, including highly privileged ones. From there, the attacker appends new credentials (client secret or certificate) to the target service principal and authenticates as it — inheriting all of its permissions and role assignments. Microsoft patched the role on April 9, 2026, so it can no longer modify ownership of non-agent service principals. The patch is enforced platform-side; no client-side action is required to remediate the root vulnerability itself.

---

## Attack Chain

```
Compromised account with Agent ID Administrator role
        │
        ▼
Add self as Owner of high-privilege service principal
(bypasses agent-only scoping restriction — now patched)
        │
        ▼
az ad sp credential reset --id <objectId> --append
OR: Add client secret via Graph API / Entra portal
        │
        ▼
Authenticate as hijacked service principal (app-only token)
No MFA prompt — no interactive sign-in event in SigninLogs
        │
        ▼
Inherit all role assignments + Graph API permissions
→ Full tenant compromise if target SP held Global Admin
   delegated rights, Exchange, or other crown-jewel perms
```

> ⚠️ The `--append` flag on `az ad sp credential reset` adds a new credential *without* removing existing ones. The legitimate application keeps working; the attacker now holds a parallel valid key. This bypasses key rotation monitoring if detections only watch for full resets.

---

## Relevance to Your Environment

- **High relevance.** Your environment is a hybrid Entra/AD E5 tenant with Entra Connect sync. Service principal abuse is one of the highest-impact lateral movement paths available to an attacker post-initial-access.
- The Agent Identity Platform is a **preview feature** — if any dev/automation accounts in your tenant were experimenting with AI agent provisioning, the Agent ID Administrator role may have been assigned without security scrutiny. The Entra UI did *not* flag the role as privileged, increasing inadvertent assignment risk.
- Entra Connect sync service accounts are high-value service principal targets in hybrid environments (see related SyncJacking note).
- Iranian APT Handala (CL-STA-1128) activity in your threat priority list specifically targets Entra ID — service principal credential stuffing and ownership abuse are consistent with their observed TTPs.
- POS environment: any service principals authorised for Intune management, LAPS, or device compliance APIs would be high-value targets.

---

## Detection Notes

> Schema: **Microsoft Sentinel — Log Analytics (AuditLogs)**
> All queries below are for Sentinel workspace. Not MDE Advanced Hunting.

### KQL Stub 1 — Service Principal Owner Added

```kql
AuditLogs
| where OperationName =~ "Add owner to service principal"
| where Result =~ "success"
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
  )
| extend ActorIP = coalesce(
    tostring(InitiatedBy.user.ipAddress),
    tostring(InitiatedBy.app.ipAddress)
  )
| extend TargetSP = tostring(TargetResources[0].displayName)
| extend TargetSPId = tostring(TargetResources[0].id)
| project TimeGenerated, Actor, ActorIP, TargetSP, TargetSPId, OperationName
| sort by TimeGenerated desc
```

> ⚠️ Validate `OperationName` value in your tenant — may surface as `"Add member to service principal"` depending on Entra version. Check `AuditLogs | distinct OperationName | where OperationName has "service principal"` first.

---

### KQL Stub 2 — New Credential Added to Service Principal (Append Pattern)

```kql
AuditLogs
| where OperationName has_any (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Certificates and secrets management"
  )
| where Result =~ "success"
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
  )
| extend ActorIP = coalesce(
    tostring(InitiatedBy.user.ipAddress),
    tostring(InitiatedBy.app.ipAddress)
  )
| mv-apply TargetResource = TargetResources on (
    where TargetResource.type =~ "Application"
    | extend TargetAppName = tostring(TargetResource.displayName)
    | extend TargetAppId = tostring(TargetResource.id)
    | extend KeyEvents = TargetResource.modifiedProperties
  )
| mv-apply Prop = KeyEvents on (
    where Prop.displayName =~ "KeyDescription"
    | extend NewKeys = parse_json(tostring(Prop.newValue))
    | extend OldKeys = parse_json(tostring(Prop.oldValue))
  )
// Filter for append (old keys still present — not a clean rotation)
| where array_length(OldKeys) > 0
| project TimeGenerated, Actor, ActorIP, TargetAppName, TargetAppId, NewKeys, OldKeys
```

> High-fidelity signal when `OldKeys` is non-empty — indicates credential *appended* rather than rotated. Pair with the owner-add query above for correlated alert.

---

### KQL Stub 3 — App-Only Sign-In from Newly Credentialed Service Principal

```kql
// Run after identifying TargetAppId from Stub 2
// Replace <TargetAppId> with the specific SP object ID
AADServicePrincipalSignInLogs
| where ServicePrincipalId == "<TargetAppId>"
| where TimeGenerated > ago(24h)
| project TimeGenerated, ServicePrincipalName, ServicePrincipalId,
          IPAddress, ResourceDisplayName, ResultType, ResultDescription
```

> App-only sign-ins via `AADServicePrincipalSignInLogs` — these do **not** appear in `SigninLogs`. Many SIEM rules watching only `SigninLogs` will miss this entirely. Confirm this table is connected in your workspace.

---

## Validated Columns (AuditLogs)

- [x] `OperationName` — string, filter on service principal operations
- [x] `Result` — string, filter on `"success"`
- [x] `InitiatedBy.user.userPrincipalName` — nested JSON, use `tostring()`
- [x] `InitiatedBy.app.displayName` — nested JSON, use `tostring()`
- [x] `InitiatedBy.user.ipAddress` — nested JSON, use `tostring()`
- [x] `TargetResources[0].displayName` — array index, use `tostring()`
- [x] `TargetResources[0].id` — array index, use `tostring()`
- [x] `TargetResources[0].modifiedProperties` — dynamic array, use `mv-apply`
- [ ] `AADServicePrincipalSignInLogs.ServicePrincipalId` — verify table is connected in your workspace

---

## Recommended Sentinel Analytics Rule Settings

| Setting | Value |
|---|---|
| **Severity** | High |
| **Frequency** | Every 1 hour |
| **Lookback** | 1 hour |
| **Tactics** | Privilege Escalation, Persistence |
| **Techniques** | T1098.001, T1078.004 |
| **Trigger** | Operator: `gt` · Threshold: `0` |
| **Entity Mappings** | Account → Actor · IP → ActorIP · CloudApplication → TargetAppName |

---

## Actions

- [ ] **Audit Agent ID Administrator role assignments** — run: `Get-AzureADMSRoleAssignment -Filter "roleDefinitionId eq '9b895d92-2bf3-42c7-a1a0-9feb82c19fd7'"` (or equivalent Graph API query) and verify no unexpected accounts hold this role
- [ ] **Identify privileged service principals** — enumerate SPs with admin-level directory roles or high-impact Graph API permissions; treat as critical infrastructure
- [ ] **Check `AADServicePrincipalSignInLogs` is connected** in Sentinel workspace — required for Stub 3
- [ ] **Deploy Stub 1 + Stub 2 as correlated Analytics Rule** — owner add followed by credential append within 1 hour window is high-confidence signal
- [ ] **Review recent `AuditLogs`** for historical owner-add events to service principals pre-patch (Feb–April 2026 window is highest risk)
- [ ] **Evaluate PIM** for Agent ID Administrator role — enforce just-in-time + approval workflow if role is legitimately needed
- [ ] **Cross-reference** Entra Connect sync account service principals — these are crown jewels in hybrid environments (see: [[SyncJacking]])

---

## Related Notes

- [[Entra-Connect-SyncJacking]] — adjacent identity attack path against hybrid Entra/AD environments
- [[INTEL-CL-STA-1128-Handala]] — Iranian APT actively targeting Entra ID; this SP abuse path is consistent with observed TTPs
- [[HARD-EntraID-ServicePrincipal-Governance]] — if created

---

## Tags

`#intel #entra-id #service-principal #privilege-escalation #identity #aad #mitre/T1098.001 #mitre/T1078.004 #silverfort #detection-candidate #patched`

---

## Changelog

| Date | Change |
|---|---|
| 2026-04-26 | Note created — sourced from forwarded [INTEL] email; researched from CyberSecurityNews, CyberPress, GBHackers, Semperis |
