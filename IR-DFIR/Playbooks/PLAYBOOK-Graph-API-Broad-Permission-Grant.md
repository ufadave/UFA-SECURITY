---
date: 2026-05-22
title: Graph API Broad Permission Grant to Service Principal
type: playbook
rule: "[[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]]"
mitre: "T1528, T1098.003"
tactic: "Persistence, Privilege Escalation"
severity_range: "High / Critical"
status: "done"
tags:
  - "#ir"
  - "#playbook"
  - "#cloud"
  - "#identity"
  - "#status/done"
---

# Playbook — Graph API Broad Permission Grant to Service Principal

**Rule:** [[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]]
**MITRE:** T1528 Steal Application Access Token · T1098.003 Account Manipulation: Additional Cloud Roles
**Severity:** High (Critical tier grants) / High (High tier grants)
**SLA:** Critical tier → triage within 1h · High tier → triage within 4h

---

## Overview

This playbook covers alerts fired by the Graph API broad permission grant detection rule.
The rule fires when an admin consent or delegated permission grant includes Microsoft Graph
scopes associated with data exfiltration, privilege escalation, or security control manipulation.

**Critical tier** — role management, CA policy, MFA methods, app/service principal write,
federated identity, security signal suppression. Any single Critical grant is high-confidence
malicious or severely misconfigured. Treat as confirmed incident until proven otherwise.

**High tier** — broad mail, file, directory, and Teams read/write. Legitimate in specific
managed contexts (provisioning apps, HR integrations) but always warrants investigation.

---

## Pre-Triage Checklist

Before opening the alert, collect these fields from the Sentinel alert entity:

| Field | Value |
|-------|-------|
| `PermissionTier` | Critical / High |
| `OperationName` | Consent to application / Add delegated permission grant |
| `TargetAppName` | |
| `TargetAppObjectId` | |
| `InitiatorUPN` | |
| `InitiatorApp` | |
| `InitiatorIP` | |
| `CorrelationId` | |
| `TimeGenerated` | |

---

## Phase 1 — Immediate Triage (all alerts)

### Step 1.1 — Determine permission tier

- **Critical tier** → proceed immediately to Phase 2 (Containment Assessment). Do not wait for context.
- **High tier** → continue through Phase 1 fully before deciding on containment.

### Step 1.2 — Identify the initiator

Run in Sentinel (Log Analytics):

```kql
// Who initiated this consent — recent sign-in context
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "<InitiatorUPN>"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ResultType, RiskLevelDuringSignIn, AuthenticationRequirement
| order by TimeGenerated desc
```

Assess:
- [ ] Is `InitiatorUPN` a known admin? Check against your admin roster.
- [ ] Is `InitiatorIP` a known corporate IP or VPN exit? Check against known IP list.
- [ ] Any concurrent risky sign-ins for this user (`RiskLevelDuringSignIn != "none"`)?
- [ ] Is `InitiatorApp` a known provisioning service (e.g. Entra ID, Microsoft Azure Portal)? Or unknown?

> **If InitiatorUPN is empty** — the grant was made by an app/service principal, not a user.
> Treat as elevated risk. Service-initiated grants are not typical for legitimate provisioning
> in most tenants and warrant immediate escalation to Phase 2.

### Step 1.3 — Identify the target application

Run in Sentinel:

```kql
// What is this app — all audit events for this object in the last 30 days
AuditLogs
| where TimeGenerated > ago(30d)
| where TargetResources has "<TargetAppObjectId>"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

Assess:
- [ ] Is `TargetAppName` a recognised, sanctioned application? Check against known app inventory.
- [ ] When was this app created? First seen today or recently → elevated risk.
- [ ] Has this app had other permissions granted recently in the same window?
- [ ] Does the app have a verified publisher in Entra ID?

Also check in Entra ID portal: **Enterprise Applications → {TargetAppName} → Permissions**

### Step 1.4 — Check for prior consent events on this app

```kql
// Has this app had permissions granted before?
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where TargetResources has "<TargetAppObjectId>"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

- [ ] First-time consent on this app → higher risk
- [ ] Repeat consent in short window → may indicate permission escalation attempt

### Step 1.5 — Cross-reference with known FP patterns

- [ ] Is this the ChatGPT enterprise app? (ref: [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]]) — if so, review approved scope and close if within sanctioned limits
- [ ] Does `CorrelationId` match a known provisioning workflow? — if yes, document and suppress per the tuning guidance in the rule note
- [ ] Was a change ticket or CAB approval raised for this consent?

---

## Phase 2 — Containment Assessment

### Step 2.1 — Determine if the app has been used since consent

```kql
// Has this app authenticated and used Graph API since consent?
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "<TargetAppObjectId>"
| where OperationName !in ("Consent to application", "Add delegated permission grant")
| project TimeGenerated, OperationName, TargetResources, InitiatedBy
| order by TimeGenerated desc
```

Also check CloudAppEvents for app-only activity:

```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application == "<TargetAppName>"
| project TimeGenerated, ActionType, AccountDisplayName, AccountType, IPAddress, ObjectName, ObjectType
| order by TimeGenerated desc
```

- [ ] Has the app made API calls since consent? → active exploitation possible
- [ ] Any bulk mailbox access, file enumeration, or directory reads? → treat as active exfiltration

### Step 2.2 — Critical tier decision gate

**If PermissionTier = Critical:** containment is presumed required unless you can affirmatively confirm the grant was legitimate and authorised. The bar for "legitimate" is:
- Known initiator, from a known IP, with a change ticket or explicit verbal confirmation from the initiating admin
- App is a recognised, publisher-verified, previously sanctioned application

**If you cannot confirm all three → escalate and contain.**

### Step 2.3 — Containment options

Select based on confidence and impact:

| Action | When to Use | How |
|--------|-------------|-----|
| Revoke app consent | Confirmed malicious or unrecognised app | Entra ID → Enterprise Applications → {App} → Permissions → Revoke admin consent |
| Disable service principal | App is actively making API calls | Entra ID → Enterprise Applications → {App} → Properties → Enabled = No |
| Revoke app tokens | App has active sessions that need immediate termination | Entra ID → Enterprise Applications → {App} → Revoke tokens (or via Graph API: `POST /servicePrincipals/{id}/revokeSignInSessions`) |
| Disable initiating admin account | Initiator account is suspected compromised | Entra ID → Users → {User} → Block sign-in |
| Force MFA re-registration | Initiator account compromise suspected | Entra ID → Users → {User} → Authentication methods → Revoke sessions and require re-registration |

> **Do not delete the app registration or service principal** until forensic review is complete —
> deletion destroys audit evidence.

---

## Phase 3 — Investigation

### Step 3.1 — Full permission scope enumeration

Extract the exact permissions granted from `TargetJson` in the alert. Cross-reference against:
- What permissions were requested at app registration vs what was actually granted
- Whether the scope includes write permissions not visible in the Sentinel alert summary

### Step 3.2 — Initiator account investigation (if user-initiated)

```kql
// Full sign-in history for initiating user — 14 days
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ "<InitiatorUPN>"
| project TimeGenerated, AppDisplayName, IPAddress, Location, ResultType, RiskLevelDuringSignIn, ConditionalAccessStatus, AuthenticationRequirement, DeviceDetail
| order by TimeGenerated desc
```

```kql
// Admin actions by this user in the same window
AuditLogs
| where TimeGenerated > ago(14d)
| where InitiatedBy has "<InitiatorUPN>"
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc
```

- [ ] Any impossible travel or unfamiliar location sign-ins in the same window?
- [ ] Any other unusual admin actions (role assignments, policy changes, new app registrations)?
- [ ] Did the user receive a phishing email around the time of the consent? Check MDO.

### Step 3.3 — Check for associated new app registrations

```kql
// New app registrations near the time of the consent grant
AuditLogs
| where TimeGenerated between (ago(2d) .. now())
| where OperationName == "Add application"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

- [ ] Was a new app registered immediately before the consent grant? → classic attacker pattern

### Step 3.4 — Data access assessment (if app was active)

If CloudAppEvents confirmed app-only API activity in Step 2.1:

```kql
// Bulk mailbox access via app-only token
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application == "<TargetAppName>"
| where AccountType == "Application"
| where ActionType in ("MailItemsAccessed", "FolderBind", "SendAs")
| summarize ActionCount = count(), DistinctMailboxes = dcount(AccountDisplayName) by ActionType, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

```kql
// File access via app-only token
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application == "<TargetAppName>"
| where AccountType == "Application"
| where ObjectType in ("File", "Folder", "Site")
| summarize FileCount = count(), DistinctSites = dcount(ObjectName) by ActionType, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

- [ ] Mailboxes accessed — how many? Whose?
- [ ] Files accessed — which SharePoint sites? Any sensitive locations?
- [ ] Any data exfiltrated externally? (Check MCAS anomaly detection)

---

## Phase 4 — Verdict & Classification

| Verdict | Criteria |
|---------|----------|
| **True Positive — Malicious** | Unrecognised app, unknown or compromised initiator, active data access, no change ticket |
| **True Positive — Misconfiguration** | Recognised app, known initiator, legitimate use case, but over-provisioned scope |
| **False Positive — Sanctioned** | Known app, known initiator, change ticket or prior approval, scope within business justification |
| **Undetermined** | Insufficient evidence — escalate and retain containment |

### Severity assignment

| Condition | Severity |
|-----------|----------|
| Critical tier permission + active data access | Critical |
| Critical tier permission + no data access yet | High |
| High tier permission + active bulk data access | High |
| High tier permission + known initiator + no data access | Medium |
| Known FP pattern (provisioning, sanctioned app) | Close — document suppression |

---

## Phase 5 — Response Actions by Verdict

### True Positive — Malicious

- [ ] Revoke app consent and disable service principal (Phase 2.3)
- [ ] Revoke initiator account sessions; force MFA re-registration if account compromised
- [ ] Notify affected mailbox/file owners if data access confirmed
- [ ] Open IR case: `IR-GraphAPI-PermissionAbuse-{date}`
- [ ] Assess data exfiltration scope — notify privacy officer if personal data accessed (PIPEDA)
- [ ] Document IOCs: app object ID, initiator IP, CorrelationId
- [ ] Consider Conditional Access emergency policy to block app if revocation insufficient
- [ ] Review for lateral movement: check if the same initiator account was used for other admin actions

### True Positive — Misconfiguration

- [ ] Revoke excess permissions; re-consent with minimum required scope
- [ ] Raise remediation ticket with app owner
- [ ] Document in [[HARD-Entra-App-Registration-Permissions-Audit]]
- [ ] Add CorrelationId suppression for this provisioning flow if recurrent
- [ ] Close finding with misconfiguration verdict

### False Positive — Sanctioned

- [ ] Confirm change ticket or admin approval exists
- [ ] Document in suppression log
- [ ] Add CorrelationId or InitiatorApp-scoped suppression to rule if this workflow will recur
- [ ] Close alert

---

## Phase 6 — Post-Incident

### If True Positive — Malicious:

- [ ] Add app object ID and initiator IP to Sentinel watchlist
- [ ] Review whether the consented permissions enabled any persistence mechanisms not yet revoked (new roles, additional app registrations, CA policy changes)
- [ ] Run companion rules manually for coverage:
  - [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]]
  - [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]]
- [ ] Review Entra ID app consent policy — consider restricting user consent to verified publishers only if not already enforced
- [ ] Update [[ACTOR-Handala]] or relevant actor note if TTPs match known campaign

### All verdicts:

- [ ] Update rule note changelog if tuning was applied
- [ ] Update this playbook if a new FP pattern was identified

---

## Escalation

| Condition | Action |
|-----------|--------|
| Critical tier grant + active data access confirmed | Escalate to management immediately; assess PIPEDA notification requirement |
| Initiator account confirmed compromised | Incident commander decision on scope of account lockdown |
| Evidence of lateral movement beyond the app consent | Broaden IR scope — do not treat as isolated app consent event |
| Ammonium nitrate or OT-adjacent data stores accessed | Escalate to OT security contact; assess CFIA/Explosives Act notification requirement |

---

## Related Notes

- [[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]]
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]]
- [[INTEL-M365Pwned-OAuth-App-Token-Exfiltration-Toolkit]]
- [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]]
- [[KQL-CloudAppEvents-AppOnly-BulkMailboxAccess-Graph]]
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]]
- [[HARD-Entra-App-Registration-Permissions-Audit]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-22 | Created |
| 2026-05-22 | UPN comparisons changed from == to =~ in Step 1.2 and Step 3.2 SigninLogs queries — case-sensitive match caused 0 rows when UPN casing differed between AuditLogs and SigninLogs |
