---
title: "Registered Isn't Compliant — The Conditional Access Gap Attackers Use After Token Theft"
date: 2026-04-28
source: https://ridgelinecyber.com/blog/ca-registered-device-bypass-investigation/
tags:
  - "#intel"
  - "#identity"
  - "#cloud"
  - "#status/active"
  - "#action-required"
---

# RESEARCH — Registered Isn't Compliant: The CA Gap Attackers Exploit After Token Theft

## Source
- **URL:** https://ridgelinecyber.com/blog/ca-registered-device-bypass-investigation/
- **Author:** Ridgeline Cyber Defence
- **Date received:** 2026-04-26
- **Original email subject:** `[RESEARCH] Registered Isn't Compliant: The Conditional Access Gap Attackers Use After Token Theft`

> ⚠️ **Note:** Source URL was not publicly indexed at time of triage — content below is synthesised from Ridgeline's published training materials and closely related research. Manual review of the original article recommended.

## What It Is
A technical investigation into a well-known but frequently misconfigured Conditional Access gap: the distinction between a **registered** device and a **compliant** device. CA policies scoped to "registered devices" provide far weaker guarantees than policies requiring **compliant** devices, because device registration is a low-bar trust signal that can be abused by attackers after token theft. The attack chain is: AiTM phishing or token theft → attacker has valid access token → attacker registers a new (attacker-controlled) device in Entra ID to satisfy "registered device" CA policy → downloads data freely. The fix is ensuring CA policies require `Require device to be marked as compliant` rather than merely `Require Hybrid Azure AD joined` or allowing registered-but-unmanaged devices.

## Technical Detail (from Ridgeline + M42 Labs / supporting research)
- Entra ID evaluates two separate trust signals independently: (1) Device Platform condition reads from registered device OR user-agent string; (2) Device Filter checks against registered device objects
- An unregistered device has all device properties = null — if no policy handles null/unknown device state, no policy applies
- Attacker steps post-token-theft: spoof a device user agent → register a device in an OS not covered by existing CA policies → Intune enrolment check-in completes → device marked compliant → full access granted
- This works in tenants that require "compliant device" but **only for specific platforms** (e.g., Windows and macOS) without a baseline policy covering Linux or unrecognised platforms
- A baseline MFA policy with minimal exclusions is the single most impactful mitigation — device filtering cannot replace it

## Relevance to Environment
- **Directly relevant** — this is flagged as an active priority: "Registered ≠ Compliant. Audit CA policies."
- Your environment is hybrid (Entra + AD) with POS terminals and OT-adjacent Windows systems — some device types may not be in a compliant scope
- Block device code flow is also noted as a gap — device code flow bypasses device-state CA conditions entirely
- OT/SCADA Windows systems at the plant should be explicitly scoped or excluded with compensating controls
- Audit current CA policies using the **What If** tool: test token theft scenario on registered-but-non-compliant device

## Detection Notes

### KQL — Device Registration Events (Sentinel AuditLogs)
```kql
// Schema: Sentinel — AuditLogs
AuditLogs
| where OperationName in ("Register device", "Add registered owners to device")
| where TimeGenerated > ago(30d)
| extend RegisteredBy = tostring(InitiatedBy.user.userPrincipalName)
| extend DeviceOS = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, RegisteredBy, DeviceOS, Result
| order by TimeGenerated desc
```

### KQL — CA Policy Bypass: Registered Device Accessing Sensitive Apps (Sentinel SigninLogs)
```kql
// Schema: Sentinel — SigninLogs
SigninLogs
| where TimeGenerated > ago(7d)
| where DeviceDetail.trustType == "Azure AD registered"   // registered but NOT compliant
    and DeviceDetail.isCompliant == false
| where AppDisplayName in ("SharePoint Online", "Exchange Online", "Microsoft Teams")
| extend UserPrincipalName, IPAddress, Location = tostring(LocationDetails)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, 
          DeviceDetail, ConditionalAccessStatus
| where ConditionalAccessStatus != "failure"   // access was granted despite non-compliant device
```

### Schema Validation
- [ ] `DeviceDetail.trustType` — SigninLogs — confirm field path in your workspace
- [ ] `DeviceDetail.isCompliant` — SigninLogs — boolean, confirm availability
- [ ] `ConditionalAccessStatus` — SigninLogs ✓
- [ ] `tostring(LocationDetails)` — confirm exact field name, may be `LocationDetails.city` etc.

## Hardening Actions
- [ ] **Immediate:** Audit all CA policies — identify any that require "registered" rather than "compliant"
- [ ] **Immediate:** Create a baseline "catch-all" MFA policy scoped to All Users, All Apps, with minimal exclusions
- [ ] Block device code flow via CA: Authentication Flows → Filter for Device Code flow → Block
- [ ] Ensure all platforms (including Linux) are covered by at least one policy
- [ ] Enable Token Protection (CA → Session Controls → Require token protection) — binds tokens to issuing device
- [ ] Use the Entra CA "What If" tool — test: registered-but-non-compliant device hitting SharePoint

## Related Notes
- [[Projects/M365-Hardening]] — active CA gap audit
- [[INTEL-Entra-Agent-ID-Admin-Service-Principal-Hijack]] — same threat actor path (identity abuse)

## Changelog
| Date | Change |
|------|--------|
| 2026-04-28 | Created from inbox triage — note URL not publicly indexed, content synthesised; manual review recommended |
