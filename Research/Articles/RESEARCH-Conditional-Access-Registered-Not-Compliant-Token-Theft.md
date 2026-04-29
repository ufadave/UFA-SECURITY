# Research — Registered Isn't Compliant: The Conditional Access Gap After Token Theft

**Source:** https://ridgelinecyber.com/blog/ca-registered-device-bypass-investigation/
**Supporting:** https://hivesecurity.gitlab.io/blog/entra-id-attacks-device-code-prt-conditional-access/
**Date:** 2026-04-26
**MITRE ATT&CK:** T1528, T1550.001 | **Tactic:** Steal Application Access Token, Use Alternate Authentication Material
**Detection Candidate:** Yes

---

## Summary
A critical gap exists in Conditional Access policies that require "compliant" devices: many organisations mistakenly use "Registered" as their device state requirement instead of "Compliant." A registered device is simply one that has been joined to Entra ID — it has no compliance checks, no Intune policy enforcement, and no certificate binding. After a token theft via AiTM phishing or device code phishing, an attacker can register their own device in Entra ID using a stolen authentication broker token, obtain a Primary Refresh Token (PRT) from that device, and register Windows Hello for Business credentials — satisfying even high-assurance CA policies while operating from a fully attacker-controlled device.

---

## Attack Chain
1. Attacker phishes user via device code flow or AiTM proxy — obtains session token
2. Uses Microsoft Authentication Broker client ID (`29d9ed98-a469-4536-ade2-f981bc1d605e`) to request a device registration token
3. Registers attacker-controlled device in Entra ID — appears as legitimate org asset
4. Requests PRT from registered device — valid for up to 90 days, silently issues new access tokens for all Microsoft services
5. Registers Windows Hello for Business credentials on attacker device — satisfies phishing-resistant MFA requirement in CA policies
6. Full M365 access maintained indefinitely — bypasses "Require compliant device" CA policies that use Registered instead of Compliant

---

## Why "Registered" ≠ "Compliant"
| Device State | What It Means | Intune Enforced | Attack Resistant |
|-------------|---------------|----------------|-----------------|
| Registered | Joined to Entra ID — any device | ❌ No | ❌ No |
| Compliant | Registered + passes all Intune compliance policies | ✅ Yes | ✅ Yes |
| Hybrid Joined | Domain + Entra joined | Partial | Partial |

---

## Relevance to Your Environment
Your Conditional Access policies need to be audited to confirm "Require device to be marked as compliant" is selected — not just "Require Hybrid Azure AD joined" or "Require registered device." In a hybrid Intune-managed environment this is the correct control. With the Stryker and Iranian APT threat context already in your vault, identity-based attacks via token theft are a realistic threat vector.

---

## Detection Notes

**1. Device code flow sign-ins (rare in corporate environments — high signal)**
```kql
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where UserType == "Member"
| project TimeGenerated, UserPrincipalName, IPAddress, 
    AppDisplayName, ClientAppUsed, DeviceDetail
| order by TimeGenerated desc
```

**2. New device registration followed by PRT issuance within short window**
```kql
AuditLogs
| where OperationName == "Register device"
| extend DeviceName = tostring(TargetResources[0].displayName)
| project TimeGenerated, 
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    DeviceName, IPAddress = tostring(AdditionalDetails)
| order by TimeGenerated desc
```

**3. Sign-in from newly registered device (high suspicion if outside business hours)**
```kql
SigninLogs
| where DeviceDetail.isCompliant == false
| where DeviceDetail.isManaged == false
| where UserType == "Member"
| project TimeGenerated, UserPrincipalName, IPAddress,
    DeviceDetail, AppDisplayName
| order by TimeGenerated desc
```

---

## Validated Columns
- [ ] SigninLogs — AuthenticationProtocol == "deviceCode"
- [ ] SigninLogs — DeviceDetail.isCompliant
- [ ] SigninLogs — DeviceDetail.isManaged
- [ ] AuditLogs — OperationName "Register device"

---

## Hardening Actions
- [ ] **Audit all CA policies** — confirm "Require device to be marked as compliant" not just "Registered"
- [ ] **Block device code flow** in CA — Authentication Flows → Device code flow → Block (for all users without legitimate use case)
- [ ] **Enable Token Protection** in CA for supported apps — binds tokens to device, prevents replay
- [ ] Build Sentinel analytics rule for device code flow sign-ins
- [ ] Build alert for new device registration + sign-in within 10 minutes

---

## Tags
#research #status/active #identity #cloud #conditional-access #token-theft #aitm #action-required

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-26 | Created |
