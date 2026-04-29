# Intel — Stryker Breach: Handala Abuses Intune to Wipe 200,000 Endpoints

**Source:** https://slcyber.io/blog/the-warning-signs-were-there-how-credential-leaks-and-dark-web-activity-foreshadowed-the-stryker-breach/
**Supporting:** https://www.lumos.com/blog/stryker-hack | https://guardz.com/blog/the-stryker-story-when-device-management-platform-becomes-a-weapon/
**Date:** 2026-04-25
**MITRE ATT&CK:** T1078.004, T1484.002, T1485 | **Tactic:** Valid Accounts, Domain Policy Modification, Data Destruction
**Detection Candidate:** Yes — critical

---

## Summary
On March 11, 2026, Iranian hacktivist group Handala gained Global Administrator access to Stryker's Microsoft Entra ID environment — likely via infostealer-compromised admin credentials active since mid-2024 — and used Microsoft Intune's native remote wipe functionality to destroy 200,000+ endpoints across 79 countries. No malware was deployed. The entire attack was executed using legitimate Microsoft admin tooling. Attackers inserted a non-malware malicious file to abuse the Intune environment and hide activity from detection solutions. Stryker has confirmed the incident impacted Q1 earnings. Palo Alto Networks led remediation.

---

## Attack Chain
1. **Initial access** — Infostealer-compromised admin credentials (admindev@stryker.com, adminqa@stryker.com) sourced from dark web, active since mid-2024. Hundreds of brute-force attempts against VPN infrastructure in months prior.
2. **Entra ID compromise** — Attackers authenticated to Microsoft Entra ID with compromised credentials. Standard MFA bypassed via AiTM (Adversary-in-the-Middle) phishing — session token stolen post-authentication.
3. **Privilege escalation** — Global Administrator access obtained. Possible Entra Connect sync abuse (SyncJacking pattern) — AD Connect with password sync enabled.
4. **Intune abuse** — Attackers accessed Intune admin console and issued enterprise-wide `Clear-MobileDevice` wipe commands to all enrolled endpoints globally, including personal BYOD devices.
5. **Exfiltration** — ~50TB data claimed exfiltrated (unverified — Handala has history of inflated claims).

---

## Relevance to Your Environment
**This is the exact attack scenario your environment needs to defend against.** Your organisation runs Microsoft Intune across ~150+ endpoints with Entra ID in a hybrid AD-joined configuration — identical architecture to Stryker. Key parallels:

- Intune is your MDM — a compromised Global Admin could issue fleet-wide wipe commands
- Hybrid Entra Connect sync creates the SyncJacking escalation path (see [[Threat-Hunting/TTPs/Fabian-Bader-Entra-Connect-SyncJacking]])
- Admin credential exposure via infostealer logs is an ongoing risk
- BYOD enrolled devices would be in scope for a wipe attack
- Standard MFA (push/OTP) does not protect against AiTM — only FIDO2/Windows Hello for Business does

---

## Detection Notes

**1. Intune bulk wipe anomaly — high priority**
```kql
AuditLogs
| where OperationName has_any ("Wipe", "Clear", "RemoveDevice", "RetireDevice")
| where InitiatedBy !has "expected-admin@yourdomain.com"
| summarize WipeCount = count() by InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), bin(TimeGenerated, 5m)
| where WipeCount > 3
| order by TimeGenerated desc
```

**2. Global Admin role assignment**
```kql
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources, RoleName
```

**3. Entra ID sign-in from anonymising infrastructure (VPN/Starlink)**
```kql
SigninLogs
| where UserType == "Member"
| where NetworkLocationDetails has "anonymizedIP" or RiskEventTypes_V2 has_any ("anonymizedIPAddress", "unfamiliarFeatures")
| where UserPrincipalName has_any ("admin", "svc", "sync")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskDetail, RiskEventTypes_V2
```

**4. AiTM token theft indicators — impossible travel post sign-in**
```kql
SigninLogs
| where RiskEventTypes_V2 has "impossibleTravel"
| where UserPrincipalName has_any ("admin", "svc", "global")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskDetail
```

> Validate all column names against your environment before deploying. `OperationName` values for Intune wipe operations should be confirmed in your AuditLogs table.

---

## Validated Columns
- [ ] AuditLogs — OperationName (Intune wipe values)
- [ ] AuditLogs — InitiatedBy
- [ ] SigninLogs — RiskEventTypes_V2
- [ ] SigninLogs — NetworkLocationDetails

---

## Hardening Actions — Priority
- [ ] **Entra Connect SyncJacking hardening** — apply GA fix (see [[Threat-Hunting/TTPs/Fabian-Bader-Entra-Connect-SyncJacking]])
- [x] **Intune admin access review** — audit who has Intune Administrator and Global Admin roles
- [ ] **Phishing-resistant MFA** — evaluate FIDO2/Windows Hello for Business for admin accounts
- [ ] **Conditional Access** — restrict Intune admin console access to compliant, managed devices only
- [x] **Intune Multi Admin Approval** — enforce for device wipe operations (you have documentation for this)
- [x] **Infostealer monitoring** — check HaveIBeenPwned, Flare, or Searchlight Cyber for org domain credential exposure
- [ ] **BYOD review** — audit personal devices enrolled in Intune — consider restricting wipe scope

---

## Related Notes
- [[Threat-Hunting/TTPs/Fabian-Bader-Entra-Connect-SyncJacking]] — SyncJacking GA hardening
- [[Threat-Hunting/TTPs/Jasper-Sleet-North-Korean-IT-Worker-Infiltration]] — identity-based attack patterns
- [[OT-SCADA/Compliance/CISA-Iranian-APT-PLC-Exploitation-AA26-097A]] — same threat actor cluster (Handala/Iranian APT)

---

## Tags
#intel #handala #iran #intune #entra #identity #wiper #t1078 #t1484 #t1485 #global-admin #aitm #infostealer #critical #action-required #status/active  

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created — sourced from Searchlight Cyber, Lumos, Guardz, HIPAA Journal reporting |
