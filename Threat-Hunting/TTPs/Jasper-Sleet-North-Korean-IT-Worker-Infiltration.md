# Intel — Jasper Sleet: North Korean IT Worker Infiltration via Workday, Teams & DocuSign

**Source:** https://www.microsoft.com/en-us/security/blog/2026/04/21/detection-strategies-cloud-identities-against-infiltrating-it-workers/
**Via:** cyb3rmik3
**Date:** 2026-04-21
**MITRE ATT&CK:** T1078, T1199, T1567 | **Tactic:** Valid Accounts, Trusted Relationship, Exfiltration
**Detection Candidate:** Yes — KQL queries included

---

## Summary
Microsoft Threat Intelligence documents Jasper Sleet, a North Korea-aligned threat actor, systematically infiltrating organisations by applying for remote IT roles using AI-generated fake identities. Actors survey HR platforms like Workday via exposed recruiting APIs, submit convincing AI-tailored applications, pass interviews using fabricated personas, and once hired gain legitimate access to Teams, SharePoint, OneDrive, and Exchange Online. Post-hire, payroll accounts are redirected and data exfiltration begins. Microsoft Defender for Cloud Apps detections now exist across Workday, DocuSign, Zoom, and Webex. The article includes five Advanced Hunting queries.

---

## Relevance to Your Environment
If your organisation hires remote IT contractors or uses Workday for HR workflows, this is directly applicable. The post-hire phase is the higher risk — once an account is created in Entra ID and provisioned with M365 access, Jasper Sleet has legitimate access to your entire collaboration stack. Impossible travel alerts on new hires are the primary signal Microsoft flags.

---

## Detection Notes — KQL Queries (from article)

**1. Workday Recruiting API access from external accounts**
```kql
let api_endpoint_regex = 'hrrecruiting/*';
CloudAppEvents
| where Application == 'Workday'
| where IsExternalUser
| where ActionType matches regex api_endpoint_regex
| where IPAddress in (<suspiciousips>) or AccountId in (<suspicious_emailids>)
| summarize make_set(ActionType) by AccountId, IPAddress, bin(Timestamp, 1d)
```

**2. Email communications related to interviews**
```kql
EmailEvents
| where SenderMailFromAddress == "<suspicious_emailids>"
    or RecipientEmailAddress == "<suspicious_emailids>"
| where Subject has "Interview"
| project Timestamp, SenderMailFromAddress, SenderDisplayName,
    SenderIPv4, SenderIPv6, RecipientEmailAddress, Subject,
    DeliveryAction, DeliveryLocation
```

**3. Teams communications from external suspicious accounts**
```kql
CloudAppEvents
| where Application == "Microsoft Teams"
| where IsExternalUser
| where AccountId == "<suspicious_emailids>"
    or IPAddress == "<suspiciousIPs>"
| summarize make_set(ActionType) by IPAddress, AccountId, bin(Timestamp, 1d)
```

**4. DocuSign agreement signing from suspicious sources**
```kql
CloudAppEvents
| where Application == "DocuSign"
| where IsExternalUser
| where ActionType == "ENVELOPE SIGNED"
| where IPAddress in ("<suspiciousIPs>")
    or AccountId == "<suspicious_emailids>"
```

**5. New hire payroll/account changes from suspicious IPs**
```kql
CloudAppEvents
| where Application == "Workday"
| where AccountId == "<NewHireWorkdayId>"
| where ActionType has_any ("Add", "Change", "Assign", "Create", "Modify")
    and ActionType has_any ("Account", "Bank", "Payment", "Tax")
| where IPAddress in ("<suspiciousIPs>")
| summarize make_set(ActionType) by IPAddress, bin(Timestamp, 1d)
```

> **Schema note:** All queries use `CloudAppEvents` — confirm table availability in your Advanced Hunting schema. `IsExternalUser` column should be validated.

---

## Validated Columns
- [ ] CloudAppEvents — IsExternalUser
- [ ] CloudAppEvents — ActionType
- [ ] CloudAppEvents — IPAddress
- [ ] CloudAppEvents — AccountId
- [ ] EmailEvents — SenderMailFromAddress
- [ ] EmailEvents — SenderIPv4 / SenderIPv6

---

## Broader Detection — Post-Hire Signals
Even without Workday, these signals apply to any new hire:
- Impossible travel alerts within first 60 days of account creation
- M365 data access (SharePoint, OneDrive downloads) from anonymising proxies
- New hire account accessing sensitive data outside business hours or from unexpected geographies

```kql
// Impossible travel on recently created accounts
SigninLogs
| where TimeGenerated > ago(60d)
| where RiskEventTypes_V2 has "impossibleTravel"
| join kind=inner (
    AuditLogs
    | where OperationName == "Add user"
    | extend NewUserUPN = tostring(TargetResources[0].userPrincipalName)
    | where TimeGenerated > ago(60d)
) on $left.UserPrincipalName == $right.NewUserUPN
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskEventTypes_V2
```

---

## Actions
- [ ] Create Sentinel analytics rule for impossible travel on accounts created in last 60 days
- [ ] Validate CloudAppEvents schema columns against your environment
- [ ] Check if Defender for Cloud Apps connectors are enabled for Teams and DocuSign
- [ ] Brief HR/People team on Jasper Sleet pattern — social engineering awareness
- [ ] File queries in [[Detection-KQL/Hunting-Queries/]] once validated

---

## Tags
#intel #jasper-sleet #north-korea #identity #insider-threat #workday #t1078 #t1199 #impossible-travel #detection-candidate

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-24 | Created — includes 5 KQL queries from Microsoft source + bonus impossible travel query |
