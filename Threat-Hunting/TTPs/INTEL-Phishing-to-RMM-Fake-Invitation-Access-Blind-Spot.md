---
title: INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot
date: 2026-05-08
source: "https://any.run/cybersecurity-blog/us-fake-invitation-phishing/"
author: "ANY.RUN Research"
mitre:
  - "T1566.002"
  - "T1219"
  - "T1556"
  - "T1114"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#email"
  - "#endpoint"
  - "#action-required"
---

# INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://any.run/cybersecurity-blog/us-fake-invitation-phishing/ |
| **Author** | ANY.RUN Research |
| **Date Observed** | 2026-05-08 |
| **Date Published** | 2026-04-22 (campaign first observed); blog ~2026-05-05 |
| **Patch Available** | N/A — technique-based; no single CVE |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1566.002 | Phishing: Spearphishing Link |
| T1219 | Remote Access Software |
| T1556 | Modify Authentication Process (OTP interception) |
| T1114 | Email Collection |

---

## Summary

ANY.RUN documented a large-scale phishing campaign active from at least April 22, 2026, targeting US organisations across banking, government, technology, and healthcare with fake event invitations. The attack chain combines three techniques in sequence: credential theft via fake login pages, OTP interception to bypass MFA, and silent installation of legitimate RMM tools (ScreenConnect, Datto RMM, ITarian, LogMeIn Rescue, Action1, NetSupport, Syncro, MeshAgent, SimpleHelp, RustDesk, Splashtop). Phishing pages are hosted on compromised legitimate websites rather than newly registered domains — bypassing domain-reputation controls. Infrastructure reuses predictable URL patterns (`/Image/*.png`, `/favicon.ico → /blocked.html → phishing content`) and ~80 phishing domains under `.de` TLD registered from December 2025. By April 27, nearly 160 suspicious links had been submitted to ANY.RUN's sandbox. Signs of AI-assisted page generation at scale. The key defender challenge: the payload is a legitimate RMM tool installed in a way that looks like an approved IT action.

---

## Relevance to Environment

Medium-High. Your MDO email surface is the primary exposure point. The fake invitation lure is particularly relevant post-BEC — your users are in a heightened state of awareness about suspicious emails, but the CAPTCHA-gated fake invitation pattern is specifically designed to look routine. The RMM delivery stage is the most dangerous: ScreenConnect, Datto, and ConnectWise are all tools that could plausibly appear in your environment as IT-sanctioned software, making MDO and MDE detections less clear-cut. OTP interception is directly relevant given the recent PRT/AiTM incident — same class of bypass technique. Mobile-only users (no MDE coverage) are particularly exposed.

---

## Detection Notes

`detection_candidate: true` — Two high-value detection surfaces: unauthorised RMM installation and the huntable URL patterns.

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect installation or execution of RMM tools not in approved software baseline
// T1219 — Remote Access Software
// Adjust the tool list to match any approved RMM in your environment

DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe",
    "ConnectWiseControl.ClientService.exe",
    "DattoRMM.exe",
    "ITarian.exe",
    "LogMeInRescue.exe",
    "Action1.exe",
    "NetSupportManager.exe",
    "MeshAgent.exe",
    "SimpleHelp.exe",
    "RustDesk.exe",
    "Splashtop.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound connections from known RMM tools to their control infrastructure
// Flag for review if the tool is not approved in your environment

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "ScreenConnect.ClientService.exe",
    "MeshAgent.exe",
    "Action1.exe",
    "RustDesk.exe",
    "SimpleHelp.exe"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, 
          InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

```kql
// Table: EmailEvents
// Schema: Advanced Hunting (MDO)
// Purpose: Hunt for fake invitation lure patterns — .de domains, CAPTCHA redirect chains
// T1566.002

EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where SenderFromDomain endswith ".de"
    or UrlDomain endswith ".de"
| where Subject has_any ("invitation", "invite", "event", "conference", "meeting")
| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
          Subject, UrlDomain, DeliveryAction, DetectionMethods
| order by Timestamp desc
```

### Validated Columns
- [ ] `FileName` — confirm in `DeviceProcessEvents` (standard)
- [ ] `InitiatingProcessFileName` — confirm in `DeviceProcessEvents` (standard)
- [ ] `RemoteUrl` — confirm availability in `DeviceNetworkEvents` (may be `RemoteIP` only)
- [ ] `EmailDirection` — confirm in `EmailEvents` (standard MDO column)
- [ ] `UrlDomain` — confirm in `EmailEvents` (may require `UrlInfo` join)

---

## Hardening Actions

- [ ] **Audit approved RMM tools** — document what's authorised in your environment and build an allowlist; anything outside it should alert
- [ ] **MDO — review inbound .de domain email volume** — flag elevated volume for review; not a block but a hunt signal
- [ ] **ASR rule — block untrusted process execution from email/browser** — reduces RMM installer execution from phishing delivery
- [ ] **User awareness** — brief staff on CAPTCHA-gated invitation lures specifically; post-BEC window is a good time to reinforce

---

## Related Notes

- [[INTEL-MS-Edge-Cleartext-Passwords-Process-Memory]]
- [[INTEL-Malicious-AI-Browser-Extensions-RAT-MitM-Infostealer]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-08 | Created — tagged [INFO] in email, escalated to [INTEL] based on active campaign with RMM delivery chain |
