---
title: INTEL-Unit42-Phishing-Pivots-Sophisticated-Methods-2026-05-07
date: 2026-05-12
source: "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-05-07-Phishing-Campaign-Pivots-To-Sophisticated-Methods.txt"
author: "Palo Alto Networks Unit 42"
mitre:
  - "T1566.001"
  - "T1557"
  - "T1114.003"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#email"
  - "#identity"
---

# INTEL — Unit 42: Phishing Campaign Pivots to Sophisticated Methods (2026-05-07)

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-05-07-Phishing-Campaign-Pivots-To-Sophisticated-Methods.txt |
| **Author** | Palo Alto Networks Unit 42 |
| **Date Observed** | 2026-05-12 |
| **Date Published** | 2026-05-07 |
| **Patch Available** | N/A -- campaign TTPs, no CVE |

**Corroborating reference:**
- https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1557 | Adversary-in-the-Middle |
| T1114.003 | Email Collection: Email Forwarding Rule |

---

## Summary

Unit 42 documented a sophisticated multi-stage phishing campaign that affected 35,000+ users across 13,000 organisations in 26 countries (92% US-based) as of early May 2026. The campaign uses a "code of conduct" HR violation lure -- emails impersonating internal HR/compliance functions with PDF attachments titled "Awareness Case Log File" or "Disciplinary Action -- Employee Device Handling Case." The PDF instructs recipients to click a "Review Case Materials" link, which leads through a Cloudflare CAPTCHA gate (reinforcing legitimacy appearance) before delivering an Adversary-in-the-Middle (AiTM) phishing page that captures credentials and session tokens in real time. The AiTM component is significant -- valid user authentication actions become the attack vector, bypassing MFA by stealing the authenticated session token rather than the password.

The campaign deliberately avoids botnets, compromised servers, and other common IOC signals, making static analysis and signature-based filtering largely ineffective. Healthcare and financial services are cited as primary targeted sectors.

---

## Relevance to Environment

**Email surface (High):** The "code of conduct" lure is specifically designed to target employees in any sector -- the HR/compliance framing is sector-agnostic and effective in agricultural/cooperative environments. The PDF attachment delivery method bypasses many URL-scanning controls since the initial email contains no malicious links.

**AiTM risk:** Your environment has an active AiTM BEC case (FIND-IR-2026-05-07-lt13069) and a prior stolen PRT incident. This campaign uses the same fundamental technique -- session token theft via AiTM proxy -- that succeeded in those cases. MDO safe links coverage and Conditional Access token binding are the relevant controls.

**MDO coverage:** Validate that MDO Safe Attachments is scanning PDF attachments from external senders. The CAPTCHA gate is specifically designed to defeat automated sandboxing -- human-realistic interaction may be required to progress past it, meaning automated detonation may not catch the payload.

---

## Detection Notes

### KQL Stubs

```kql
// Table: EmailEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect inbound emails with PDF attachments using HR/compliance lure subject patterns
// Matches "code of conduct", "disciplinary action", "awareness case" subject patterns

EmailEvents
| where EmailDirection == "Inbound"
| where AttachmentCount > 0
| where Subject has_any (
    "code of conduct",
    "disciplinary action",
    "awareness case",
    "case log",
    "employee device",
    "conduct review"
)
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress,
    Subject, AttachmentCount, ThreatTypes, DetectionMethods
| order by Timestamp desc
```

```kql
// Table: EmailAttachmentInfo
// Schema: Advanced Hunting (MDE)
// Purpose: Correlate PDF attachment filenames matching campaign lure patterns
// Links to EmailEvents via NetworkMessageId

EmailAttachmentInfo
| where FileName matches regex @"(?i)(awareness.case|disciplinary.action|conduct.review|case.log).*(\.pdf)$"
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
    FileName, FileSize, ThreatTypes, DetectionMethods
| order by Timestamp desc
```

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect inbox forwarding rules created after a phishing click -- post-AiTM persistence
// AiTM campaigns commonly create auto-forward rules immediately after token theft

CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress,
    ActionType, RawEventData
| order by Timestamp desc
```

### Validated Columns
- [ ] `AttachmentCount` -- confirm available in EmailEvents Advanced Hunting schema
- [ ] `EmailDirection` -- confirm "Inbound" is the correct value for external emails
- [ ] `FileName` in EmailAttachmentInfo -- validate regex syntax in Advanced Hunting
- [ ] `RawEventData` forwarding rule fields -- validate JSON path for ForwardTo in New-InboxRule events

---

## Hardening Actions

- [ ] **Validate MDO Safe Attachments** is configured to scan PDF attachments from external senders -- confirm policy covers the full user population including acquired company users
- [ ] **Review MDO anti-phishing policies** -- confirm AiTM protection (Defender for Office 365 Plan 2) is enabled; "Honor DMARC policy" and "Impersonation protection" are relevant controls
- [ ] **Inbox forwarding rule audit** -- run the CloudAppEvents forwarding rule query above for the last 30 days; this is also an open action from the AiTM BEC case
- [ ] **User awareness** -- "code of conduct" lure is high-efficacy; consider a targeted awareness reminder to HR-adjacent staff (managers, admin assistants) who are most likely targets

---

## Related Notes

- [[IR-DFIR/Cases/]] -- AiTM BEC / stolen PRT case -- same underlying technique
- [[FIND-IR-2026-05-07-lt13069]]

---

## Tags

#intel #status/draft #email #identity

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created |
