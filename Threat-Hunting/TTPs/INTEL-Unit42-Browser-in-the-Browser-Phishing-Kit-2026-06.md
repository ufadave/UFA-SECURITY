---
title: INTEL-Unit42-Browser-in-the-Browser-Phishing-Kit-2026-06
date: 2026-06-25
source: "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-06-22-malware-distribution-via-browser-in-the-browser-kit.txt"
author: "Palo Alto Networks Unit 42"
mitre:
  - "T1566.002"
  - "T1056.003"
  - "T1539"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#email"
  - "#identity"
---

# INTEL -- Unit 42: Browser-in-the-Browser Phishing Kit (June 22, 2026)

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-06-22-malware-distribution-via-browser-in-the-browser-kit.txt |
| **Author** | Palo Alto Networks Unit 42 |
| **Date Observed** | 2026-06-25 |
| **Date Published** | 2026-06-22 |
| **Campaign Status** | Active |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1566.002 | Phishing: Spearphishing Link |
| T1056.003 | Input Capture: Web Portal Capture |
| T1539 | Steal Web Session Cookie |

---

## Summary

Unit 42 documented an active Browser-in-the-Browser (BitB) phishing campaign distributing
malware via a sophisticated kit that spoofs OAuth popup windows to steal Microsoft 365
credentials. The campaign uses several advanced evasion techniques that go beyond
standard BitB implementations:

**Draggable popup window:** Unlike most BitB implementations, the spoofed popup can
be dragged around the screen, mimicking the feel of a real OS window. This removes
one of the most reliable visual cues users use to identify fake popups -- the inability
to move a browser-rendered overlay outside its parent window.

**OS and browser fingerprinting:** The kit fingerprints the victim's OS and browser
at runtime and renders the popup with matching fonts, styling, and UI chrome. Windows
users see a Windows-styled OAuth window; Mac users see a macOS-styled one. This
eliminates styling mismatches that trained users might spot.

**Spoofed OAuth URL with real-domain display:** The popup displays a URL that appears
to be a legitimate Microsoft OAuth endpoint (`login.microsoftonline.com`). This passes
visual inspection and can defeat hover-preview-based checks since the popup URL bar
is rendered HTML, not a real browser URL bar.

**Debugging block and bot redirect:** The kit blocks browser DevTools to prevent
analysis and detects automated scanners/bots, redirecting them to a benign page. This
defeats many URL sandboxing approaches.

**Keyword fragmentation:** Malicious keywords are fragmented in the source HTML to
evade static signature scanning.

**Silent exfiltration and redirect:** Credentials entered in the popup are silently
sent to an attacker-controlled server. The victim is then redirected to the real
Microsoft login page, so they simply believe they mistyped their password and try
again -- providing a second credential submission opportunity and delaying detection.

---

## Relevance

High. The M365-focused credential theft vector is directly relevant to the 1,600-user
environment. MDO Safe Links and Safe Attachments are the primary email-layer controls,
but this campaign operates via web delivery (malicious link in email opens a webpage
that renders the BitB popup) rather than direct attachment or malicious domain
link. The OAuth popup spoofing specifically targets the familiar M365 login flow that
users encounter daily.

**Key defensive gap this exploits:** Users are trained to check URLs in the browser
address bar. The BitB popup has a fake address bar that shows a legitimate URL -- users
are checking the right thing, but the thing they're checking is fake. This defeats
URL-bar verification as a user training control.

**MDO coverage:** Safe Links wraps the initial phishing link, but if the phishing page
itself passes URL reputation checks (new domain, clean reputation, or legitimate
hosting infrastructure), Safe Links may not block it. The kit's bot-detection
specifically targets sandbox evaluation that Safe Links uses.

---

## Detection Notes

### KQL Stubs

```kql
// Table: EmailEvents
// Schema: Advanced Hunting (MDE/MDO)
// Purpose: Surface emails containing links to domains newly registered or with low
// UrlCount that subsequently have ClickedThrough events -- proxy for credential
// phishing pages that evade initial reputation scanning.

EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction != "Blocked"
| extend UrlCount = toint(UrlCount)
| where UrlCount between (1 .. 3)  // minimal URLs -- typical phishing delivery
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(7d)
    | where IsClickedThrough == tobool("true")
    | where ActionType == "ClickAllowed"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, UrlDomain, Url, IsClickedThrough
| order by Timestamp desc
```

### Validated Columns
- [ ] `IsClickedThrough` -- requires `tobool()` cast per schema notes
- [ ] `UrlCount` -- requires `toint()` cast per schema notes
- [ ] `UrlDomain` -- confirm field exists in UrlClickEvents (vs `Url`)

---

## Hardening Actions

- [ ] **Review MDO Safe Links policy** -- confirm "Do not track when users click safe links"
  is disabled (tracking required for ClickedThrough detection)
- [ ] **Enable "Block the following URLs" list** in Safe Links for known-bad BitB infrastructure
  once IOCs are extracted from the Unit 42 file
- [ ] **Phishing simulation training** -- run a BitB-style phishing simulation to test user
  awareness of the draggable OAuth popup technique; standard URL-bar training is insufficient
  against this class of attack
- [ ] **Fetch IOCs from Unit 42 GitHub file** -- the .txt file contains specific domains, IPs,
  and hashes for this campaign; load into MDO block lists and Cisco Secure Access

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-25 | Created -- Unit 42 BitB campaign with draggable popup, OS fingerprinting, bot detection |
