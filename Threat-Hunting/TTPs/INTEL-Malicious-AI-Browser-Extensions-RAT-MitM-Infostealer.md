---
title: INTEL-Malicious-AI-Browser-Extensions-RAT-MitM-Infostealer
date: 2026-05-07
source: "https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/"
author: "Unit 42 — Palo Alto Networks"
mitre:
  - "T1176"
  - "T1539"
  - "T1185"
  - "T1557"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#cloud"
  - "#infostealer"
  - "#action-required"
---

# INTEL-Malicious-AI-Browser-Extensions-RAT-MitM-Infostealer

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/ |
| **Author** | Unit 42 — Palo Alto Networks |
| **Date Observed** | 2026-05-07 |
| **Date Published** | ~2026-05-05 |
| **Patch Available** | N/A — Google removed/warned 18 identified extensions; ongoing threat category |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1176 | Browser Extensions |
| T1539 | Steal Web Session Cookie |
| T1185 | Browser Session Hijacking |
| T1557 | Adversary-in-the-Middle |

---

## Summary

Unit 42 identified 18 Chrome browser extensions marketed as AI productivity tools (email assistants, writing helpers, summarisers) that deliver remote access trojans (RATs), adversary-in-the-browser (AitB) attacks, and infostealers. Malicious techniques include WebSocket-based C2, browser API hooking (replacing `window.fetch`/`XMLHttpRequest`), DOM-based credential and prompt harvesting, and dynamic PAC-based proxy hijacking. A subset used LLM-generated code to accelerate malware production. Earlier in the campaign series (Aug 2025–Feb 2026) Unit 42 flagged related activity: AI summary extensions exfiltrating to low-reputation domains, MCP-themed RATs targeting developers, and 30K+ domains distributing the "OmniBar AI Chat and Search" hijacker. Google has removed or issued policy warnings for all 18 disclosed extensions, but the threat category is active and recurring.

---

## Relevance to Environment

Medium-High. Your managed Windows endpoints run Edge (Chromium-based, supports Chrome extensions via flag or policy). Any user who has installed an AI writing assistant, email helper, or prompt tool via the Chrome/Edge extension store is a potential victim. The data most at risk is exactly what your users handle: M365 email content, Entra ID session tokens, and prompts containing potentially sensitive operational data. MCP-themed RAT activity is particularly relevant given growing MCP tooling adoption. No Intune policy currently restricts extension installation — this is a gap. OT-adjacent workstations should be assessed for browser extension exposure.

---

## Detection Notes

`detection_candidate: true` — Detection opportunities around suspicious extension network behaviour and C2 beaconing from browser processes.

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect browser process making outbound connections to low-reputation or unusual external hosts
// Proxy for AitB extension C2 beaconing
// T1185 / T1557

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe")
| where RemotePort in (80, 443, 8080, 8443)
| where not(RemoteUrl has_any (
    "microsoft.com", "google.com", "bing.com", "office.com",
    "windowsupdate.com", "azure.com", "akamai.com", "cloudflare.com"
))
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
| where ConnectionCount > 10
| order by ConnectionCount desc
```

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect browser extension processes spawning child processes (unusual — may indicate RAT activity)
// T1176

DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe")
| where FileName !in~ ("msedge.exe", "chrome.exe", "crashpad_handler.exe", "elevation_service.exe")
| where FileName !endswith ".tmp"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Validated Columns
- [ ] `RemoteUrl` — confirm availability in `DeviceNetworkEvents` (may be `RemoteIP` only in some tenants)
- [ ] `InitiatingProcessFileName` — standard column, confirm case sensitivity handling
- [ ] `RemotePort` — confirm column name vs `RemoteIPPort` in your schema

---

## Hardening Actions

- [ ] **Audit installed browser extensions across managed endpoints** — Use MDE Advanced Hunting or Intune device inventory; prioritise AI/productivity category extensions installed from unknown publishers
- [ ] **Implement Intune/GPO browser extension allowlist** — Block installation of unapproved extensions via Edge ExtensionInstallBlocklist / ExtensionInstallAllowlist policies
- [ ] **Review MCP-adjacent tooling** — If any staff use MCP clients or AI coding tools via browser, assess extension footprint
- [ ] **User awareness** — Brief staff: AI writing assistants from unknown sources are an active threat vector

---

## Related Notes

- [[KQL-Browser-Extension-C2-Beaconing]]
- [[HARD-Edge-Extension-Installation-Policy]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Created — Unit 42 research; escalated from [Info] to [INTEL] based on active RAT/MitM campaign content |
