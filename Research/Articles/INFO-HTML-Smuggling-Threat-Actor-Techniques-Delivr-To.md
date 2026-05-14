---
title: INFO-HTML-Smuggling-Threat-Actor-Techniques-Delivr-To
date: 2026-05-14
source: "https://blog.delivr.to/html-smuggling-recent-observations-of-threat-actor-techniques-74501d5c8a06"
tags:
  - "#resource"
  - "#status/draft"
  - "#email"
  - "#endpoint"
---

# INFO — HTML Smuggling: Recent Threat Actor Techniques (delivr.to)

**Source:** https://blog.delivr.to/html-smuggling-recent-observations-of-threat-actor-techniques-74501d5c8a06
**Date:** 2026-05-14
**Author:** delivr.to

---

## What It Is

Technical breakdown of HTML smuggling delivery techniques observed in the wild — how threat actors use HTML5 Blob objects and JavaScript to assemble malicious payloads locally in the browser, bypassing perimeter email gateways and web proxies entirely. Covers ISO/ZIP payload delivery (Qakbot pattern), fake Microsoft 365 login page delivery for AiTM credential capture, and encoding/obfuscation progressions from Base64 to reversed Base64 to XOR-encrypted payloads.

---

## Relevance

Medium-High. HTML smuggling is the delivery mechanism behind several email-based threats directly relevant to the environment: AiTM phishing (local iframe login page rendered in browser, as seen in the active BEC case), Qakbot-style ISO drops, and fake Google Drive / Adobe lure pages. The technique is specifically designed to defeat MDO Safe Attachments sandbox analysis — the payload assembles post-delivery in the browser, so there is nothing malicious passing through the network at scan time. MDO detection of HTML smuggling relies on heuristic analysis of the HTML/JS structure at the attachment level rather than detonation. Worth validating MDO HTML smuggling heuristic coverage is enabled.

---

## Key Points

- Payload assembles locally in the browser via JavaScript — no outbound request, no network-level IOC at delivery time
- Common lure patterns: fake Google Drive, fake Adobe, fake Microsoft 365 login
- Encoding progression: plain Base64 → reversed Base64 → XOR cipher — each step reduces signature detection
- XHTML and SHTML extensions used to bypass filters scoped to `.html` only
- AiTM variant: login page rendered locally via smuggled HTML, credentials captured via transparent proxy — used in active campaigns targeting M365 (directly relevant to BEC case)
- MDO safe attachments must heuristically detect the JS structure — confirm HTML smuggling protection is enabled in anti-malware policies

---

## Actions

- [ ] Confirm MDO Safe Attachments policy is configured to scan HTML/XHTML/SHTML attachment types — not just .exe/.zip/.doc
- [ ] Validate MDO anti-phishing policy has HTML smuggling heuristics enabled (Defender for Office 365 Plan 2 — Advanced Phishing Thresholds: 2 or higher)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-14 | Created — lightweight triage note |
