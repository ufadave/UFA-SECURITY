---
title: INFO-HTML-Smuggling-Threat-Actor-Techniques
date: 2026-05-18
source: "https://blog.delivr.to/html-smuggling-recent-observations-of-threat-actor-techniques-74501d5c8a06"
tags:
  - "#resource"
  - "#status/draft"
  - "#email"
  - "#endpoint"
---

# INFO-HTML-Smuggling-Threat-Actor-Techniques

**Source:** https://blog.delivr.to/html-smuggling-recent-observations-of-threat-actor-techniques-74501d5c8a06
**Date:** 2026-05-18

---

## What It Is

A delivr.to analysis of evolving HTML smuggling techniques observed in threat actor campaigns — covering payload obfuscation methods (Base64, hex encoding, XOR encryption), delivery triggers (button-click vs auto-execute), sandbox evasion patterns, and browser-side payload reconstruction. Covers Qakbot variants and fake Microsoft 365 credential harvest pages. MITRE T1027.006.

---

## Relevance

Medium-high. HTML smuggling is a persistent email threat surface that bypasses MDO attachment scanning (the payload is assembled client-side by the browser, never transmitted as a detectable file type). Your environment has MDO for email protection, but HTML smuggling is specifically designed to evade gateway inspection. Given KongTuke is now using Teams + PowerShell delivery (similar social engineering logic), HTML smuggling remains relevant as a parallel email delivery vector. The delivr.to platform also offers email security control validation — potentially useful for testing MDO coverage gaps.

---

## Actions

- [ ] Review MDO safe attachments policy — confirm `.html` and `.htm` attachments are detonated in sandbox
- [ ] Consider testing MDO coverage against HTML smuggling using delivr.to sample payloads (free tier available)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-18 | Created — lightweight triage note |
