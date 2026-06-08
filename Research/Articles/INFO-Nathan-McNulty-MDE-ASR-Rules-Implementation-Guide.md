---
title: INFO-Nathan-McNulty-MDE-ASR-Rules-Implementation-Guide
date: 2026-06-06
source: "https://nathanmcnulty.com/blog/2022/11/defender-for-endpoint-implementing-asr-rules/"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
---

# INFO -- Nathan McNulty: Implementing MDE ASR Rules (Updated 2025)

**Source:** https://nathanmcnulty.com/blog/2022/11/defender-for-endpoint-implementing-asr-rules/
**Date:** 2026-06-06
**Author:** Nathan McNulty
**Last Updated:** January 27, 2025 (content review in progress per site note)

---

## What It Is

Practitioner guide to deploying Attack Surface Reduction (ASR) rules via Intune for
Microsoft Defender for Endpoint environments. Covers the full deployment lifecycle:
discovery of what ASR events are generating alerts in the environment, exclusion management,
CSV import/export via the Intune portal, and an Advanced Hunting KQL query for monitoring
new ASR detections after exclusions are applied.

**Key workflow documented:**
1. Use the ASR rules report in the M365 Defender portal to discover existing detections
2. Export detections as CSV, identify legitimate activity to exclude (full file paths)
3. Import exclusion CSV into Intune via Endpoint Security → Attack Surface Reduction policy
4. After exclusions propagate (30 days), monitor for net-new detections only
5. Automate ongoing monitoring via MDE Custom Detection using an Advanced Hunting query

**Updated guidance (from site note):**
- Credential theft ASR rule (`lsass.exe`) is now recommended for enablement out of the box,
  without requiring audit-mode discovery first
- Several additional rules now recommended in audit mode with associated KQL queries to
  support the discovery workflow

---

## Relevance

Medium-High — directly applicable to current Intune-managed MDE deployment. ASR rules are
listed in the Active Security Context under "Hardening Controls Deployed" as "ASR policy
monitoring" but this note clarifies the full deployment methodology and the exclusion
management approach which is needed to operationalise them without generating alert fatigue.

**The Advanced Hunting custom detection approach** for monitoring net-new ASR events after
exclusions are applied is the same pattern used for the network scanning and LOLBin detections
already deployed — consistent with the existing detection workflow.

The credential theft rule update (enable out of the box rather than audit-first) is
particularly relevant given the active threat priority of Iranian APT identity attacks and
the AiTM BEC case open in IR.

---

## Actions

- [ ] Review current ASR rule state in Intune — confirm which rules are in audit vs enforce mode
- [ ] Apply updated guidance: enable credential theft (LSASS) rule in enforce mode without waiting for audit-discovery
- [ ] Review McNulty's recommended audit-mode rules and associated KQL queries for any new coverage gaps
- [ ] Consider the Advanced Hunting monitoring query for net-new ASR events post-exclusion as a complement to existing custom detections

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-06 | Created — McNulty ASR implementation guide; credential theft rule updated guidance flagged |
