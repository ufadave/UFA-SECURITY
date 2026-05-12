---
title: INFO-MDE-Selective-Response-Actions-Critical-Assets
date: 2026-05-07
source: "https://learn.microsoft.com/en-us/defender-endpoint/restrict-response-actions-high-value-assets"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
---

# INFO-MDE-Selective-Response-Actions-Critical-Assets

**Source:** https://learn.microsoft.com/en-us/defender-endpoint/restrict-response-actions-high-value-assets
**Date:** 2026-05-07

---

## What It Is

Microsoft Defender for Endpoint preview feature — **Selective Response Actions** — that allows per-device control over which high-impact response capabilities (isolation, app restriction, live response, AIR, remediation requests) are permitted on Tier-0 and high-value assets (domain controllers, ADFS servers, critical infrastructure). Configuration is baked into the MDE onboarding package at deployment time using the Defender Deployment Tool; it cannot be changed post-onboarding without offboarding and re-onboarding. Devices in restricted mode retain full detection, alerting, and sensor coverage — only the *response* actions are scoped. Live response script execution is disabled by design in restricted mode even when live response is otherwise enabled.

Requires Sense version 10.8798+ and OS-specific KBs (Server 2022: KB5063880, Server 2019: KB5063877, Win 10 22H2: KB5062649, Win 11 24H2: KB5062660). The `RestrictedDeviceSecurityOperations` property is queryable in Advanced Hunting.

---

## Relevance

Medium. Directly applicable to domain controller onboarding and the fertilizer plant OT-adjacent Windows servers — environments where full isolation or live response could cause operational disruption. Worth evaluating for the DC tier before expanding MDE coverage to Tier-0 assets. The Advanced Hunting queryability of `RestrictedDeviceSecurityOperations` is a useful operational visibility addition.

---

## Actions

- [ ] Review which domain controllers and Tier-0 servers are currently onboarded to MDE and in what mode (check Device Inventory `Security operations` column)
- [ ] Assess whether restricted mode is appropriate for DC tier before any re-onboarding cycle
- [ ] Note: offboard/re-onboard is required to change mode — plan ahead before any hardening push touches DCs
- [ ] Evaluate for OT-adjacent Windows hosts at fertilizer plant if/when MDE onboarding is extended there

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Created |
