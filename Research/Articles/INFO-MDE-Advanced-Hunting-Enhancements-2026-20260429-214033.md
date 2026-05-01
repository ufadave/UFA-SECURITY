---
title: "Microsoft Defender: New Advanced Hunting Enhancements"
date: 2026-04-29
source: https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/microsoft-defender-new-advanced-hunting-enhancements/4514654
type: product-update
tags:
  - "#resource"
  - "#detection"
  - "#endpoint"
  - "#cloud"
  - "#status/review"
---

# Microsoft Defender: New Advanced Hunting Enhancements

**Source:** [Microsoft Defender XDR Blog – Apr 28, 2026](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/microsoft-defender-new-advanced-hunting-enhancements/4514654)
**Author:** Noa Nutkevitch, Microsoft
**Date Received:** 2026-04-29
**Type:** Product Update — Advanced Hunting / KQL

---

## What It Is

Microsoft has shipped a set of enhancements to the Advanced Hunting experience in Microsoft Defender XDR targeting analyst friction points — scale limits, result set management, and UX clarity. Aimed at reducing mid-investigation interruptions caused by query limits or unexpected portal behaviour.

---

## Key Changes

### Records Limitation Picker
A new toolbar control lets analysts explicitly cap query result rows before running. Available presets: **1,000 / 5,000 / 10,000 / 30,000 / 100,000** rows, plus a custom value. The lower of the picker value and any KQL-defined `take` / `limit` always wins. Selection persists across refreshes and browser restarts. Default is maximum (100,000).

> **Analyst note:** Previously, hitting the 100k limit silently truncated results or threw an error mid-hunt. The picker makes resource management explicit and persistent — useful when doing broad pivots that you know will return noise.

### UX Streamlining
Significant interface declutter focused on reducing visual noise and improving navigation clarity. Microsoft cites customer feedback that the XDR portal previously felt less familiar than the Sentinel / Azure portal experience — new changes include pinnable tabs and simplified navigation to ease transition for Sentinel-first analysts.

### Error Transparency
Query execution errors and limit-hit conditions now surface with clearer messaging rather than requiring trial-and-error troubleshooting. Partial result sets (where the 64MB size limit was hit) now display a visible indicator rather than silently truncating.

### Scale for Large Investigations
Broader capacity improvements to support large-scale, multi-domain investigations. Designed to reduce constraint-related interruptions during complex hunts.

---

## Relevance to Environment

**High.** You work heavily in Advanced Hunting across MDE, MDO, and MCAS tables. The records picker is immediately useful for managing large hunts against `DeviceNetworkEvents`, `DeviceProcessEvents`, and `CloudAppEvents` — all of which can return massive result sets when hunting across 150+ endpoints. The UX improvements should also ease any future onboarding of other analysts to the XDR portal vs Sentinel.

The partial result indicator (64MB limit) is operationally relevant — silent truncation was a known risk when writing broad hunting queries without explicit `take` limits.

---

## Broader Context (from research)

While reviewing this article, several related April 2026 updates are worth noting:

- **Two new AH tables in Public Preview:** `CloudDnsEvents` (DNS activity from cloud infra) and `CloudPolicyEnforcementEvents` (Defender for Cloud policy enforcement decisions). Potentially useful for cloud-side detection coverage.
- **Copilot chat in Defender portal** — conversational AI access across incidents, alerts, identities, and devices without leaving the portal.
- **Security Alert Triage Agent** expanding to identity and cloud alerts (phish + identity + cloud in single agent).
- **Identity Security Dashboard (Preview)** — new dashboard covering human and non-human identities, privileged accounts, risky users. Non-human identities tab (Entra apps, AD service accounts, Salesforce apps) is directly relevant given service principal abuse concerns.
- **Identity Risk Score (0-100)** — likelihood of compromise score, feeds into Conditional Access workflows.
- **Sentinel repositories API call to action:** Update older "content as code" API versions before **June 15, 2026**.

---

## Action Items

- [ ] Review the new records limitation picker behaviour — confirm default is 100k in your tenant and adjust if needed for routine hunts
- [ ] Validate `CloudDnsEvents` and `CloudPolicyEnforcementEvents` table availability in your tenant once GA
- [ ] Review Identity Security Dashboard when available — specifically non-human identities / service principal tab given current SP abuse threat priority
- [ ] **Check Sentinel repositories API version before June 15, 2026** — update any content-as-code pipelines
- [ ] Consider enabling identity risk score and reviewing CA policy integration

---

## Related Notes

- [[KQL-Detection/Queries/]] — General query library
- [[Projects/M365-Hardening/]] — Ongoing M365 hardening
- [[Threat-Hunting/TTPs/]] — Service principal abuse TTPs

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-29 | Note created from Gmail [INFO] email |
