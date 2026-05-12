---
title: INFO-AADGraphActivityLogs-Entra-Recon-Detection
date: 2026-05-12
source: "https://cloudbrothers.info/en/aadgraphactivitylogs/"
tags:
  - "#resource"
  - "#status/draft"
  - "#action-required"
  - "#identity"
  - "#cloud"
---

# INFO — AADGraphActivityLogs: Entra Recon Detection (Cloudbrothers)

**Source:** https://cloudbrothers.info/en/aadgraphactivitylogs/
**Date:** 2026-05-12
**Author:** Fabian Bader (Cloudbrothers)

---

## What It Is

Deep-dive by Fabian Bader on `AADGraphActivityLogs`, a new Sentinel log source that entered general availability in early May 2026 after a long private preview. The table logs all requests made against the legacy Azure AD Graph API (the old API on a retirement path) and is configured via Entra ID Diagnostic Settings forwarding to a Log Analytics workspace. The article covers the schema, key fields for detection engineers, timing caveats (7-minute median lag, 70-minute maximum between `TimeRequested` and `TimeGenerated`), and KQL hunting queries to detect known recon tooling (ROADtools, AADInternals, Ping Castle) based on `UserAgent`, `RequestUri`, and request volume patterns.

---

## Relevance

High -- directly actionable. The Azure AD Graph API is one of the most abused recon surfaces in Entra ID attacks. ROADtools and AADInternals both use it extensively for tenant enumeration, and the Intune Company Portal Conditional Access bypass relies on the default grant to this resource. This fills a gap that has existed for years. The `AADGraphActivityLogs` table needs to be enabled via Entra ID Diagnostic Settings -- it is not on by default. Given the active Entra app registration audit action item and the AiTM BEC case, enabling this now is high value.

**Key schema fields:**
- `TimeRequested` -- actual API call time (use this for detections, not `TimeGenerated`)
- `RequestMethod` -- GET/POST/PATCH/DELETE
- `ResponseStatusCode` -- 200-204 (success), 403/401 (access denied -- interesting)
- `ResponseSizeBytes` -- large responses on enumeration endpoints are significant
- `UserAgent` -- ROADtools and AADInternals have distinctive UA strings

**Timing note:** Adjust all KQL queries by at least 70 minutes to account for the maximum lag between `TimeRequested` and `TimeGenerated`. Near-real-time detection on this table is not reliable.

---

## Actions

- [ ] **Enable AADGraphActivityLogs** in Entra ID Diagnostic Settings -- forward to Sentinel Log Analytics workspace. Navigate: Entra admin center > Monitoring > Diagnostic settings > Add diagnostic setting > check AADGraphActivityLogs > send to Log Analytics workspace
- [ ] **Build hunting query** for ROADtools/AADInternals UserAgent patterns once log is flowing -- reference Bader's queries as a starting point
- [ ] **Validate** `TimeRequested` vs `TimeGenerated` lag in your tenant before building scheduled analytics rules on this table

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created -- GA release of AADGraphActivityLogs, immediate action to enable |
