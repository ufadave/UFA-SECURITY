---
title: INTEL-SlimKQL-Copilot-External-Prompt-Attack-Detection-KQL
date: 2026-06-16
source: "https://github.com/SlimKQL/Detections.AI/blob/main/KQL/external-copilot-prompt-attack-detection-.kql"
author: "SlimKQL (Investigator Yong)"
mitre:
  - "T1567"
  - "T1078.004"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#cloud"
  - "#identity"
  - "#email"
---

# INTEL -- SlimKQL: External Copilot Prompt Attack Detection (KQL)

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/SlimKQL/Detections.AI/blob/main/KQL/external-copilot-prompt-attack-detection-.kql |
| **Author** | SlimKQL (Investigator Yong) -- Detections.AI mirror repo |
| **Date Observed** | 2026-06-16 |
| **Related Intel** | Directly relevant to Varonis SearchLeak (CVE-2026-42824) and EchoLeak (CVE-2025-32711) |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1567 | Exfiltration Over Web Service |
| T1078.004 | Valid Accounts: Cloud Accounts |

---

## Summary

SlimKQL (Investigator Yong) maintains a detection-focused KQL repository including
Detections.AI, covering Copilot and M365 AI threat patterns. The emailed KQL focuses
on detecting external prompt injection attacks against M365 Copilot -- the same attack
class Varonis demonstrated with SearchLeak (CVE-2026-42824).

The SlimKQL Hunting-Queries-Detection-Rules repo (from which Detections.AI mirrors)
contains several complementary Copilot security queries:

- **External Copilot prompt attack detection** -- the emailed query; detects Copilot
  activity initiated via crafted external URLs (the SearchLeak/P2P injection vector)
- **Detecting New Copilot Extensions** -- monitors for new Copilot extensions/plugins
  being registered, correlated against threat intelligence
- **Hunting Malicious Copilot Agent** -- detects compromised accounts creating Copilot
  agents on sensitive SharePoint sites for slow exfiltration
- **M365 Copilot Extensions Threat Monitoring** -- Sentinel analytics rule monitoring
  external URLs accessed by Copilot extensions against a TI database
- **Copilot Activities via AiTM token theft** -- correlates Copilot data access with
  new ISP logins (UEBA) to detect stolen-token abuse of Copilot

**Key dependency:** Several SlimKQL Copilot queries use the `CopilotActivity` Sentinel
table (from the Copilot data connector, public preview early 2026). This table must be
enabled before these detections can function.

**Underlying data source:**
`CopilotActivity` in Sentinel ingests from the Microsoft Purview Unified Audit Log (UAL),
which captures Copilot interactions including prompts, responses, data sources accessed,
and plugin/extension usage. Once enabled, it supports KQL hunting, analytics rules, and
automation playbooks.

---

## Relevance

Medium-High -- directly actionable if M365 Copilot is deployed in the environment.
If Copilot is not yet deployed, file as preparation for adoption governance.

The P2P injection detection from SlimKQL is specifically designed to surface the SearchLeak
attack class -- crafted external links causing Copilot to execute attacker-supplied
instructions. Combined with the `CopilotActivity` connector, this would surface any
future attempts to exploit this class of vulnerability even after the specific SearchLeak
CVE is patched (the underlying pattern remains exploitable via new variants).

---

## Detection Notes

### KQL Stubs

```kql
// Table: CopilotActivity (Sentinel -- requires Copilot data connector enabled)
// Schema: Sentinel / Log Analytics
// Purpose: Detect Copilot search activity initiated from external/crafted URLs --
// the SearchLeak / Parameter-to-Prompt injection attack pattern.
// NOTE: CopilotActivity connector must be enabled in Sentinel before this functions.
// Review actual SlimKQL query content before deploying -- this is a structural stub.

CopilotActivity
| where TimeGenerated > ago(1d)
| where EventSource == "CopilotSearch"
// Flag Copilot sessions where the originating URL contains query parameters
// inconsistent with normal Enterprise Search usage
| extend SearchQuery = tostring(parse_json(AdditionalDetails).SearchQuery)
| extend ReferrerUrl = tostring(parse_json(AdditionalDetails).ReferrerUrl)
| where isnotempty(ReferrerUrl)
| where ReferrerUrl !has "microsoft.com/search"  // normal Enterprise Search origin
// Flag external or unusual referrer domains
| where ReferrerUrl !has_any (
    "teams.microsoft.com", "outlook.office.com", "sharepoint.com",
    "office.com", "microsoft365.com"
)
| project TimeGenerated, UserId, SearchQuery, ReferrerUrl, AdditionalDetails
| order by TimeGenerated desc
```

### Validated Columns
- [ ] `CopilotActivity` table -- confirm connector is enabled and data is flowing
- [ ] `AdditionalDetails` field structure -- review actual SlimKQL query for correct field paths
- [ ] Verify `EventSource` / `EventType` values for Copilot Search activity in this tenant

---

## Hardening Actions

- [ ] Review actual SlimKQL `external-copilot-prompt-attack-detection-.kql` file content
  from the GitHub repo before building a production rule
- [ ] Enable the CopilotActivity Sentinel data connector if Copilot is deployed
- [ ] Assess whether the broader SlimKQL Copilot detection suite is relevant to current
  Copilot deployment posture

---

## Related Notes
- [[INFO-Varonis-SearchLeak-CVE-2026-42824-M365-Copilot-Exfiltration]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-16 | Created -- SlimKQL Copilot prompt attack detection; paired with SearchLeak INFO note; stub requires CopilotActivity connector |
