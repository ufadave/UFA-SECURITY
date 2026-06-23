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

> ⚠️ **Schema corrected 2026-06-22.** Original stub used fields (`EventSource`, `ReferrerUrl`,
> `SearchQuery`, `AdditionalDetails`) that do not exist in actual `CopilotActivity` data.
> Rewritten against confirmed tenant schema from live data.

### Confirmed Schema (from tenant CSV, June 22 2026)

| Column | Type | Notes |
|--------|------|-------|
| `RecordType` | string | `CopilotInteraction`, `OutlookCopilotAutomation` |
| `ActorName` | string | UPN of the user |
| `AppHost` | string | `OutlookSidepane`, `Office`, `Word`, `Edge`, `Outlook` |
| `AppIdentity` | string | `Copilot.M365Copilot.Bizchat`, `Copilot.M365Copilot.WebChat` |
| `LLMEventData` | dynamic JSON | Contains `Messages[]`, `AccessedResources[]`, `AISystemPlugin[]`, `Contexts[]`, `JailbreakDetected` (per message), `ThreadId` |
| `AIModelName` | string | e.g. `gpt-53-medium` |
| `AgentName` | string | Populated when a Copilot agent is invoked |

**Fields that do NOT exist:** `EventSource`, `ReferrerUrl`, `SearchQuery`, `AdditionalDetails`

### KQL Stubs

```kql
// Table: CopilotActivity (Sentinel -- requires CopilotActivity data connector enabled)
// Schema: Sentinel / Log Analytics
// Purpose: Surface Copilot interactions where JailbreakDetected=true in any message --
// Microsoft's own jailbreak/prompt-injection signal. Most reliable detection available
// in this table for the SearchLeak / P2P injection attack class.

CopilotActivity
| where TimeGenerated > ago(1d)
| where RecordType == "CopilotInteraction"
| extend LLM = parse_json(LLMEventData)
| extend Messages = LLM.Messages
| mv-expand Message = Messages
| extend JailbreakDetected = tobool(Message.JailbreakDetected)
| where JailbreakDetected == true
| project
    TimeGenerated,
    ActorName,
    AppHost,
    AppIdentity,
    AgentName,
    AIModelName,
    ThreadId = tostring(LLM.ThreadId),
    MessageId = tostring(Message.Id),
    IsPrompt = tobool(Message.isPrompt)
| order by TimeGenerated desc
```

```kql
// Table: CopilotActivity (Sentinel)
// Schema: Sentinel / Log Analytics
// Purpose: Detect Copilot agents being invoked -- malicious agent creation on SharePoint
// sites is the slow-exfiltration pattern documented by SlimKQL. Alert on any agent
// invocation (AgentName populated) for baseline visibility and anomaly detection.

CopilotActivity
| where TimeGenerated > ago(1d)
| where RecordType == "CopilotInteraction"
| where isnotempty(AgentName)
| extend LLM = parse_json(LLMEventData)
| extend AccessedResources = LLM.AccessedResources
| mv-expand Resource = AccessedResources
| extend ResourceUrl = tostring(Resource.Url)
| summarize
    InteractionCount = count(),
    ResourcesAccessed = make_set(ResourceUrl, 20),
    AppHosts = make_set(AppHost, 5)
    by ActorName, AgentName, AgentId, AIModelName, bin(TimeGenerated, 1h)
| order by InteractionCount desc
```

```kql
// Table: CopilotActivity (Sentinel)
// Schema: Sentinel / Log Analytics
// Purpose: Inventory of data accessed via Copilot per user -- baseline and anomaly hunting.
// AccessedResources[] shows SharePoint/OneDrive content Copilot retrieved during interactions.
// Useful for investigating suspected exfiltration: what did Copilot actually touch?

CopilotActivity
| where TimeGenerated > ago(7d)
| where RecordType == "CopilotInteraction"
| extend LLM = parse_json(LLMEventData)
| extend AccessedResources = LLM.AccessedResources
| mv-expand Resource = AccessedResources
| extend ResourceUrl = tostring(Resource.Url)
| where isnotempty(ResourceUrl)
| summarize
    AccessCount = count(),
    UniqueResources = dcount(ResourceUrl),
    ResourceUrls = make_set(ResourceUrl, 50)
    by ActorName, AppHost, AppIdentity
| order by UniqueResources desc
```

### Validated Columns (confirmed against tenant CSV, 2026-06-22)

- [x] `RecordType` -- confirmed: `CopilotInteraction`, `OutlookCopilotAutomation`
- [x] `AppHost` -- confirmed: `OutlookSidepane`, `Office`, `Word`, `Edge`, `Outlook`
- [x] `LLMEventData` -- confirmed as JSON; parse with `parse_json(LLMEventData)`
- [x] `LLMEventData.Messages[].JailbreakDetected` -- confirmed field exists (bool)
- [x] `LLMEventData.Messages[].isPrompt` -- confirmed field exists (bool)
- [x] `LLMEventData.AccessedResources[]` -- confirmed field exists (array, may be empty)
- [x] `LLMEventData.AISystemPlugin[]` -- confirmed; e.g. `BingWebSearch` as BuiltIn plugin
- [x] `LLMEventData.ThreadId` -- confirmed field exists
- [x] `AgentName` -- confirmed field exists (empty when no agent invoked)
- [ ] `LLMEventData.AccessedResources[].Url` -- confirm field name for resource URLs
- [ ] `LLMEventData.Contexts[]` -- structure not yet inspected; may contain referrer context

---

## Hardening Actions

- [x] Review actual SlimKQL `external-copilot-prompt-attack-detection-.kql` file content
  from the GitHub repo before building a production rule
- [x] Enable the CopilotActivity Sentinel data connector if Copilot is deployed
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
| 2026-06-22 | Schema corrected -- original stub fields (EventSource, ReferrerUrl, SearchQuery, AdditionalDetails) do not exist in actual CopilotActivity data. Rewritten with 3 new queries against confirmed tenant schema: JailbreakDetected signal, agent invocation detection, and accessed-resources inventory. Validated against 10-row tenant CSV. |
