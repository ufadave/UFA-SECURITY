---
title: INFO-CopilotActivity-Sentinel-Connector-Evaluation
date: 2026-06-16
source: "https://windowsforum.com/threads/copilot-data-connector-for-microsoft-sentinel-public-preview-and-soc-benefits.400146/"
tags:
  - "#resource"
  - "#status/draft"
  - "#cloud"
  - "#action-required"
---

# INFO -- CopilotActivity Sentinel Data Connector: Evaluation and Recommendation

**Source:** https://windowsforum.com/threads/copilot-data-connector-for-microsoft-sentinel-public-preview-and-soc-benefits.400146/
**Microsoft Docs:** https://learn.microsoft.com/azure/sentinel/data-connectors-reference#microsoft-copilot
**Table schema:** https://learn.microsoft.com/azure/azure-monitor/reference/tables/copilotactivity
**Date:** 2026-06-16

---

## Background

Microsoft released a dedicated Copilot data connector for Microsoft Sentinel in public
preview (February 2026). It ingests Copilot audit records from the Purview Unified Audit
Log (UAL) into a Sentinel table called `CopilotActivity`, enabling KQL hunting queries,
analytics rules, and automation playbooks against AI-specific telemetry -- without
pivoting to the Purview portal.

**Evaluation triggered by:** Varonis SearchLeak disclosure (CVE-2026-42824, June 2026)
and SlimKQL Copilot external prompt attack detection (both processed in June 16 triage
session). Both detections depend on this connector being active.

---

## What It Ingests

The connector pulls a predefined set of record types from the UAL into `CopilotActivity`:

| RecordType | What It Captures |
|------------|-----------------|
| `CopilotInteraction` | Prompt/response metadata (not content), app host, model used |
| `Create/Update/Delete CopilotPlugin` | Plugin lifecycle events -- creation, modification, removal |
| `CreateCopilotWorkspace` | Agent workspace creation |
| `CopilotPromptBook` operations | Scheduled prompt creation and modification |
| `CopilotForSecurityTrigger` | Security Copilot trigger events |
| `CopilotAgentManagement` | Agent creation and configuration changes |

**Important:** `CopilotActivity` captures audit-log-style metadata, not raw prompt or
response content. The `LLMEventData` field contains parsed event metadata. This is
structured telemetry, not a content stream.

**Table attributes (confirmed from Microsoft docs):**
- Supports lake-only ingestion: **Yes** (cost optimisation path available)
- Supports ingestion-time DCR: **Yes**
- Basic log support: **Yes**
- Part of SecurityInsights solution

---

## Volume and Cost Assessment — 1,600 Users

Environment: ~1,600 Microsoft 365 users, Copilot for Microsoft 365 licensed.

Each `CopilotActivity` row is approximately 1–3 KB based on the schema (20 string/guid
fields, `LLMEventData` dynamic payload). Volume scales with active Copilot usage:

| Scenario | Active Users | Interactions/day | Rows/day | ~GB/day |
|----------|-------------|-----------------|----------|---------|
| Light (25% active, 5 interactions) | 400 | 2,000 | ~0.004 |
| Moderate (50% active, 20 interactions) | 800 | 16,000 | ~0.03 |
| Heavy (80% active, 50 interactions) | 1,280 | 64,000 | ~0.13 |

**Assessment:** Even at heavy usage, `CopilotActivity` generates well under 1 GB/day.
This is negligible relative to existing SigninLogs, AuditLogs, and DeviceEvents volumes.
Cost impact on the current Sentinel commitment tier will be minimal.

**Cost optimisation options:**
- **Analytics tier:** Standard Sentinel pricing, fully queryable, runs scheduled
  analytics rules. Required for detection rules targeting `CopilotActivity`.
- **Lake tier after 90 days:** Switch table to Basic/Lake tier for long-term retention
  beyond 90 days at significantly lower cost. Configure via Data Management > Tables.
- **No Azure Functions dependency:** This connector ingests directly from the Purview UAL
  (unlike some third-party connectors) -- no additional Azure Functions cost.

---

## Security Value

### Threat scenarios now detectable

**Prompt injection / SearchLeak-class attacks:**
CVE-2026-42824 (patched June 2026) demonstrated one-click silent data exfiltration via
a crafted Copilot Enterprise Search URL. The underlying P2P injection class persists --
future variants will exploit the same `CopilotInteraction` telemetry that `CopilotActivity`
captures. The SlimKQL external-copilot-prompt-attack detection requires this table.
See: [[INTEL-SlimKQL-Copilot-External-Prompt-Attack-Detection-KQL]]
See: [[INFO-Varonis-SearchLeak-CVE-2026-42824-M365-Copilot-Exfiltration]]

**Malicious Copilot agent creation:**
An attacker with a compromised account can create a Copilot agent on a sensitive
SharePoint site to slowly exfiltrate data via scheduled prompts. `CopilotAgentManagement`
and `CreateCopilotWorkspace` events in `CopilotActivity` are the detection signal.
Without the connector, this is invisible in Sentinel.

**Unexpected plugin deployment:**
`Create/Update CopilotPlugin` events surface new or modified plugins -- a signal for
either supply-chain compromise (malicious plugin) or insider threat. Plugin monitoring
is one of the primary use cases Microsoft documents for this connector.

**AiTM token theft → Copilot abuse:**
A stolen token used for Copilot interactions (data summarisation, file access) generates
`CopilotInteraction` events that, combined with anomalous ISP/location data from
SigninLogs (UEBA), produce a correlated detection. The SlimKQL "Copilot Activities via
AiTM token theft" query demonstrates this correlation pattern -- directly relevant given
the recent AiTM BEC incident.

---

## Recommendation

**Enable the connector.** With 1,600 users and Copilot already licensed, the risk
surface is live and currently invisible in Sentinel. The cost impact is minimal. The
detection value -- particularly Copilot agent creation monitoring, plugin lifecycle
events, and prompt injection detection -- is high relative to ingestion cost.

**Configuration approach:**
- Ingest into **Analytics tier** for active detection rules
- Set **table-level retention to 90 days** in Analytics tier, then move to Lake tier
  for historical retention (Data Management > Tables)
- Install from **Sentinel Content Hub** (Microsoft Copilot solution)
- Requires **Global Administrator or Security Administrator** to enable

---

## Prerequisite Check

Before enabling the connector, confirm:

- [ ] **Purview audit logging is enabled** -- the connector pulls from the UAL. Verify in
  Purview compliance portal: Audit > confirm "Recording user and admin activity" is active.
  For E5 tenants this should already be enabled, but worth confirming explicitly.
- [ ] **Copilot interactions are captured in the UAL** -- run a test interaction with Copilot
  and check the UAL for `CopilotInteraction` records within 30 minutes.
- [ ] **Sentinel Content Hub** -- confirm the "Microsoft Copilot" solution is available and
  install it before enabling the data connector.

---

## Actions

- [ ] Confirm Purview UAL audit logging is active and capturing Copilot events
- [ ] Install Microsoft Copilot solution from Sentinel Content Hub
- [ ] Enable the CopilotActivity data connector
- [ ] Configure table-level retention: 90 days Analytics tier, then Lake tier
- [ ] After 7 days, run a baseline query to confirm data is flowing:
  `CopilotActivity | summarize count() by RecordType | order by count_ desc`
- [ ] Build detection rules from [[INTEL-SlimKQL-Copilot-External-Prompt-Attack-Detection-KQL]]
  once telemetry is confirmed

---

## Related Notes

- [[INFO-Varonis-SearchLeak-CVE-2026-42824-M365-Copilot-Exfiltration]]
- [[INTEL-SlimKQL-Copilot-External-Prompt-Attack-Detection-KQL]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-16 | Created -- connector evaluation for 1,600-user Copilot-licensed environment; volume modelled; recommendation: enable with lake-tier retention after 90 days |
