---
title: RESEARCH-AI-Coding-Tools-and-M365-Integration-Security-Summary
date: 2026-05-09
source: "Internal — Security Operations review"
author: "Security Operations"
detection_candidate: false
tags:
  - "#resource"
  - "#status/active"
  - "#identity"
  - "#cloud"
  - "#email"
  - "#action-required"
---

# RESEARCH — AI Coding Tools and M365 Integration: Security Summary

**Date:** 2026-05-09
**Prepared By:** Security Operations
**Status:** Active — ongoing dev team POC, policy gap open

---

## Context

Following a developer team POC connecting ChatGPT/Codex to Microsoft 365 via OAuth, Security Operations conducted a full review across four areas: the M365 OAuth connector risk, a comparison against Microsoft 365 Copilot as an alternative, the standalone Codex coding tool risk, and the current control posture. This note summarises all findings and open items in one place.

---

## What Was Reviewed

| Area | Output |
|------|--------|
| ChatGPT/Codex M365 OAuth connector — setup, risk, and monitoring | RESEARCH-ChatGPT-Codex-M365-Connector-POC-Setup-and-Security |
| KQL detection coverage for OAuth app activity | KQL-ChatGPT-Codex-OAuth-App-Monitoring |
| Technical risk assessment (security engineering audience) | Technical-Risk-Assessment-ChatGPT-Codex-M365.docx |
| Management risk briefing | Management-Risk-Briefing-ChatGPT-Codex-M365.docx |
| Head-to-head comparison: ChatGPT/Codex vs M365 Copilot | RESEARCH-AI-Assistant-Comparison-ChatGPT-Codex-vs-M365-Copilot |
| Comparison document (manager-shareable) | Security-Comparison-ChatGPT-Codex-vs-M365-Copilot.docx |

---

## Finding 1 — The M365 OAuth Connector Is the Highest Risk Item

The ChatGPT/Codex M365 OAuth connector grants OpenAI persistent delegated access to organisational email, files, Teams messages, and calendar data via Microsoft Graph API. This is not a Microsoft product — data leaves the tenant and transits OpenAI infrastructure.

**Key risks:**

- `Mail.ReadWrite` scope is present in the consent grant regardless of whether write actions are enabled in the OpenAI workspace. This creates a viable Business Email Compromise vector with no endpoint footprint — the entire attack chain executes via Graph API from OpenAI's infrastructure, generating no MDE signal.
- OAuth refresh tokens persist indefinitely until explicitly revoked. They are not tied to the user's Entra ID session. If a POC participant leaves without revocation, the access pathway remains live.
- User self-consent is not locked down by default. Any employee could independently connect their account — including high-privilege users — without admin knowledge.
- Detection coverage is partial. Consent grants and token issuance are capturable via AuditLogs and SigninLogs, but data access via Codex sessions requires MCAS session policy configuration that is not yet in place.
- The development team's OpenAI account tier has not been confirmed. If not Enterprise tier, organisational data submitted to Codex may be used for model training.

**MITRE:** T1078.004, T1114.002, T1530, T1550.001, T1566, T1586.002

---

## Finding 2 — Microsoft 365 Copilot Is a Materially Safer Alternative

M365 Copilot provides equivalent AI assistant functionality within the existing M365 security boundary. Key differences:

| Criterion | ChatGPT/Codex OAuth | M365 Copilot |
|-----------|---------------------|--------------|
| Data residency | Leaves tenant | Stays in tenant |
| Token model | Persistent external refresh tokens | Standard Entra ID session lifecycle |
| BEC risk | High — no endpoint telemetry | Reduced — within existing controls |
| Audit logging | Requires MCAS configuration | Native UAL (CopilotInteraction events) |
| DLP / sensitivity labels | Not enforced outside tenant | Enforced within M365 boundary |
| Conditional Access | Consent only | Per-session |
| Model training | Tier-dependent — unconfirmed | Prohibited — Microsoft Product Terms |
| OT/SCADA exclusion | No mechanism | Via sensitivity labels and site exclusions |
| Approx. cost | ~$30 USD/user/month | ~$30 USD/user/month add-on; E5 base in place |

SharePoint oversharing is the one shared risk — both tools surface content based on user permissions. Copilot keeps it in-tenant; ChatGPT sends it to OpenAI. A SharePoint access review is a prerequisite for either tool.

**Security recommendation:** Pivot the POC to M365 Copilot. If the goal is specifically Codex's agentic coding capabilities, evaluate that separately with a scoped, read-only POC on non-sensitive repositories.

---

## Finding 3 — Standalone Codex (Coding Tool) Is a Data Hygiene Problem

Codex is approved for developer use and Cisco Umbrella blocks unsanctioned generative AI broadly. The residual risk from approved Codex use is not an attack surface problem — it is a data hygiene problem.

**Actual risks:**

- **Secrets in prompts** — developers routinely paste code containing API keys, connection strings, and internal credentials without thinking. Highest-likelihood near-term risk.
- **Source code exfiltration** — proprietary code, internal libraries, detection logic, or OT/SCADA integration code submitted to Codex leaves the environment.
- **Internal architecture disclosure** — tenant names, internal DNS, IP ranges, and service names accumulate into reconnaissance material over time.

**Umbrella coverage gaps to be aware of:**
- Umbrella covers managed devices on managed network paths only. Personal devices, mobile hotspots, and off-VPN remote work are not covered.
- DNS-level telemetry from Umbrella can show which devices are hitting OpenAI API domains and at what volume — useful for anomaly detection even without content inspection.
- The approved access path (API key, CLI, IDE plugin, or browser) determines the actual exposure surface. This has not been documented as part of the approval.

**The approval has no documented conditions.** "Approved" without defined constraints on what can and cannot be submitted does not meaningfully reduce risk — it legitimises current behaviour without shaping it.

---

## Open Items

| # | Item | Priority | Owner |
|---|------|----------|-------|
| 1 | Confirm OpenAI account tier in writing — Enterprise vs Business/Team | High | Dev team owner |
| 2 | Lock down user OAuth self-consent in Entra ID — enable admin consent workflow | High | Security Operations |
| 3 | Confirm Mail.ReadWrite write actions disabled in OpenAI workspace settings | High | Dev team owner |
| 4 | Restrict ChatGPT service principal to POC group only (Assignment required = Yes) | High | Security Operations |
| 5 | Deploy Query 1 and Query 2 from KQL note as Sentinel analytics rules | High | Security Operations |
| 6 | Populate POC user watchlist and deploy Query 3 as High severity rule | Medium | Security Operations |
| 7 | Configure MCAS session policy for ChatGPT app — close CloudAppEvents gap | Medium | Security Operations |
| 8 | Build KQL for MailItemsAccessed — detect Graph API draft creation | Medium | Security Operations |
| 9 | Set formal POC end date with scheduled token revocation | Medium | Leadership / dev team |
| 10 | Attach written use conditions to the Codex approval — prohibit secrets and production code | Medium | Security Operations / management |
| 11 | Pull Umbrella logs for OpenAI API domains — baseline volume per device | Low | Security Operations |
| 12 | Audit whether OT/SCADA documentation resides in M365 before any AI tool deployment | High | Security Operations |
| 13 | SharePoint access review — prerequisite for any AI assistant deployment | High | Security Operations |
| 14 | Leadership decision: pivot POC to M365 Copilot? | High | Leadership |

---

## Control Posture Summary

| Control | Status |
|---------|--------|
| Cisco Umbrella — generative AI blocking | ✅ Active — covers managed devices |
| Codex — approved with limited access | ✅ Approved — no documented use conditions |
| Entra ID — user OAuth consent restriction | ❌ Not confirmed locked down |
| Entra ID — admin consent workflow | ❌ Not confirmed enabled |
| ChatGPT SP — restricted to POC group | ❌ Not yet applied |
| Mail.ReadWrite write actions — disabled | ❌ Not confirmed |
| Sentinel — OAuth consent monitoring | ⚠️ Queries built, not deployed as rules |
| MCAS — ChatGPT session policy | ❌ Not configured |
| MailItemsAccessed — draft creation detection | ❌ Not built |
| OT/SCADA content — M365 audit | ❌ Not completed |
| SharePoint permission review | ❌ Not completed |

---

## Hardening Actions (if M365 Copilot is Selected as the Path Forward)

- [ ] Complete SharePoint access review before enabling Copilot
- [ ] Apply sensitivity labels to OT/SCADA and plant-adjacent content — validate Copilot exclusion
- [ ] Configure site exclusions in M365 Admin Center for OT-adjacent SharePoint sites
- [ ] Validate CopilotInteraction events are flowing to Sentinel before rollout
- [ ] Build KQL anomaly hunting over CopilotInteraction events
- [ ] Confirm existing Conditional Access policies cover Copilot access surface

---

## Related Notes

- [[RESEARCH-ChatGPT-Codex-M365-Connector-POC-Setup-and-Security]]
- [[KQL-ChatGPT-Codex-OAuth-App-Monitoring]]
- [[RESEARCH-AI-Assistant-Comparison-ChatGPT-Codex-vs-M365-Copilot]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-09 | Created — summary of all AI tool security review work |
