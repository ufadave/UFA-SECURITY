---
title: RESEARCH-AI-Assistant-Comparison-ChatGPT-Codex-vs-M365-Copilot
date: 2026-05-09
source: "https://help.openai.com/en/articles/11509118 | https://learn.microsoft.com/en-us/microsoft-365/copilot/microsoft-365-copilot-privacy | https://cyberdom.blog/the-hidden-risks-inside-chatgpt-in-entra-id/"
author: "Security Operations"
detection_candidate: true
tags:
  - "#resource"
  - "#vendor"
  - "#status/active"
  - "#identity"
  - "#cloud"
  - "#email"
  - "#action-required"
---

# RESEARCH — AI Assistant Comparison: ChatGPT/Codex M365 Connector vs Microsoft 365 Copilot for Office

**Date:** 2026-05-09
**Prepared By:** Security Operations
**Status:** Active — input for dev team POC decision
**Decision Required By:** TBD — pending leadership direction per management briefing 2026-05-08

---

## Context

A development team is evaluating ChatGPT/Codex as an AI assistant connected to the organisation's Microsoft 365 environment via OAuth. This note compares that integration against Microsoft 365 Copilot for Office (Copilot M365) as a safer alternative, across security, data handling, governance, and operational fit criteria relevant to this environment.

This note does not make a procurement recommendation — that requires a business case and licensing review outside the security scope. It provides the security risk differential to inform that decision.

---

## TL;DR — Security Posture Comparison

| Criterion | ChatGPT / Codex (OAuth) | Microsoft 365 Copilot |
|-----------|------------------------|----------------------|
| Data residency | Leaves tenant — transits to OpenAI infrastructure | Stays within M365 tenant / Azure boundary |
| Token model | External OAuth refresh tokens — persist until revoked | First-party session — standard Entra ID lifecycle |
| BEC risk | High — Mail.ReadWrite scope + no endpoint telemetry | Reduced — same M365 session controls apply |
| Audit logging | Gap — requires MCAS policy; no native UAL coverage | Native — CopilotInteraction events in UAL |
| DLP / sensitivity labels | Not enforced on ChatGPT-side processing | Enforced — Copilot respects M365 label policy |
| Conditional Access | Applies at consent only — not per-interaction | Applies per-session — standard CA policies |
| Model training risk | Depends on OpenAI tier — must confirm | No — Microsoft Product Terms prohibit it |
| Admin governance | OpenAI workspace admin + Entra ID consent | M365 Admin Center — fully integrated |
| OT/SCADA data exposure | No exclusion mechanism — all accessible content in scope | Scoped via sensitivity labels and site exclusions |
| SharePoint oversharing exposure | High — Files.Read.All enumerates all accessible content | High — same underlying permission model; requires permission audit pre-deployment |
| Existing stack integration | None — external product | Full — same tenant, same governance, same alerting |
| Canadian data residency | Not guaranteed — depends on OpenAI region | Yes — M365 Canadian data residency available |

**Overall security posture: M365 Copilot is materially lower risk for this environment across every critical criterion except SharePoint permission hygiene, which both tools share equally.**

---

## 1. Data Residency and Tenancy

### ChatGPT / Codex
When a user interacts with Codex using the M365 connector, the content of their query — which may include email excerpts, file content, or Teams messages retrieved via Graph API — is transmitted to OpenAI's infrastructure for processing. This data leaves the organisation's Microsoft 365 tenant boundary.

OpenAI's data handling commitment varies by account tier:
- **Free / Plus / Pro / Team:** Data may be used for model training unless opted out. Not appropriate for organisational use.
- **Business:** Opt-out from training available but requires explicit configuration. Data still leaves tenant.
- **Enterprise:** Contractual commitment — data not used for training. Strongest protection, but still leaves tenant.

The development team's current account tier has not been confirmed. This is a blocking issue for compliance purposes.

### Microsoft 365 Copilot
Copilot is built on Azure OpenAI Service operating within Microsoft's commercial cloud boundary. Prompts, retrieved content, and responses are processed within the tenant's Microsoft 365 compliance perimeter. The same data handling, retention, and legal hold policies that govern Exchange Online and SharePoint apply.

Microsoft's Product Terms explicitly prohibit using commercial customer data to train foundation models. This applies to all M365 commercial tenants — no tier dependency.

Canadian data residency is available through Microsoft's standard M365 data residency options. No equivalent commitment exists from OpenAI for Canadian organisations.

**Verdict: Copilot wins decisively. No data leaves the tenant. Canadian data residency available. Model training prohibition in Product Terms — no tier dependency.**

---

## 2. Authentication and Token Model

### ChatGPT / Codex
OAuth 2.0 delegated permissions. At first connection:
1. User or admin grants consent in Entra ID
2. A Service Principal is minted in the tenant for the ChatGPT app
3. Persistent OAuth **refresh tokens** are issued to OpenAI
4. These tokens authenticate all subsequent Graph API calls — they do not expire at session end
5. Tokens persist until explicitly revoked in Entra ID or by the user disconnecting in ChatGPT

This means if the dev team forgets to revoke tokens at POC close, or if a participant leaves the organisation before revocation, the access pathway remains live. There is no automatic expiry tied to the user's Entra ID session.

Known ChatGPT App ID: `e0476654-c1d5-430b-ab80-70cbd947616a`

### Microsoft 365 Copilot
First-party service — no external service principal, no external refresh tokens. Copilot operates using the user's active Entra ID session. When the session ends (logout, Conditional Access revocation, token lifetime policy), Copilot access ends with it. Leaver processes, Conditional Access policies, and token lifetime configurations all apply normally.

**Verdict: Copilot wins. Standard Entra ID session lifecycle. No orphaned external tokens. Leaver risk is managed through existing processes.**

---

## 3. Business Email Compromise Risk

This is the highest-severity risk differential between the two products.

### ChatGPT / Codex
The `Mail.ReadWrite` scope is present in the Entra ID consent grant regardless of whether write actions are enabled in the OpenAI workspace. The full BEC attack chain is documented in the Technical Risk Assessment (2026-05-08):

- Token compromise (via OpenAI infrastructure breach or session hijack) gives an attacker delegated mailbox access
- `Mail.Read` enables full mailbox reconnaissance — payment threads, vendor relationships, executive communications
- `Calendars.Read` enables timing intelligence — user absence windows
- `Mail.ReadWrite` enables draft creation mimicking the user's writing style (Codex has full mailbox context)
- Email sent from the legitimate account passes SPF, DKIM, and DMARC
- No MDE endpoint telemetry — attack executes entirely via Graph API from OpenAI's infrastructure
- No MDO signal — no malicious attachment, no suspicious link, legitimate sender

### Microsoft 365 Copilot
Copilot can also draft emails — that is a core feature. The risk profile is materially different:

- Attack requires compromise of the user's active M365 session, not an external OAuth token
- Draft creation is captured in the M365 Unified Audit Log (`CopilotInteraction` events)
- MDO has visibility — email drafted via Copilot still transits MDO on send
- Conditional Access applies to the session — MFA, compliant device, location policies all remain active
- No persistent external token to exfiltrate

The BEC vector is reduced to the same risk level as any other email client access. That is a meaningful difference — it brings Copilot inside the existing control envelope rather than bypassing it.

**Verdict: Copilot significantly lower risk. BEC is not eliminated — any write-capable mail client carries this risk — but Copilot operates within existing controls. ChatGPT OAuth introduces a bypass that has no endpoint footprint.**

---

## 4. Audit Logging and Detection Coverage

### ChatGPT / Codex

| Event | Coverage |
|-------|----------|
| OAuth consent grant | AuditLogs — capturable (Query 1 in KQL note) |
| Service principal creation | AuditLogs — capturable (Query 2) |
| Token issuance (sign-in) | SigninLogs — capturable (Query 3) |
| Data access via Codex session | CloudAppEvents — **requires MCAS session policy, not yet configured** |
| Draft email creation | MailItemsAccessed — **no KQL stub yet, detection gap** |
| Prompt injection via email content | **No viable automated detection** |

Detection requires active configuration work. The MCAS gap means data access patterns are currently invisible.

### Microsoft 365 Copilot

| Event | Coverage |
|-------|----------|
| Copilot interaction (prompt + response) | `CopilotInteraction` in Unified Audit Log — native, no config required |
| Files accessed during interaction | Logged with interaction event |
| Email content accessed | Logged with interaction event |
| Sensitivity label encounters | Logged — Copilot respects and logs label-blocked access attempts |
| Conditional Access events | Standard SigninLogs — same as any M365 access |

Native UAL coverage means hunting and anomaly detection are immediately available without additional tooling. KQL over `CopilotInteraction` events is the detection primitive — no MCAS dependency.

**Verdict: Copilot wins. Audit coverage is native and immediate. ChatGPT OAuth requires active MCAS configuration to achieve comparable visibility, and prompt-level logging is not achievable.**

---

## 5. DLP, Sensitivity Labels, and Conditional Access

### ChatGPT / Codex
Microsoft Purview DLP policies and sensitivity labels govern data within the M365 tenant. Once content is retrieved via Graph API and transmitted to OpenAI infrastructure, those controls no longer apply. A file labelled `Confidential` in SharePoint can be retrieved by Codex and processed outside the label enforcement boundary.

Conditional Access applies at the OAuth consent event — not per-interaction. Once consent is granted and tokens issued, subsequent Graph API calls are not gated by CA policies.

### Microsoft 365 Copilot
Copilot operates within the M365 compliance boundary. Sensitivity labels are respected — Copilot will not surface content from a label that the user's policy prohibits accessing, and label-blocked access attempts are logged. DLP policies apply to Copilot-generated content before it can be shared.

Conditional Access applies per-session — the same CA policies that govern Exchange Online and SharePoint apply to Copilot access. MFA, device compliance, and location restrictions all remain active.

**Verdict: Copilot wins. Full label and DLP enforcement. CA applies per-session, not just at consent.**

---

## 6. SharePoint Oversharing — Shared Risk

This is the one area where both tools carry equivalent risk, and it is significant.

Both ChatGPT/Codex (via `Files.Read.All` and `Sites.Read.All`) and Microsoft 365 Copilot surface content based on what the user has permission to access in SharePoint. If SharePoint permissions are poorly managed — broadly shared sites, broken inheritance, stale access, content shared "everyone" years ago — both tools will expose that content to the user through natural language queries.

Copilot keeps this exposure within the tenant. ChatGPT sends it to OpenAI. The risk category is the same; the blast radius is different.

**Pre-requisite for either tool:** A SharePoint access review and permission hygiene exercise is required before broad deployment of any AI assistant with SharePoint access. This is particularly relevant given the recently acquired fertilizer plant — any SharePoint or Teams content containing OT/SCADA network diagrams, process documentation, or plant operational data should be scoped out of AI assistant access via sensitivity labels or site exclusions before any deployment.

---

## 7. OT/SCADA Specific Risk

Neither tool has native OT/SCADA awareness. The risk is in what organisational data the AI assistant can reach.

### ChatGPT / Codex
No exclusion mechanism exists. Any SharePoint document, Teams message, or email accessible to a connected user — including OT/SCADA documentation, network diagrams, or Rockwell/Allen-Bradley configuration references — is within scope for retrieval and transmission to OpenAI infrastructure. If plant operational data is stored in M365 (which is not confirmed), this is a critical concern given the active Iranian APT threat targeting Rockwell equipment in this sector.

### Microsoft 365 Copilot
Sensitivity labels can be used to explicitly exclude OT/SCADA content from Copilot access. Microsoft's admin controls allow site-level exclusions from Copilot indexing. This provides a practical mechanism to protect OT-adjacent documentation that does not exist in the ChatGPT OAuth model.

**Action required:** Audit whether OT/SCADA documentation, network diagrams, or fertilizer plant operational data resides in M365 before enabling either tool. Apply `Highly Confidential` or equivalent labels to any such content and validate Copilot exclusion behaviour before deployment.

---

## 8. Governance and Admin Integration

### ChatGPT / Codex
Dual administration model — OpenAI workspace admin controls (Workspace Settings > Apps) and Entra ID consent management. These are separate control planes. A change in OpenAI's app (e.g., new scope request, write action enablement) requires action in both. Security visibility requires MCAS integration as an additional layer.

### Microsoft 365 Copilot
Single pane — M365 Admin Center. Copilot controls sit alongside Exchange, SharePoint, and Teams administration. Licensing, user assignment, and feature enablement are managed through existing M365 admin workflows. No separate vendor relationship for security governance.

**Verdict: Copilot wins. Integrated into existing governance model. No parallel admin plane.**

---

## 9. Licensing and Cost Consideration

> *Note: Security Operations does not make procurement decisions. This section is provided for completeness — a business case owner should validate current pricing.*

| Product | Licensing Model | Notes |
|---------|----------------|-------|
| ChatGPT / Codex | OpenAI Business ~$30 USD/user/month or Enterprise (custom) | Separate vendor relationship. Data handling tier matters — confirm before committing. |
| Microsoft 365 Copilot | M365 Copilot add-on — currently ~$30 USD/user/month | Requires M365 E3 or E5 base. Organisation already has E5 — add-on is the only incremental cost. |

At equivalent per-user cost, M365 Copilot provides significantly stronger security posture, integrated governance, and no data residency risk. The E5 base is already in place.

---

## 10. Decision Framework

For leadership and the dev team — the decision points from the management briefing apply here:

- [ ] **If the POC goal is AI-assisted productivity in Outlook and Teams:** M365 Copilot achieves this within the existing security boundary. Recommend pivoting the POC.
- [ ] **If the POC goal is specifically Codex's agentic coding capabilities:** That use case is distinct from M365 integration and should be evaluated separately with a scoped, read-only proof of concept on non-sensitive repositories.
- [ ] **If the POC continues with ChatGPT/Codex:** All controls from the Technical Risk Assessment (2026-05-08) must be in place. Mail.ReadWrite write actions must remain disabled. MCAS session policy must be configured before the POC produces meaningful data access.

---

## Hardening Actions (if M365 Copilot is selected)

- [ ] Run SharePoint access review before enabling Copilot — prioritise broadly shared sites and "everyone" permissions
- [ ] Apply sensitivity labels to OT/SCADA and plant-adjacent documentation — validate Copilot exclusion
- [ ] Configure site exclusions in M365 Admin Center for any OT-adjacent SharePoint sites
- [ ] Enable `CopilotInteraction` audit log retention — validate events are flowing to Sentinel
- [ ] Build KQL over `CopilotInteraction` for anomaly hunting — users querying unusual content, off-hours access, volume spikes
- [ ] Define a sensitivity label policy that maps to Copilot access tiers before broad rollout
- [ ] Confirm Conditional Access policies cover Copilot access surface (they should automatically — validate)

---

## Related Notes

- [[RESEARCH-ChatGPT-Codex-M365-Connector-POC-Setup-and-Security]]
- [[KQL-ChatGPT-Codex-OAuth-App-Monitoring]]
- [[Hardening/Controls/HARD-OAuth-App-Consent-Controls]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-09 | Created — security comparison to support dev team POC decision |
