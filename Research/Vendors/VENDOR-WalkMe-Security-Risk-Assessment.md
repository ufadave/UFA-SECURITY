---
title: "WalkMe — Security Risk Assessment"
date: 2026-05-14
vendor: WalkMe (SAP)
product: WalkMe Digital Adoption Platform + Browser Extension
category: Other
eval_status: Researching
decision_date:
tags:
  - "#resource"
  - "#vendor"
  - "#status/draft"
  - "#endpoint"
  - "#cloud"
  - "#action-required"
---

# WalkMe — Security Risk Assessment

**Date:** 2026-05-14
**Vendor:** WalkMe (acquired by SAP, September 2024)
**Product:** WalkMe Digital Adoption Platform + Browser Extension (Chrome / Edge)
**Category:** Digital Adoption Platform (DAP)
**Eval Status:** Researching

---

## Overview

WalkMe is a Digital Adoption Platform that overlays interactive guidance, tooltips, and workflow automation on top of web applications. It is deployed either via a JavaScript snippet injected into application source code, or — more commonly in enterprise environments — via a force-installed browser extension (Chrome / Edge). The extension is the primary deployment vector when organisations cannot modify application source code directly. WalkMe was acquired by SAP in September 2024.

---

## Why This Review Exists

A request was received to assess the security risks of deploying WalkMe, with specific emphasis on the browser extension component. This note documents identified risks, required controls, and open questions before any deployment decision is made.

---

## Extension Architecture — What It Actually Does

Understanding the risk requires understanding how the extension operates:

- **Injection model:** The extension injects WalkMe's JavaScript overlay into web pages at the browser level, bypassing the need for server-side code changes. URL matching is performed locally in the browser before injection — no URL data is transmitted for matching.
- **Permissions granted (Chrome/Edge):** `browsingData`, `webRequest`, `webRequestBlocking`, `tabs`, `storage`, `cookies`, `scripting`, `offscreen`, `declarativeNetRequestWithHostAccess`, and broad host permissions covering `http://*/*` and `https://*/*`.
- **Data telemetry backend:** Analytics data is sent to WalkMe's GCP-hosted backend. A Canadian data centre option exists.
- **Deployment:** Machine-level (all users on a device) or user-level. Force-installed via GPO / Intune MDM policy — users cannot remove or disable it.
- **Manifest V3:** WalkMe has migrated to Manifest V3, the current Chrome extension security standard. This is a positive — MV3 imposes stricter security constraints than the legacy MV2.

---

## Risk Register

### R1 — Overprivileged Extension Permissions (HIGH)

**Risk:** The extension requests permissions that collectively enable read/write access to all browsing data across all HTTP/HTTPS sites — not just the applications WalkMe is configured for. Permissions include:

| Permission | Risk |
|---|---|
| `webRequest` / `webRequestBlocking` | Can intercept and inspect all HTTP/S requests in the browser, including authenticated sessions, tokens, and API calls |
| `scripting` | Can inject arbitrary JavaScript into any page |
| `cookies` | Can read cookies for any domain |
| `browsingData` | Can clear browsing data |
| `tabs` | Can enumerate all open tabs and track browsing history |
| `http://*/* https://*/*` | Host permissions covering every site, not limited to WalkMe-configured apps |

**Assessment:** The extension's reach extends well beyond the applications it is configured to guide users through. A compromised or maliciously updated extension would have the capability to harvest authentication tokens, session cookies, and page content from every application a user visits — including Sentinel, Entra ID admin portals, POS management interfaces, and Intune.

**Likelihood modifier:** WalkMe itself is not assessed as currently malicious. The risk is primarily supply chain — a compromised update to the extension, a build pipeline compromise at WalkMe/SAP, or a future policy change post-acquisition.

---

### R2 — Supply Chain / Extension Update Risk (HIGH)

**Risk:** Browser extensions auto-update by default. A malicious update pushed from WalkMe's extension infrastructure (Chrome Web Store / Edge Add-on Store) would deploy automatically to all managed endpoints with no intervention required.

**Context:** This is not theoretical. Barracuda Networks documented a mid-2025 campaign where extensions in official Chrome and Edge stores — with good reputations and positive reviews — had malicious code introduced via update, turning them into surveillance tools. Extensions in the DarkSpectre campaign remained benign for five or more years before being weaponised. WalkMe's extension was last updated December 2025 (Chrome) and is actively maintained.

**Assessment:** The auto-update model means the extension's security posture at deployment time is not the posture it will have in six months. This is a standing risk for any force-deployed extension, but the blast radius here is high given the permission set (R1).

---

### R3 — Data Collection Scope (MEDIUM–HIGH)

**Risk:** WalkMe's analytics capabilities extend significantly beyond basic guidance telemetry, depending on which features are enabled:

| Feature | Data Collected |
|---|---|
| Engagement Analytics (default on) | WalkMe content interaction events, page URLs, page titles, browser type, OS, IP address (pseudonymised), approximate geolocation |
| Digital Experience Analytics (DXA) | All user interactions with HTML elements — clicks, input changes, page views — across configured applications |
| Session Playback | Full DOM capture, asset copies, real-time session replay sent to WalkMe servers |
| Discovery (optional) | Application usage by user, hashed or identified email addresses, role data |

**Assessment:** With DXA or Session Playback enabled, WalkMe effectively has keylogger-class visibility into user activity within configured applications. The vendor states passwords are never recorded and input fields can be masked — but this depends on correct configuration. By default, page URLs and page titles are transmitted, which can be disabled on request. The distinction between "what WalkMe collects by default" and "what WalkMe can collect if misconfigured or fully enabled" is significant and must be documented before deployment.

**Canadian data centre:** WalkMe does offer a Canadian data centre. This must be explicitly requested and contractually confirmed — account location does not automatically determine data centre assignment.

---

### R4 — Session Playback as Credential/PII Exposure Vector (HIGH if enabled)

**Risk:** Session Playback captures everything occurring in the DOM and transmits it to WalkMe servers. Configured applications that display sensitive data — financial records, HR data, POS transaction data, operational parameters — would have that data replicated off-premises. While WalkMe provides censorship controls (mask by HTML ID / class name), these require ongoing maintenance as applications update. Any uncensored sensitive field becomes part of the session replay dataset.

**Assessment:** Session Playback should be treated as a data exfiltration risk equivalent to a screen recording tool with cloud upload. It must be disabled unless there is a specific, justified use case with a full data mapping exercise completed first.

---

### R5 — MDE / Defender for Endpoint Visibility Gap (MEDIUM)

**Risk:** The extension operates at the browser layer. MDE's process-level telemetry will capture the browser process, but the extension's in-browser activity — intercepted requests, injected scripts, data submissions to WalkMe's GCP backend — is largely opaque to MDE. Network-level egress to WalkMe's CDN/GCP endpoints will be visible in `DeviceNetworkEvents`, but the content is TLS-encrypted.

**Assessment:** Existing MDE coverage does not provide meaningful visibility into what the WalkMe extension is doing at runtime. Dedicated extension monitoring or browser telemetry (e.g., Defender for Endpoint browser extensions policy visibility, or a CASB-level proxy with TLS inspection) would be needed to close this gap.

---

### R6 — SAP Acquisition — Governance and Roadmap Risk (MEDIUM)

**Risk:** WalkMe was acquired by SAP in September 2024 for approximately $1.5B USD. Post-acquisition, several risks emerge: product roadmap may shift toward SAP ecosystem customers, support quality may degrade for non-SAP environments, pricing models may change, and contractual terms (including DPA and data handling obligations) may be renegotiated under SAP's standard terms. The vendor's security team and incident response commitments inherited from pre-acquisition WalkMe are now subject to SAP's governance model.

**Assessment:** No confirmed negative incidents post-acquisition, but the acquisition represents a meaningful governance change. Any existing WalkMe contracts or new agreements should be reviewed against SAP's terms. Request an updated DPA reflecting SAP ownership.

---

### R7 — Third-Party Cookie Dependency (LOW–MEDIUM)

**Risk:** WalkMe documentation explicitly states that most configurations require third-party cookies to be enabled in the browser for WalkMe content to load. Browser hardening that blocks third-party cookies (which is increasingly a default in Chromium-based browsers) can break WalkMe functionality. This creates pressure to relax browser cookie controls on managed endpoints.

**Assessment:** If Conditional Access or browser hardening policies block third-party cookies, WalkMe may require per-site exceptions. Document which applications require this exception and review against your cookie policy.

---

## Required Controls Before Deployment

- [ ] **Scope-limit extension activation** — Use WalkMe's URL allowlisting to restrict extension injection to explicitly approved applications only. Verify this is enforced at the extension level, not just the WalkMe console.
- [ ] **Disable Session Playback** — Contractually and in WalkMe console configuration. Confirm it cannot be re-enabled without a change process.
- [ ] **Disable or scope DXA** — If DXA is required, configure page-level exclusions for any pages displaying PII, financial data, credentials, or operational parameters.
- [ ] **Confirm Canadian data centre** — Obtain written confirmation from WalkMe/SAP that data is stored in the Canadian DC. Request the DPA reflecting SAP ownership.
- [ ] **Request page URL/title collection opt-out** — Per WalkMe documentation, this is available on request. Submit the request before go-live.
- [ ] **Pin extension version or gate auto-updates** — Evaluate whether Intune / browser policy can pin the extension version. At minimum, monitor Chrome Web Store / Edge Add-on Store for WalkMe extension updates and review changelogs before auto-propagation.
- [ ] **Deploy via Intune MDM policy** — Force-install via managed browser policy (do not rely on user self-install). This ensures the correct version is deployed and provides an enforcement mechanism.
- [ ] **Egress monitoring** — Create a Sentinel or MDE detection on outbound connections from managed endpoints to WalkMe's CDN and GCP endpoints. Establish a baseline of normal egress volume. Alert on anomalous spikes.
- [ ] **Review DPA and data processing terms** — Obtain SAP/WalkMe DPA, confirm data processor obligations, verify sub-processor list, and confirm breach notification timelines.
- [ ] **Confirm Manifest V3 status** — Verify the deployed extension version is MV3-compliant. At time of writing, WalkMe has migrated to MV3.

---

## KQL Detection Pair — WalkMe Egress Monitoring

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound connections to WalkMe CDN / GCP analytics endpoints from managed endpoints
// Tune: Add known WalkMe domains to the allowlist after baselining; alert on new or unexpected destinations

DeviceNetworkEvents
| where TimeGenerated >= ago(24h)
| where RemoteUrl has_any ("walkme.com", "walkmeusercontent.com", "storage.googleapis.com")
    or RemoteIP has_any ("walkme") // Update with actual IP ranges after baselining
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP, RemotePort, LocalPort
| order by TimeGenerated desc
```

> **Note:** WalkMe backend is hosted on GCP. `storage.googleapis.com` is a broad domain — refine to WalkMe-specific subdomains after baselining egress from a test device. WalkMe's specific analytics endpoints should be obtainable from their security whitepaper or network traffic capture during POC.

### Validated Columns
- [ ] `RemoteUrl` — confirm availability in your MDE schema (vs `RemoteIP` only)
- [ ] `InitiatingProcessFileName` — should be `chrome.exe` or `msedge.exe`
- [ ] `RemoteIP` — supplement with WalkMe CDN IP ranges from vendor

---

## Fit Assessment

| Criterion | Notes |
|---|---|
| Covers OT/SCADA? | Not applicable — WalkMe is a web/desktop DAP, not an OT tool |
| MDE/Sentinel integration | No native integration; egress monitoring via KQL is the available approach |
| Entra ID / Intune compatible | Yes — force-install via Intune browser policy is the recommended deployment path |
| On-prem / hybrid support | Extension operates on managed endpoints regardless of identity model |
| Pricing model | ~$79K USD/year average for enterprise; pricing opacity is a documented concern |
| Vendor HQ / data residency | US-headquartered (SAP Germany parent); Canadian data centre available — must be requested explicitly |
| Canadian data residency option | Yes — confirmed. Must be contractually specified. |

---

## Certifications

| Certification | Status |
|---|---|
| SOC 2 Type II | Confirmed |
| ISO 27001 | Confirmed |
| FedRAMP Ready | Confirmed |
| HIPAA | Confirmed |
| GDPR (as processor) | Confirmed |
| CCPA | Confirmed |
| PIPEDA / Canadian privacy law | Not explicitly confirmed — raise with vendor |

---

## Open Questions for Vendor

- [ ] Confirm Canadian data centre assignment in writing and provide the specific DC location
- [ ] Provide updated DPA reflecting SAP acquisition (September 2024)
- [ ] Provide full sub-processor list
- [ ] Confirm extension update process — is there a customer notification mechanism before an update is pushed?
- [ ] Confirm whether extension version pinning is supported under Intune MDM deployment
- [ ] Provide the WalkMe Security Whitepaper (available via support.walkme.com under security compliance)
- [ ] Confirm Session Playback is disabled at the account level — not just unconfigured
- [ ] Clarify breach notification timeline under SAP ownership
- [ ] Confirm PIPEDA compliance posture for Canadian operations

---

## Weaknesses / Concerns

- Overprivileged extension permissions with no effective scoping to configured apps only at the OS level — relies on WalkMe's own URL filtering
- Auto-update model creates a standing supply chain risk with no customer-side gating mechanism confirmed
- Session Playback feature is a data exfiltration risk if enabled — requires contractual and console-level disable
- Post-SAP acquisition governance change introduces uncertainty on DPA, support, and roadmap
- MDE provides no meaningful in-browser visibility into extension activity at runtime
- Third-party cookie dependency may create pressure to relax browser hardening

## Strengths

- SOC 2 Type II, ISO 27001, FedRAMP Ready certifications provide a reasonable compliance baseline
- Manifest V3 migration completed — a positive signal for extension security posture
- Canadian data centre available
- URL matching performed locally (not server-transmitted) for extension activation scoping
- Configurable data collection levels — DXA and Session Playback are not on by default

---

## Decision

**Outcome:** Deferred pending vendor responses to open questions and contractual review
**Rationale:** Extension permission scope and supply chain update risk are not acceptable without additional controls. Session Playback must be contractually disabled. Canadian DC must be confirmed in writing.
**Decision Date:**

---

## Related Notes

- [[]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-14 | Created — initial risk assessment |
