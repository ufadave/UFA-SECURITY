---
title: INFO-Cisco-Secure-Access-Feature-Evaluation-2026-05
date: 2026-05-28
source: "https://www.cisco.com/c/en/us/products/collateral/security/secure-access/secure-access-ds.html"
tags:
  - "#resource"
  - "#status/draft"
  - "#vendor"
  - "#network"
  - "#identity"
  - "#endpoint"
---

# INFO -- Cisco Secure Access: Feature Evaluation (Migration from Umbrella)

**Source:** Cisco Secure Access documentation and product briefs
**Date:** 2026-05-28

---

## What It Is

Feature assessment of Cisco Secure Access (SSE platform) relative to the previous
Cisco Umbrella deployment. Covers capabilities now available that were not present
in Umbrella, with relevance ratings for the current E5 hybrid environment.

---

## New Capabilities vs Umbrella

### Universal ZTNA — High Priority

Umbrella provided DNS security and SWG only. Secure Access adds proper Zero Trust
Network Access for private application connectivity. Users authenticate through Entra ID
with Intune device compliance checked before granting access to internal resources —
replacing traditional VPN for most use cases. Directly supports the CA policy refactor
in progress.

**Entra ID and Intune integration:** Secure Access authenticates against Entra ID and
supports Entra ID External Authentication Methods (EAM) plus Intune device compliance
as a ZTNA policy condition. Also supports Entra ID user/group provisioning (released
May 11, 2026) — keeps Secure Access policy targeting in sync with Entra ID groups
automatically.

**Trusted Network Detection (released March 2026):** Client detects when users are on
a trusted corporate network vs remote and adjusts ZTNA enforcement accordingly —
eliminates split-tunnel VPN exceptions.

---

### Realtime DLP — High Priority

DLP integrates with Azure Storage and other Microsoft services to control data
exfiltration risk including Azure key and secrets exposure. Provides granular ingress
and egress control of AI-generated and AI-reviewed code both via API and web
interfaces. Directly relevant to the active ChatGPT admin consent finding and the
broader AI tool exposure surface.

---

### AI Application Discovery and Guardrails — Medium Priority

Visibility into what AI services users are accessing across the estate, with usage
guardrails including prompt injection detection, how-to-harm prompt blocking, and
toxic content filtering. Provides a policy enforcement layer on top of OAuth scope
controls. Relevant given active ChatGPT, Codex, and Copilot deployments and the
NSA MCP guidance (May 2026).

---

### Remote Browser Isolation (RBI) — Medium Priority

Web content executes in a remote cloud environment; only a visual stream reaches
the endpoint. Malware, drive-by downloads, and browser exploits never touch the
managed device.

**Advanced Isolation Controls (Menlo Security partnership, March 2026):**
Beyond basic RBI, Secure Access now supports:
- **Copy/paste restrictions** — users can view content but cannot exfiltrate it via clipboard
- **Read-only browsing mode** — prevents interaction with page content
- **Print control** — blocks printing of sensitive web content
- **Document isolation** — safe viewing of documents without local download
- **Watermarking** — discourages misuse of viewed content

**Recommended deployment pattern:** Policy-based, not blanket. Apply to uncategorised
or risky sites, unmanaged/contractor devices, AI services (ChatGPT, Copilot via web),
and high-risk roles (finance, HR, executives). RBI degrades user experience on
media-heavy or complex web apps — selective application is the right posture.

**Use cases for this environment:**
- Route uncategorised Talos-rated sites through RBI rather than hard-blocking
- AI tool access with copy/paste restrictions and DLP inspection as a complement
  to OAuth scope reduction
- Contractor or unmanaged device access without requiring Intune enrollment

---

### Cisco XDR Integration — Medium Priority

Integration with Cisco XDR provides complete visibility into internet activity across all
users and locations, enabling faster identification of infected devices and prevention
of data exfiltration. Useful if XDR is in the roadmap, but not an immediate priority
given existing Sentinel/MDE SIEM coverage.

---

## Priority Summary

| Feature | Priority | Notes |
|---------|----------|-------|
| Universal ZTNA + Entra ID/Intune integration | High | Supports CA refactor; replaces VPN |
| Realtime DLP | High | AI code control; Azure key protection |
| Entra ID user provisioning (May 2026) | High | Enable to keep policy in sync |
| Trusted Network Detection (March 2026) | High | Enable alongside ZTNA |
| AI app discovery and guardrails | Medium | Complements ChatGPT scope reduction |
| RBI advanced isolation controls | Medium | AI tools + uncategorised sites |
| Cisco XDR integration | Low | Defer; Sentinel/MDE covers current needs |

---

## Actions

- [ ] Confirm whether Universal ZTNA is enabled and configured for Entra ID auth + Intune compliance
- [ ] Confirm whether RBI is included in current Secure Access license tier or requires add-on
- [ ] Enable Entra ID user/group provisioning to Secure Access if not already active
- [ ] Evaluate AI app discovery policy for ChatGPT and Codex visibility
- [ ] Consider RBI policy for AI web services as complement to ChatGPT scope reduction work

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-28 | Created — post-migration feature assessment following move from Cisco Umbrella |
