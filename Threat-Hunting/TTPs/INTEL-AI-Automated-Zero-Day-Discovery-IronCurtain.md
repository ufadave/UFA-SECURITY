---
title: INTEL-AI-Automated-Zero-Day-Discovery-IronCurtain
date: 2026-05-05
source: "https://www.provos.org/p/finding-zero-days-with-any-model/"
author: "Niels Provos"
mitre:
  - "T1587.004"
  - "T1190"
detection_candidate: false
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#network"
---

# INTEL-AI-Automated-Zero-Day-Discovery-IronCurtain

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.provos.org/p/finding-zero-days-with-any-model/ |
| **Author** | Niels Provos |
| **Date Observed** | 2026-05-05 |
| **Date Published** | ~2026-04-28 |
| **Patch Available** | N/A — research / capability disclosure |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1587.004 | Develop Capabilities: Exploits |
| T1190 | Exploit Public-Facing Application |

---

## Summary

Researcher Niels Provos demonstrates that autonomous zero-day discovery does not require restricted frontier AI models — it is a function of the orchestration harness. Using the open-source IronCurtain framework (a finite-state machine YAML-driven agentic runtime), he replicated frontier-model vulnerability discovery results using commercial models (Claude Opus 4.6, Sonnet 4.6) and open-weight models (Z.AI GLM 5.1), finding net-new zero-days in foundational software now undergoing remediation. This is consistent with and complements Anthropic's own disclosure of Claude Mythos Preview autonomously finding and exploiting zero-days across major OS and browser targets. The practical implication is that the cost of zero-day discovery has dropped significantly and is no longer gated on access to restricted frontier models — commercial API access is sufficient given the right workflow scaffolding.

---

## Relevance to Environment

**Indirect but strategically important.** This is a threat landscape shift rather than an immediate operational indicator — it signals that adversaries (including well-resourced state actors like Handala/CL-STA-1128) are operating in an environment where automated vulnerability discovery is becoming accessible at lower cost and capability thresholds. The implication for your patch cadence is direct: the window between vulnerability existence and weaponized exploit is compressing. This reinforces shortening patch cycles on internet-facing and OT-adjacent systems. No immediate KQL detection stub is warranted, but the finding should inform threat model updates and the OT/SCADA vulnerability assessment timeline.

---

## Detection Notes

> `detection_candidate: false` — no specific IOC or behavioral signature to detect from this research. Threat model update, not an operational detection.

---

## Hardening Actions

- [ ] Note for threat model: reduce assumed patch window for critical CVEs — treat new critical/high CVEs as potentially weaponized within days, not weeks
- [ ] Ensure automated vulnerability scanning (OpenVAS, OT assessment tooling) is running on a schedule consistent with this compressed timeline
- [ ] Prioritize CopyFail (CVE-2026-31431) and any future Linux/Windows kernel LPEs accordingly

---

## Related Notes

- [[Threat-Hunting/TTPs/INTEL-Linux-CopyFail-CVE-2026-31431-LPE]]
- [[Projects/OT-SCADA-Assessment/]]

---

## Tags

#intel #status/draft #endpoint #network

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-05 | Created — AI-automated zero-day discovery capability disclosure |
