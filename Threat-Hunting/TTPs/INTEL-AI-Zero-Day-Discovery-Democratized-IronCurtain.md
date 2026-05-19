---
title: INTEL-AI-Zero-Day-Discovery-Democratized-IronCurtain
date: 2026-05-18
source: "https://www.provos.org/p/finding-zero-days-with-any-model/"
author: "Niels Provos"
mitre:
  - "T1587.001 — Develop Capabilities: Malware"
  - "T1588.006 — Obtain Capabilities: Vulnerabilities"
detection_candidate: false
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#cloud"
  - "#action-required"
---

# INTEL-AI-Zero-Day-Discovery-Democratized-IronCurtain

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.provos.org/p/finding-zero-days-with-any-model/ |
| **Author** | Niels Provos |
| **Date Observed** | 2026-05-18 |
| **Date Published** | 2026-05-02 |
| **Patch Available** | N/A — strategic awareness item |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1587.001 | Develop Capabilities: Malware |
| T1588.006 | Obtain Capabilities: Vulnerabilities |

---

## Summary

Niels Provos (formerly Google, Honeyd author) published research demonstrating that AI-driven zero-day discovery is not limited to restricted frontier models — it is fundamentally an orchestration problem. Using his open-source IronCurtain framework (finite-state machine-based agent orchestration via YAML) with commercial models including Claude Sonnet 4.6 and Opus 4.6, he replicated Anthropic's finding of a 1998 OpenBSD TCP SACK vulnerability and discovered new zero-days in widely deployed software, with per-codebase scan costs of $30–$150. This follows Google GTIG's separate disclosure that a criminal threat actor used AI to develop a zero-day exploit in the wild — identifiable by hallucinated CVSS scores and educational docstrings in the exploit code. The implication is that the technical barrier to novel vulnerability discovery is now low enough for well-resourced threat actors and sophisticated criminals.

---

## Relevance to Environment

Strategic relevance rather than tactical. The primary implication for your environment is patch velocity — the window between vulnerability existence and exploitation is compressing as AI-assisted discovery matures. Your hybrid environment, OT/SCADA assets, and Rockwell/Allen-Bradley PLCs (which receive infrequent vendor patches) are at elevated risk as this capability proliferates. This also reinforces your existing threat model for Iranian APT groups (Handala/CL-STA-1128), who are well-resourced and likely exploring or already using AI-assisted techniques. There is no direct detection candidate here — the detection opportunity is in the resulting exploit activity, not the discovery process itself. Priority action: review patch SLA for OT assets given shrinking exploitation windows.

---

## Detection Notes

> `detection_candidate: false` — No KQL stubs. The threat is strategic (accelerated vuln discovery pipeline), not a specific TTP with detectable artifacts at this time. Monitor for AI-assisted exploit signatures (hallucinated CVSS scores in payload metadata, unusual docstring patterns in script-based exploits found during IR).

---

## Hardening Actions

- [ ] Review patch SLA for OT/SCADA assets — if currently quarterly, consider moving to monthly or risk-tiered
- [ ] Ensure Defender Vulnerability Management covers all Intune-enrolled endpoints for expedited patch prioritisation
- [ ] Bookmark IronCurtain (github.com/provos/ironcurtain) as a potential internal red team / detection engineering tool — $30-150/scan is operationally accessible

---

## Related Notes

- [[]]

---

## Tags

#endpoint #cloud

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-18 | Created |
