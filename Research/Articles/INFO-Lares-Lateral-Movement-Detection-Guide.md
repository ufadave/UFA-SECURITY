---
title: INFO-Lares-Lateral-Movement-Detection-Guide
date: 2026-06-01
source: "https://www.lares.com/blog/what-is-lateral-movement/"
tags:
  - "#resource"
  - "#status/draft"
  - "#network"
  - "#endpoint"
  - "#identity"
---

# INFO -- Lares: The Lowdown on Lateral Movement

**Source:** https://www.lares.com/blog/the-lowdown-on-lateral-movement/
**Date:** 2026-06-01
**Author:** Lares

---

## What It Is

Practitioner-oriented deep dive into lateral movement from both offensive and defensive perspectives, covering all nine MITRE ATT&CK lateral movement techniques and sub-techniques. Structured around the "why" of lateral movement — what it tells defenders about adversary goals and constraints — and provides actionable defensive guidance for each technique including telemetry requirements, detection logic anchors, and Sysmon/MDE equivalents.

Key framing: observed lateral movement technique reveals adversary approach and constraints (e.g. lack of SMB access forces WMI; presence of Kerberoastable accounts enables pass-the-ticket). Defenders can use technique selection as a predictive signal for next steps.

---

## Relevance

High — directly applicable to active IR cases (FIND-IR-2026-05-07-lt13069, AiTM BEC) and the current detection engineering backlog. The Impacket IOC note from earlier this week (INFO-Dissecting-Impacket-IOCs-Detection) covered protocol-level indicators; this article provides the broader detection framework for each technique class. Useful reference for building out the gap detected in the HUNT-GapAnalysis note.

**Most relevant technique sections for current environment:**
- Pass-the-Hash / Pass-the-Ticket — hybrid AD environment with on-prem AD via Entra Connect
- Remote Services (SMB/WinRM/RDP) — primary lateral movement paths in Windows AD estate
- WMI lateral movement — high-value detection gap given WMIExec is the Impacket default

---

## Actions

- [ ] File as reference for lateral movement detection engineering
- [ ] Cross-reference with INFO-Dissecting-Impacket-IOCs-Detection for combined WMIExec/SMBExec detection coverage

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-01 | Created |
