---
title: "VENDOR-Illumio-ZTS-Evaluation"
date: 2026-04-30
vendor: Illumio
product: Illumio Zero Trust Segmentation (ZTS) / Illumio Insights
category: OT-Security
eval_status: Researching
decision_date: 
tags:
  - "#resource"
  - "#vendor"
  - "#ot-scada"
  - "#network"
  - "#status/draft"
  - "#action-required"
---

# Illumio Zero Trust Segmentation — Vendor Evaluation

**Date:** 2026-04-30
**Vendor:** Illumio
**Product:** Illumio Zero Trust Segmentation (ZTS) + Illumio Insights (CDR)
**Category:** Microsegmentation / OT Security / Breach Containment
**Eval Status:** Researching
**Priority Driver:** OT/SCADA network segmentation unconfirmed at fertilizer plant + active Iranian APT targeting Rockwell/Allen-Bradley PLCs

---

## Overview

Illumio is a microsegmentation platform built around the concept of Zero Trust Segmentation (ZTS) — the principle that once an attacker is inside, lateral movement must be contained regardless of where the breach started. The platform has two primary components: **Illumio Segmentation** (policy enforcement and east-west traffic control) and **Illumio Insights** (AI-powered cloud detection and response built on an AI security graph). Both are now available via the Microsoft Security Store with native Sentinel integration.

Illumio is a Forrester Wave Leader for Microsegmentation and a 2026 Gartner Peer Insights Customers' Choice for Network Security Microsegmentation.

---

## Problem It Solves

Your environment has two converging problems:

1. **OT/SCADA network segmentation unconfirmed** at the recently acquired fertilizer plant. Without confirmed segmentation, a breach in the IT network has a clear path to Rockwell/Allen-Bradley PLCs. Iranian APT (Handala/CL-STA-1128) is actively targeting this class of OT equipment.
2. **Lateral movement visibility gap** — existing tools (MDE, Sentinel) are strong on endpoint telemetry and identity but don't give you east-west traffic visibility between workloads, servers, or OT assets. A compromised endpoint moving laterally between servers or into the OT network would have limited detection coverage today.

---

## Fit Assessment

| Criterion | Notes |
|-----------|-------|
| **Covers OT/SCADA?** | Yes — explicit IT/OT convergence use case. Supports legacy OT and ICS environments. NVIDIA BlueField integration for hardware-accelerated ZTS in OT/ICS (announced June 2025). Armis partnership (Feb 2026) extends to OT asset visibility. |
| **MDE/Sentinel integration** | Strong. Native Illumio for Microsoft Sentinel integration (GA Oct 2025). Illumio Insights streams telemetry directly into Sentinel data lake. Correlates with Defender XDR, Entra ID activity logs, and Defender Threat Intelligence vulnerability data. Security Copilot agent available for natural-language threat queries. |
| **Entra ID / Intune compatible** | Yes — Illumio Insights correlates Entra ID activity logs natively in the Sentinel integration. |
| **On-prem / hybrid support** | Yes — covers endpoints, servers, data centres, cloud workloads, containers, IoT, and OT devices. Hybrid and multi-cloud support is a core use case. |
| **Pricing model** | Not publicly listed. Likely per-workload subscription. Forrester TEI study (2023) cites 111% ROI and $10.2M total benefits — worth requesting updated figures. |
| **Vendor HQ / data residency** | HQ: Sunnyvale, CA, USA. Data residency options for Canada not confirmed — **must clarify before proceeding**. |
| **Canadian data residency option** | Unknown — flag for demo call. Critical given regulatory scope (CFIA, Explosives Act, TDG). |

---

## What Makes It Relevant to This Environment

- **East-west visibility** — Illumio builds a live application dependency map showing all traffic between workloads, devices, and endpoints, including flows without any policy in place. This directly addresses the unknown segmentation state at the plant.
- **IT/OT convergence** — Illumio explicitly targets converged IT/OT environments. Traditional firewalls and VLANs are called out as inadequate for hybrid OT environments — consistent with the plant's current state.
- **Sentinel-native** — Segmentation data (traffic flows, policy changes, enforcement actions) pipes directly into Sentinel in real time. No new console, no new workflow for your SOC.
- **Security Copilot integration** — Analysts can ask Copilot natural-language questions (e.g. "What's the blast radius if this host is compromised?") and get policy recommendations and attack path analysis directly.
- **Microsoft itself uses Illumio** — Microsoft deployed Illumio Insights and Segmentation across its entire corporate IT environment (announced Sept 2025). Relevant signal for an E5 shop.
- **Threat modelling use case** — Could be used to model the OT/SCADA attack surface before or during the segmentation audit, independent of a full deployment decision.

---

## Strengths

- Only segmentation platform with confirmed Sentinel data lake + Security Copilot + Defender XDR correlation in a single integration
- Explicit OT/ICS support — not retrofitted, it's a primary use case
- Agentless visibility option announced Feb 2026 (integrates firewall telemetry for hybrid environments)
- Armis partnership (Feb 2026) adds OT asset visibility — potentially additive to your Nmap/OpenVAS/Wazuh stack at the plant
- Policy recommendation engine — AI suggests least-privilege policies based on observed traffic, reducing manual effort
- Available on Microsoft Security Store — procurement simplification for an E5 environment

---

## Weaknesses / Concerns

- **Pricing opacity** — no public pricing. Likely expensive at enterprise scale
- **Canadian data residency** — unconfirmed, must be resolved before any serious evaluation
- **Deployment complexity** — agent-based segmentation on 150+ endpoints plus legacy OT gear could be operationally challenging. Agentless option mitigates this for OT but needs validation
- **Overlap with existing tooling** — MDE already provides some endpoint telemetry; need to assess whether Illumio Insights adds enough signal that isn't already in Sentinel to justify cost
- **OT agent support for Rockwell/Allen-Bradley** — needs explicit confirmation. Legacy PLC firmware may not support agents

---

## Competitive Comparison

| Feature | Illumio ZTS | Claroty | Armis |
|---------|-------------|---------|-------|
| Microsegmentation (IT) | ✅ Core product | ❌ | ❌ |
| OT/ICS visibility | ✅ Via Armis partnership | ✅ Core product | ✅ Core product |
| Sentinel integration | ✅ Native, GA | Partial | Partial |
| Security Copilot agent | ✅ | ❌ | ❌ |
| Agentless option | ✅ (Feb 2026) | ✅ | ✅ |
| Policy enforcement | ✅ | Limited | Limited |
| Canadian data residency | ❓ | ❓ | ❓ |

> **Note:** Claroty and Armis are purpose-built OT visibility platforms. Illumio's strength is segmentation and breach containment with Sentinel-native integration. These may be complementary rather than competing — worth exploring Illumio + Claroty/Armis as a combined architecture given the Armis partnership announced Feb 2026.

---

## Demo / POC Notes

### Pre-Demo Questions to Prepare

- [ ] What is the deployment model for legacy OT environments (Rockwell/Allen-Bradley PLCs)? Agent, agentless, or network tap?
- [ ] Is Canadian data residency available for Illumio Insights telemetry stored in Sentinel data lake?
- [ ] How does the Armis partnership work in practice — does Armis handle OT asset discovery and Illumio handles segmentation?
- [ ] What does the Sentinel integration look like for a Sentinel-primary SOC? Custom workbooks, OOTB dashboards, custom analytics rules?
- [ ] Licensing model — per workload, per endpoint, or consumption-based?
- [ ] What is the typical deployment timeline for a 150-endpoint hybrid IT/OT environment?
- [ ] NERC CIP compliance support — relevant given plant regulatory scope

---

## Decision

**Outcome:** Pending
**Rationale:** 
**Decision Date:** 

---

## Contacts

| Name | Role | Email |
|------|------|-------|
| | Illumio Account Executive | |
| | Illumio SE | |

---

## Related Notes

- [[OT-SCADA/Assets/]] — Plant asset inventory
- [[Projects/OT-SCADA-Assessment/]] — Active assessment project
- [[Threat-Hunting/TTPs/INTEL-Iranian-APT-OT-Targeting]] — Iranian APT threat context
- [[Hardening/Controls/]] — Network segmentation controls

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-30 | Note created — initial research phase. No demo booked yet. |
