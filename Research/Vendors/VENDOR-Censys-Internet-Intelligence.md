---
title: "VENDOR-Censys-Internet-Intelligence"
date: 2026-05-19
vendor: Censys
product: Censys Platform (Search + ASM + Threat Hunting)
category: Threat-Intel
eval_status: Demo-Requested
decision_date: 
tags:
  - "#resource"
  - "#vendor"
  - "#status/draft"
---

# VENDOR-Censys-Internet-Intelligence

**Date:** 2026-05-19
**Vendor:** Censys
**Product:** Censys Platform (Search + ASM + Threat Hunting)
**Category:** Threat-Intel
**Eval Status:** Demo-Requested

---

## Overview

Censys provides internet intelligence through continuous scanning and indexing of the global internet — mapping exposed services, certificates, banners, and host attributes across IPv4/IPv6 space. Primary use cases are Attack Surface Management (ASM), threat actor infrastructure tracking, and proactive threat hunting against externally visible attack surface. Being evaluated alongside GreyNoise.

---

## Problem It Solves

No current visibility into what your organisation looks like from the outside — exposed services, certificate exposure, subdomains, or internet-facing OT assets at the fertilizer plant. Also evaluating for threat hunting use: tracking Iranian APT (Handala/CL-STA-1128) infrastructure patterns via cert reuse, ASN clustering, and JA3/JA4 fingerprints.

---

## Fit Assessment

| Criterion | Notes |
|-----------|-------|
| Covers OT/SCADA? | TBD — ask about ICS protocol coverage (Modbus, DNP3, EtherNet/IP) and Rockwell/Allen-Bradley visibility |
| MDE/Sentinel integration | TBD — API exists; native Sentinel connector unconfirmed |
| Entra ID / Intune compatible | Not applicable — external intel product |
| On-prem / hybrid support | Not applicable |
| Pricing model | TBD — ask: per seat / per query / per asset count? Floor for ~150 endpoints + 1 OT site? |
| Vendor HQ / data residency | US-based (Ann Arbor, MI) — data residency TBD |
| Canadian data residency option | TBD — must confirm; data processed/stored location |

---

## Demo / POC Notes

### 2026-05-19 — Initial Demo

**Questions to cover:**

**Data & Coverage**
- [ ] Scan frequency per IP — daily / on-demand / other?
- [ ] IPv6, cloud-provider IP, and ephemeral infrastructure handling
- [ ] ICS/OT protocol coverage — Modbus, DNP3, EtherNet/IP — and Rockwell/Allen-Bradley exposed services specifically
- [ ] Accuracy of ASN and geolocation data for Canadian IP ranges

**Threat Hunting**
- [ ] API query → Sentinel / KQL pipeline — what does this look like technically? REST? Native connector?
- [ ] Pre-built threat actor infrastructure profiles — Iranian APT specifically (Handala/CL-STA-1128)
- [ ] Cert reuse, hosting ASN, JA3/JA4 fingerprint hunting — supported?
- [ ] Certificate and banner data retention window

**Differentiation vs. GreyNoise**
- [ ] Is Censys primarily outbound intel (what attackers see about me) or inbound classification (what's scanning me) — or both?
- [ ] What does Censys add that MDE / Sentinel network signals don't already surface?

**Operational Fit**
- [ ] Minimum viable workflow for a solo analyst — active daily tool or on-demand pivot resource?
- [ ] Sentinel / Defender XDR integration — native or API-only?
- [ ] Canadian data residency — where is data processed and stored?

**Pricing**
- [ ] Pricing model — per seat / per query / per asset count?
- [ ] Minimum viable tier for ~150 endpoints + 1 OT site, solo analyst

---

**Notes from call:**

> Met with Dylan Rodgers and Garrett Zvoch from Censys.
> - Unique space. Been around for 14 years. Started as a research project at the University of Michigan 
> - Scans the internet continuously
> - Works with SOC for enrichment, vulns and many threat intelligence teams. 
> - Also for dynamic blocking rules with Firewalls using API. 
> - Splunk integrator, recently introduced a Sentinel connector. 
> - Not sure if data can be stored in Canada. 
> 

---

## Strengths

- Comprehensive internet scan data — hosts, certs, banners, services
- Threat hunting use case for actor infrastructure tracking
- ASM capability for understanding external exposure

## Weaknesses / Concerns

- Solo analyst — unclear if active daily use is realistic vs. point-in-time queries
- OT/ICS coverage depth unknown — critical for fertilizer plant context
- Sentinel integration unconfirmed — may require custom API work to operationalise
- Data residency unclear — Canadian orgs need to confirm

---

## Competitive Comparison

| Feature | Censys | GreyNoise | Notes |
|---------|--------|-----------|-------|
| ASM / external exposure mapping | ✅ Core use case | ❌ Not primary | Censys leads |
| Inbound noise classification | ❓ TBD | ✅ Core use case | GreyNoise leads |
| Threat actor infra hunting | ✅ Certs, banners, JA3/JA4 | ⚠️ Limited | Censys leads |
| ICS/OT protocol coverage | ❓ TBD | ❓ TBD | Ask both |
| Sentinel integration | ❓ API only? | ❓ TBD | Ask both |
| Pricing model | ❓ TBD | ❓ TBD | |
| Canadian data residency | ❓ TBD | ❓ TBD | |

---

## Decision

**Outcome:**
**Rationale:**
**Decision Date:**

---

## Contacts

| Name | Role | Email |
|------|------|-------|
| | | |

---

## Related Notes

- [[VENDOR-GreyNoise]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-19 | Note created — pre-demo |
