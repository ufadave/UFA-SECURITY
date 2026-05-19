---
title: "Perimeter Intelligence Tool Comparison — Shodan vs GreyNoise vs Censys"
date: 2026-05-14
vendor: Multiple
product: "Shodan / GreyNoise / Censys"
category: Threat-Intel
eval_status: Researching
decision_date:
tags:
  - "#resource"
  - "#vendor"
  - "#status/draft"
  - "#network"
  - "#endpoint"
---

# Perimeter Intelligence Tool Comparison — Shodan vs GreyNoise vs Censys

**Date:** 2026-05-14
**Category:** External Attack Surface / Perimeter Threat Intelligence
**Eval Status:** Researching — director considering adding GreyNoise or Censys alongside or replacing current Shodan usage

---

## Overview

Three tools, three fundamentally different jobs — despite superficial overlap:

| Tool | Core Function |
|------|--------------|
| **Shodan** | Internet-wide search engine — find exposed services, devices, and open ports globally or scoped to your IPs |
| **GreyNoise** | Internet noise classifier — identify and suppress mass-scanning/opportunistic traffic; enriches IPs with intent context |
| **Censys** | Attack surface management platform — continuous discovery, inventory, and risk monitoring of your internet-facing assets |

The key insight: **Shodan and Censys look outward at the internet to show you what's exposed. GreyNoise looks at who is scanning the internet and tells you whether to care.** These are complementary functions, not direct replacements.

---

## Detailed Comparison

### 1. Shodan (Current)

**What it does:** Scans the internet and indexes banners, open ports, services, and device metadata. You query it — either to see what your org looks like from the outside, or to hunt for exposed infrastructure globally.

**Strengths:**
- Lowest barrier to entry — familiar, well-documented, widely integrated
- Excellent for ad-hoc perimeter checks and one-off lookups
- Strong community ecosystem and integration library
- Shodan Monitor alerts you when new services appear on your registered IPs
- C2 hunter (MalwareHunter) and exploit search built in

**Weaknesses:**
- Data freshness is a known gap — services discovered up to ~3 days after exposure vs Censys's <24 hours
- Covers ~68% of live services accurately vs Censys's ~92%
- Port coverage concentrates on top ports; non-standard ports are less reliably indexed
- No native Microsoft Sentinel integration
- No intent classification — a scan from a botnet and a scan from a security researcher look the same
- Passive tool only — shows you what's exposed, doesn't actively manage or remediate

**Pricing:** Freemium to ~$899/year (Freelancer). Enterprise/API pricing on request. Monitor included in paid plans.

---

### 2. GreyNoise

**What it does:** Runs a global network of 3,100+ honeypot sensors and classifies every IP that scans the internet as `Benign` (known good — Shodan, Censys, security researchers), `Malicious` (known bad — botnets, exploit campaigns), or `Unknown` (unclassified). Enriches your alerts with this context to cut noise.

**Strengths:**
- Direct Microsoft Sentinel integration — available on Azure Marketplace; enriches Sentinel incidents with IP classification automatically
- Dramatically reduces alert fatigue — suppresses opportunistic/mass-scan traffic so you focus on targeted threats
- GNQL (GreyNoise Query Language) lets you hunt for IPs actively exploiting specific CVEs
- Real-time exploit campaign tracking — actively tracks mass exploitation of KEVs (including ransomware use flips)
- New C2 Detection module (April 2026) flags compromised internal devices
- Query-based blocklists — turn any GreyNoise query into a real-time firewall/SOAR blocklist feed
- GreyNoise Recall provides historical time-series data for retrospective analysis
- Community free tier available; enterprise API for Sentinel integration requires paid license

**Weaknesses:**
- Not a perimeter visibility tool — it won't show you what ports are open on your IPs
- Doesn't replace Shodan/Censys for asset discovery — it's an enrichment and noise-reduction layer
- Enterprise pricing is quote-based (not publicly listed)
- Effectiveness scales with how much internet-sourced traffic you see — less useful if your perimeter is heavily firewalled and rarely hit

**Pricing:** Free community tier. Enterprise — quote only. Sentinel integration requires trial or enterprise license.

**OT/SCADA relevance:** GreyNoise actively tracks exploitation campaigns against industrial protocols (Modbus, BACnet, ENIP). Given the Iranian APT threat to Rockwell/Allen-Bradley assets, the ability to see which IPs are actively scanning for ICS/SCADA services is directly relevant to your environment.

---

### 3. Censys

**What it does:** Continuously scans the entire internet across all 65,535 ports and builds a real-time map of internet-facing assets. The ASM (Attack Surface Management) product seeds from your known domains/IPs/cloud accounts and automatically discovers your full external footprint — including shadow IT, acquired assets, and cloud sprawl — then surfaces risks and changes.

**Strengths:**
- Broadest scan coverage — 100% of 65K ports, 8x more services than Shodan, ~92% data accuracy
- Fastest discovery — new services detected in <24 hours vs Shodan's ~3 days
- Native Microsoft Sentinel connector — ASM logbook and risk events push directly into Sentinel as `Censys_Risks_CL` table; queryable via KQL
- Attack surface management is the primary product — continuous monitoring, not ad-hoc search
- TLS certificate tracking is best-in-class; strong for shadow IT and subdomain discovery
- Cloud-native asset connectors (Azure, AWS, GCP) for automatic cloud asset seeding
- Used by U.S. government and 50%+ of Fortune 500
- OT/IoT visibility — explicitly covers IT, OT, IoT devices in ASM scope

**Weaknesses:**
- Enterprise pricing — quote only, significantly higher cost than Shodan; not budget-friendly for smaller teams
- Requires onboarding investment — ASM needs seeds (domains, IPs, cloud accounts) to work well; initial setup has overhead
- Can produce noise in ASM results; some reviewers note manual cleanup required for stale seeds
- Technically demanding — interpreting service banners, certificate chains, and exposure context requires experienced analysts
- Less useful as an ad-hoc search tool for external threat hunting (that's more Shodan/GreyNoise territory)

**Pricing:** Quote only. Enterprise/ASM is a premium product. Free search tier available (250 queries/month) for the search platform.

---

## Head-to-Head Matrix

| Criterion | Shodan (Current) | GreyNoise | Censys ASM |
|-----------|-----------------|-----------|------------|
| **Primary use case** | Perimeter lookup / ad-hoc search | Alert enrichment / noise reduction | Continuous ASM / asset discovery |
| **Data freshness** | ~3 days | Real-time | <24 hours |
| **Port coverage** | Top ports (good), full 65K (limited) | N/A | Full 65K (best-in-class) |
| **Data accuracy** | ~68% live services | N/A | ~92% live services |
| **Microsoft Sentinel integration** | None native | ✅ Azure Marketplace | ✅ Native connector → `Censys_Risks_CL` |
| **OT/SCADA visibility** | Limited | ICS scanning campaign tracking | ✅ Explicit IT/OT/IoT coverage |
| **Alert enrichment** | ❌ | ✅ Core function | Partial (via ASM risks) |
| **Continuous monitoring** | Basic (Monitor alerts) | ❌ | ✅ Core function |
| **Cloud asset discovery** | ❌ | ❌ | ✅ Native cloud connectors |
| **Threat hunting (external)** | ✅ Strong | ✅ (exploit campaign tracking) | Moderate |
| **Ease of use** | High | High | Medium (technical) |
| **Pricing tier** | Low–Medium | Medium (quote) | High (quote) |
| **Canadian data residency** | Not confirmed | Not confirmed | Not confirmed — contact vendor |

---

## Fit Assessment for Your Environment

| Criterion | Notes |
|-----------|-------|
| **Covers OT/SCADA?** | Censys explicitly covers OT/IoT. GreyNoise tracks ICS scanning campaigns. Shodan has OT data but limited monitoring. |
| **MDE/Sentinel integration** | GreyNoise and Censys both have native Sentinel integrations. Shodan has none. |
| **Entra ID / Intune compatible** | N/A for all three — perimeter tools only |
| **On-prem / hybrid support** | All three are cloud SaaS — they look at your external footprint regardless of internal architecture |
| **Pricing model** | Shodan: known/low. GreyNoise: quote. Censys ASM: quote (premium). |
| **Vendor HQ / data residency** | Shodan: US. GreyNoise: US. Censys: US. Canadian data residency — confirm with each vendor. |
| **Acquired fertilizer plant** | OT/SCADA exposure monitoring is a gap in current Shodan usage. Censys ASM with OT scope or GreyNoise ICS campaign tracking would address it. |

---

## Recommendation

**These tools are not mutually exclusive — the most effective answer is layered.**

### Recommended: Add GreyNoise (Priority 1)

GreyNoise is the highest-leverage addition to your current stack for the lowest cost and integration effort. The Sentinel integration is native, available on Azure Marketplace, and directly addresses one of your highest-friction daily problems — alert fatigue from opportunistic internet scanning noise. As a solo analyst in a Sentinel-heavy environment, any tool that automatically classifies incoming IPs and suppresses mass-scan traffic gives you time back on every triage cycle.

The OT/SCADA angle is directly relevant: GreyNoise tracks mass exploitation campaigns against ICS protocols and Rockwell/Allen-Bradley-targeted scanning in near real-time. Given Handala/CL-STA-1128's known interest in your PLC manufacturer, having visibility into who is actively hunting for those services is a concrete threat intel capability, not a nice-to-have.

### Recommended: Evaluate Censys ASM (Priority 2, longer horizon)

Censys ASM is the right tool if the goal is proper external attack surface management — particularly given the acquired fertilizer plant, which almost certainly has internet-facing assets that haven't been fully inventoried. The Sentinel connector pushing `Censys_Risks_CL` directly into Log Analytics is a meaningful operational capability. The cost and onboarding investment are real, but so is the gap: if you don't know your full external footprint, you can't protect it.

**Recommended sequence:** Request a GreyNoise trial first (low friction, immediate Sentinel value). Run it in parallel with Shodan for 30–60 days to validate alert volume reduction. Then evaluate Censys ASM for a formal demo with the fertilizer plant OT scope as the primary use case driver — that gives you a concrete business justification for the budget conversation.

### Keep Shodan (Don't Replace Yet)

Shodan still has value for ad-hoc perimeter lookups and external threat hunting (C2 MalwareHunter, exploit search). Don't replace it until Censys ASM is operational and proven — the two overlap in scope but Shodan is lower cost and immediately available for hunting queries.

---

## Actions
- [ ] Request GreyNoise enterprise trial — contact via greynoise.io; mention Sentinel integration as primary use case
- [ ] Request Censys ASM demo — use fertilizer plant OT asset discovery as the primary evaluation driver
- [ ] Confirm Canadian data residency options with both vendors before procurement
- [ ] Review GreyNoise Azure Marketplace listing for Sentinel content pack requirements
- [ ] Evaluate GreyNoise ICS/OT tag coverage against Rockwell/Allen-Bradley CVEs

---

## Related Notes

- [[PROJ-OT-SCADA-Assessment]]
- [[PROJ-M365-Hardening]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-14 | Created — director evaluating GreyNoise and Censys as additions/replacements for Shodan |
