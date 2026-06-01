---
title: INFO-Cloud-Architekt-CA-SignIn-Audience-Enrichment-KQL
date: 2026-06-01
source: "https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Hunting%20Queries/EID-Authentication/CASignInsWithAudienceEnrichment.kql"
tags:
  - "#resource"
  - "#status/draft"
  - "#identity"
  - "#cloud"
---

# INFO -- Cloud-Architekt: CA Sign-Ins With Audience Enrichment (KQL)

**Source:** https://github.com/Cloud-Architekt/AzureSentinel/blob/main/Hunting%20Queries/EID-Authentication/CASignInsWithAudienceEnrichment.kql
**Date:** 2026-06-01
**Author:** Thomas Naunheim / Cloud-Architekt

---

## What It Is

Hunting query from Thomas Naunheim's AzureSentinel repository that enriches SigninLogs with Conditional Access policy audience context — specifically resolving the resource/audience being accessed per sign-in and correlating it against CA policy applied and result. Part of Naunheim's broader EntraOps enrichment framework which extends Sentinel with watchlist-driven classification of identities, workload identities, and access tiers.

The broader Cloud-Architekt/AzureSentinel repo is a high-quality reference for Entra ID and identity-focused KQL — covers workload identity hunting, token protection, privileged account correlation, UEBA anomaly detection on application management, and enriched sign-in analysis using custom Sentinel watchlists (WorkloadIdentityInfo, UnifiedIdentityInfo, SensitiveEntraDirectoryRoles).

---

## Relevance

Medium-High — the CA audience enrichment query directly supports the CA policy refactor currently in progress. Being able to see what resource/audience is being targeted per sign-in alongside which CA policy applied (and whether it succeeded, failed, or was report-only) is exactly the visibility needed to validate the refactored policies before switching from report-only to enforced mode.

The broader repo is worth bookmarking given the active detection engineering work on Entra ID identity threats — particularly the workload identity hunting queries given the ongoing Entra app registration audit and ChatGPT consent finding.

**Dependency note:** Some queries in this repo require custom Sentinel watchlists (`WorkloadIdentityInfo`, `UnifiedIdentityInfo`, `SensitiveEntraDirectoryRoles`) deployed as part of Naunheim's EntraOps framework. The CA audience enrichment query may work standalone against SigninLogs — test before assuming.

---

## Actions

- [ ] Test `CASignInsWithAudienceEnrichment.kql` in Sentinel during CA refactor validation
- [ ] Review broader Cloud-Architekt/AzureSentinel repo for workload identity hunting queries relevant to Entra app audit
- [ ] Bookmark `EnrichedEntraSignInLogs-TokenProtectionNetworkAccess.kql` — relevant for AiTM token theft detection

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-01 | Created |
