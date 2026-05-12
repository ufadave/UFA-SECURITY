---
title: INFO-Defender-XDR-Advanced-Hunting-Schema-Claude-Skill
date: 2026-05-08
source: "https://github.com/ml58158/defender-xdr-advanced-hunting"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
  - "#action-required"
---

# INFO-Defender-XDR-Advanced-Hunting-Schema-Claude-Skill

**Source:** https://github.com/ml58158/defender-xdr-advanced-hunting
**Date:** 2026-05-08

---

## What It Is

A GitHub repository providing a schema-aware dataset and Claude AI skill specifically for Microsoft Defender XDR Advanced Hunting. The project appears to package the full Defender XDR Advanced Hunting schema (table definitions, column names, ActionType values) in a format consumable by Claude — enabling schema-validated KQL query generation without manually cross-referencing Microsoft Learn documentation. Exact implementation details not confirmed — repository may be very new or low-indexed; manual review required.

---

## Relevance

High. Directly relevant to your detection engineering workflow. Schema column validation is one of the highest-friction steps in the KQL note creation process — having a Claude skill with schema awareness baked in would reduce the validated columns checklist burden and catch column name mismatches (e.g. `RemoteIPAddress` vs `RemoteIP`, `IpAddress` vs `IPAddress`) at query generation time rather than at test time. Worth evaluating as a workflow addition, especially against the existing validated columns checklist pattern in your KQL template.

---

## Actions

- [ ] **Review the repository** — https://github.com/ml58158/defender-xdr-advanced-hunting — assess what the skill covers and how it's structured
- [ ] **Evaluate against your KQL workflow** — does it reduce schema validation overhead, and is it compatible with how this project operates?
- [ ] **Note:** GitHub fetch failed during triage — manual review required before routing to `Research/Tools/`

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-08 | Created — GitHub fetch unavailable; manual review flagged |
