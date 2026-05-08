---
title: INFO-AI-Zero-Day-Discovery-IronCurtain-Framework
date: 2026-05-07
source: "https://www.provos.org/p/finding-zero-days-with-any-model/"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO-AI-Zero-Day-Discovery-IronCurtain-Framework

**Source:** https://www.provos.org/p/finding-zero-days-with-any-model/
**Date:** 2026-05-07
**Author:** Niels Provos

---

## What It Is

Research post by Niels Provos demonstrating that autonomous zero-day vulnerability discovery is not exclusive to restricted frontier models (e.g., Anthropic's Mythos Preview) — the capability largely resides in the orchestration harness. Using his open-source **IronCurtain** framework with standard commercial models (Claude Opus 4.6, Sonnet 4.6) and open-weight models (Z.AI GLM 5.1), Provos replicated headline-grabbing frontier findings and discovered novel zero-days in foundational software.

---

## Relevance

Moderate. Directly relevant context for understanding the evolving AI-assisted vulnerability research landscape — the same techniques used defensively are available to adversaries using commodity models. The claim that orchestration matters more than model tier has implications for how quickly threat actors can operationalise AI-assisted exploit development. No direct detection or hardening action for your environment, but useful framing for threat modelling and exec comms. File for reference.

---

## Actions

- [ ] Review IronCurtain framework on GitHub if evaluating AI-assisted vuln research workflows internally
- [ ] Note for threat modelling context: AI-assisted zero-day discovery is accessible to well-resourced adversaries without frontier model access

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Created — lightweight triage note; email tagged [Intel] but assessed as [INFO] |
