---
title: INFO-AI-Threat-Hunting-vs-Real-World-KQL-Teixeira-2026-06
date: 2026-06-25
source: "https://detect.fyi/testing-ai-threat-hunting-against-real-world-kql-a-side-by-side-test"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- Testing AI Threat Hunting Against Real-World KQL: A Side-by-Side Test

**Source:** https://detect.fyi/testing-ai-threat-hunting-against-real-world-kql-a-side-by-side-test
**Date:** 2026-06-25
**Author:** Alex Teixeira (detect.fyi)

> Note: Article was too recently published to be fully indexed at triage time.
> Summary is based on the article title, Alex Teixeira's published detection
> engineering methodology, and the detect.fyi publication context.

---

## What It Is

Practical head-to-head comparison by Alex Teixeira (detection engineering practitioner
and detect.fyi contributor) testing AI-assisted threat hunting tools against manually
written, production-validated KQL queries. Teixeira is a known KQL/detection engineering
practitioner whose work includes contributions to the Bert-Jan Pals KQL hunting
repository and detect.fyi.

The "side-by-side test" framing suggests empirical evaluation of AI-generated hunt
queries vs. analyst-written ones against real telemetry, likely covering:
- Query correctness against actual tenant schema (the gap this session has encountered
  multiple times -- CopilotActivity schema, `OSPlatform` field placement, etc.)
- Coverage completeness for a given TTP
- False positive rate differences
- Whether AI-generated KQL requires significant analyst review/correction before use

---

## Relevance

Medium -- directly relevant to the current Claude-assisted detection engineering
workflow. The key question Teixeira likely addresses -- whether AI-generated KQL
is production-ready or requires analyst review -- is the central design question in
the current pipeline. Session history suggests the answer is "requires review": the
CopilotActivity stub, the `!has_any` vs `not(has_any())` syntax correction, and the
`OSPlatform` field join requirement are all examples where AI-generated KQL needed
correction before deployment.

**Fetch and read the actual article** -- Teixeira's empirical findings and specific
failure modes identified are likely directly applicable to the current workflow.

---

## Actions

- [ ] **Fetch and read the full article** -- specific findings on AI KQL accuracy and
  failure modes are likely actionable for the current detection pipeline workflow
- [ ] Consider whether any identified failure modes warrant additions to the KQL
  validation checklist in the CLAUDE notes

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-25 | Created -- article too new to index at triage; summary inferred from title and author context; fetch article when indexed |
