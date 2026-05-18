---
title: INFO-Awesome-DFIR-Skills-Admiralty-System
date: 2026-05-18
source: "https://github.com/tsale/awesome-dfir-skills/blob/main/skills/analysis/admiralty-system-tr/SKILL.md"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO-Awesome-DFIR-Skills-Admiralty-System

**Source:** https://github.com/tsale/awesome-dfir-skills/blob/main/skills/analysis/admiralty-system-tr/SKILL.md
**Date:** 2026-05-18

---

## What It Is

A skill from tsale's `awesome-dfir-skills` GitHub repo — a community-driven collection of reusable DFIR prompts, workflows, and helper files structured as Claude-compatible "skills." The Admiralty System skill implements the NATO AJP-2.1 source reliability and information credibility rating framework (A–F source reliability × 1–6 information credibility) as a structured analysis workflow for evaluating CTI sources.

---

## Relevance

Medium — useful for formalising intel source evaluation in your triage workflow. The Admiralty System would let you rate INTEL notes at intake (e.g., a Hunt.io report might be B2 — usually reliable source, probably true but unconfirmed). The broader `awesome-dfir-skills` repo is worth bookmarking as a source of Templater/AI-compatible DFIR workflows. The repo structure (skills as folders with `skill.md` + `helpers/`) mirrors your own vault's approach to reusable content.

**On whether to add to project:** The Admiralty rating is a lightweight addition to your INTEL note frontmatter (`source_reliability: ""`, `info_credibility: ""`). The overhead is low; the value is in bringing structure to mixed-quality intel sources. Recommend: add rating fields to the INTEL template as optional, not mandatory. Don't add the full skill workflow as a project dependency — use the concept, not the implementation.

---

## Actions

- [ ] Consider adding `source_reliability` and `info_credibility` optional fields to `INTEL-Note-Template.md` frontmatter (Admiralty ratings: A–F / 1–6)
- [ ] Star `tsale/awesome-dfir-skills` on GitHub for future skill reference

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-18 | Created — lightweight triage note |
