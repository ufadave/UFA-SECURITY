---
title: "Finding Zero-Days with Any Model — AI-Driven Vulnerability Discovery (provos.org)"
date: 2026-05-02
source: https://www.provos.org/p/finding-zero-days-with-any-model/
type: intel
status: draft
mitre_techniques:
  - T1587.004 (Develop Capabilities: Exploits)
detection_candidate: false
tags:
  - "#intel"
  - "#resource"
  - "#status/draft"
---

# INTEL — Finding Zero-Days with Any Model

## Source
- **URL:** https://www.provos.org/p/finding-zero-days-with-any-model/
- **Date:** 2026-05-02
- **Author:** Niels Provos (IronCurtain framework / open-source vulnerability research)
- **Related context:** Anthropic Mythos Preview coverage via helpnetsecurity.com

## Summary

Research published by Niels Provos demonstrates that autonomous zero-day vulnerability discovery is no longer limited to restricted frontier AI models — it is achievable using commercially available models (Claude Opus 4.6, Sonnet 4.6) and open-weight models (Z.AI GLM 5.1) when orchestrated through a well-designed workflow harness. Provos built workflows on top of the open-source **IronCurtain** framework, replicated previously reported "frontier-only" findings (e.g., the 1998 OpenBSD TCP SACK flaw), and autonomously discovered new zero-days in foundational software.

This aligns with broader reporting: Anthropic's Mythos Preview achieved 181 working exploits for Firefox 147 JS engine vulnerabilities in one test run; standard Sonnet 4.6 and Opus 4.6 each reached exploit tier 5 (complete control flow hijack) at least once against OSS-Fuzz targets. The key finding across the research landscape: **the limiting factor is orchestration, not the model itself.** Capabilities that were assumed to require restricted frontier access are now within reach of commodity tooling with the right harness.

## Relevance to Environment

**Strategic / threat model shaping.** This doesn't present an immediate operational threat, but it has direct implications for your threat model:

- The timeline from vulnerability identification to working exploit is compressing substantially for threat actors with access to similar orchestration tooling.
- AI-assisted exploit development lowers the bar for APT groups — Iranian and other nation-state actors who previously lacked elite vulnerability research capacity now have an accelerant.
- The CopyFail (CVE-2026-31431) disclosure in the same week noted that AI surfaced the bug in approximately one hour.
- **Defensive corollary:** Anthropic recommends integrating current frontier models into vulnerability management workflows now — Sentinel/MDE coverage gaps could be found faster externally than internally.

## Detection Notes

No direct detection applicable — this is a capability shift note. Key implication: accelerate detection coverage for known CVEs before exploit tooling catches up.

## Actions
- [ ] File as threat landscape reference — no immediate hunting action
- [ ] Consider using AI-assisted approaches (MDE Advanced Hunting + Claude) to audit detection coverage gaps in your own environment
- [ ] Reference when justifying detection engineering investment to leadership

## Related Notes
- [[INTEL-CVE-2026-31431-CopyFail-Linux-LPE]]
- [[Research/Claude/Claude-Detection-Engineering-Prompts]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-02 | Initial note created |
