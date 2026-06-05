---
title: INFO-mukul975-Anthropic-Cybersecurity-Skills-AI-Agent-Library
date: 2026-06-05
source: "https://github.com/mukul975/Anthropic-Cybersecurity-Skills"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- mukul975 Anthropic-Cybersecurity-Skills: 754 Skills for AI Agents

**Source:** https://github.com/mukul975/Anthropic-Cybersecurity-Skills
**Date:** 2026-06-05
**Author:** mukul975 (community project)
**License:** Apache 2.0

---

## What It Is

Open-source library of 754 structured cybersecurity skills for AI agents, built on the
agentskills.io open standard. Each skill is a structured Markdown file with YAML frontmatter
encoding a real practitioner workflow -- not tutorials or blog summaries. Spans 26 security
domains including DFIR, threat intelligence, threat hunting, cloud security, OT/SCADA, web
security, penetration testing, and AI security. Every skill is mapped to five frameworks:
MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, and NIST AI RMF.

**Important:** Despite the name, this is an independent community project -- **not affiliated
with Anthropic PBC.** The "Anthropic" in the repo name refers to the agent-skills format
popularized by Anthropic, not authorship.

**Architecture:** Progressive disclosure -- each skill costs ~30 tokens to scan (frontmatter
only) and 500-2,000 tokens to fully load. An agent can search all 754 skill frontmatters in a
single pass, identify relevant matches by tag/domain, then load only the top matches. Example:
a "analyze this memory dump for credential theft" prompt surfaces volatility3, LSASS dumping,
and Windows event log credential-access skills.

**Compatibility:** Claude Code, GitHub Copilot, Codex CLI, Cursor, Gemini CLI, and 20+ agent
platforms via the agentskills.io standard. Install: `npx skills add mukul975/Anthropic-Cybersecurity-Skills`.

---

## Relevance

Medium -- reference and potential tooling. Given active use of Claude Code and Codex in the
environment, this is directly loadable into those agents to provide structured security
workflow guidance. The OT/SCADA and cloud security domains are relevant to current work
(fertilizer plant OT assessment, M365 hardening).

**Caveat -- supply chain consideration:** This is a community repo with a name that implies
Anthropic affiliation it does not have. Before pointing any agent at it (especially one with
access to production systems or credentials), the repo should be reviewed under the same
scrutiny applied to any third-party code dependency -- consistent with the NSA MCP guidance
and the Microsoft Agent Governance Toolkit notes already in the vault. The skills execute as
agent instructions; a malicious or compromised skill could influence agent behaviour. Apache
2.0 license and 4,100+ stars are positive signals but not a substitute for review.

---

## Actions

- [ ] If evaluating for Claude Code / Codex use, review skill content under third-party dependency scrutiny first
- [ ] Cross-reference with INFO-NSA-MCP-Security-Design-Considerations-May-2026 and the Agent Governance Toolkit note -- same agentic supply-chain risk class
- [ ] Consider the DFIR and threat-hunting domain skills as a reference for workflow structuring

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-05 | Created -- community AI agent skills library; flagged non-affiliation + supply-chain review caveat |
