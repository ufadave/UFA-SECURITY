---
title: INFO-Azure-Foundry-AI-Red-Teaming-Agent
date: 2026-05-12
source: "https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO — Azure Foundry AI Red Teaming Agent

**Source:** https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent
**Date:** 2026-05-12

---

## What It Is

Microsoft Azure Foundry's AI Red Teaming Agent is a managed automated adversarial testing tool (currently in preview) that simulates adversarial probing of generative AI systems to identify safety risks before and after deployment. It integrates PyRIT (Microsoft's open-source Python Risk Identification Tool) directly into Azure Foundry, enabling automated scans across a set of built-in risk categories and attack strategies including jailbreaks, indirect prompt injection (XPIA), Unicode obfuscation, crescendo multi-turn attacks, and code vulnerability probing.

---

## Relevance

Low relevance to current operational priorities -- your environment does not currently run Azure Foundry-hosted AI agents or GenAI applications in production. File for reference in the event AI workloads are adopted in Azure. The indirect prompt injection (XPIA) attack category is worth noting conceptually -- it maps directly to risks in any agentic or LLM-integrated workflow and is relevant background for evaluating future AI tool deployments (e.g., Codex/ChatGPT M365 connector POC).

---

## Key Points

- Runs locally (preview) or in the cloud (scheduled, continuous post-deployment)
- Supported targets: Azure Foundry-hosted agents and Azure OpenAI model deployments only -- non-Azure and non-Foundry agents are not supported
- Risk categories: Violence, Hate/Unfairness, Sexual, Self-Harm, Protected Material, Code Vulnerability, Ungrounded Attributes, Prohibited Actions, Sensitive Data Leakage, Task Adherence
- Attack Success Rate (ASR) is the primary output metric
- Region support is limited: East US 2, France Central, Sweden Central, Switzerland West, US North Central
- Complements MITRE ATLAS for structured AI threat simulation

---

## Actions

- [ ] No immediate action required -- file for reference

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created -- lightweight triage note |
