---
title: INFO-Microsoft-Agent-Governance-Toolkit-OWASP-Agentic-Top10-2026
date: 2026-05-28
source: "https://github.com/microsoft/agent-governance-toolkit"
tags:
  - "#resource"
  - "#status/draft"
  - "#cloud"
  - "#identity"
---

# INFO -- Microsoft Agent Governance Toolkit (OWASP Agentic Top 10, April 2026)

**Source:** https://github.com/microsoft/agent-governance-toolkit
**Date:** 2026-05-28
**Author:** Microsoft Open Source / Nabil Siddique
**Blog:** https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/

---

## What It Is

Open-source MIT-licensed toolkit released by Microsoft on April 2, 2026 providing
runtime security governance for autonomous AI agents. First framework to address
all 10 OWASP Agentic Top 10 (ASI 2026) risks with deterministic sub-millisecond
policy enforcement. Available in Python, TypeScript, Rust, Go, and .NET. Seven
packages covering policy enforcement, cryptographic agent identity, execution
sandboxing, SRE patterns, and compliance automation.

**OWASP Agentic Top 10 (ASI 2026) coverage:**

| Risk | Toolkit Mitigation |
|------|--------------------|
| ASI-01 Goal hijacking / prompt injection | Semantic intent classifier; policy-based action interception before tool execution |
| ASI-02 Tool misuse | Capability sandboxing; MCP security gateway |
| ASI-03 Identity abuse | DID-based cryptographic identity with behavioral trust scoring; Ed25519 |
| ASI-04 Supply chain risks | Plugin signing with Ed25519 and manifest verification; SLSA-compatible |
| ASI-05 Code execution | Execution rings with resource limits |
| ASI-06 Memory poisoning | Cross-Model Verification Kernel (CMVK) with majority voting |
| ASI-07 Insecure communications | Inter-Agent Trust Protocol (IATP) encryption layer |
| ASI-08 Cascading failures | Circuit breakers and SLO enforcement |
| ASI-09 Human-agent trust exploitation | Approval workflows with quorum logic |
| ASI-10 Rogue agents | Ring isolation, trust decay, automated kill switch |

**Key packages:**
- `agent-os` / `AgentOS kernel` -- StatelessKernel with PolicyEvaluator; all tool calls intercepted before execution
- `agent-mesh` / `AgentMesh` -- Ed25519 cryptographic identity, lifecycle management, capability wildcards, W3C DID export
- `agent-sre` -- circuit breakers, SLO enforcement, observability adapters (Datadog, OpenTelemetry, Azure Service Bus)
- `agent-compliance` -- OWASP ASI 2026 compliance verification CLI (`agt verify`); produces signed machine-readable attestation
- `mcp-security` -- MCP-specific security scanning: invisible Unicode detection, tool poisoning, rug-pull detection

**Automated compliance CLI:**
```bash
agt verify                                        # OWASP ASI 2026 compliance check
agt verify --evidence ./agt-evidence.json --strict  # fail CI on governance gaps
agt red-team scan ./prompts/ --min-grade B          # prompt injection audit
agt lint-policy policies/                           # validate policy files
```

---

## Relevance

Medium -- strategic reference and future-use. Not immediately deployable in the
current E5 environment which doesn't run autonomous agents in production. However:

**MCP security gateway:** The `mcp-security` package addresses exactly the NSA MCP
guidance concerns documented yesterday (INFO-NSA-MCP-Security-Design-Considerations-May-2026) --
specifically tool poisoning detection, invisible Unicode in tool descriptions, and rug-pull
detection (server switching from benign to malicious instructions after initial trust). The
MCPSecurityScanner detects zero-width joiners, bidi overrides, and deceptive tool
metadata.

**Agent identity governance:** The `agent-mesh` DID-based identity model is directly
relevant to the Entra Agent ID scenario (service principal governance for AI agents)
and the ongoing ChatGPT admin consent finding. Treating AI agents as identities with
lifecycle management and behavioral trust scoring mirrors the governance model the
NSA document recommends.

**OWASP Agentic Top 10 as a framework:** The ASI 2026 taxonomy is worth adopting
as a structured lens for evaluating any future AI tool deployments (Codex, ChatGPT,
Copilot). It provides a more rigorous framework than ad-hoc risk assessment.

**Regulatory context:** EU AI Act high-risk provisions take effect August 2026; Colorado
AI Act enforceable June 2026. If any AI agents are deployed in production environments
(including agricultural operations systems at the fertilizer plant) these frameworks will
be relevant.

---

## Actions

- [ ] File as reference for evaluating future AI/agentic tool deployments
- [ ] Review OWASP Agentic Top 10 (ASI 2026) taxonomy as a governance checklist
  for existing AI tool usage (ChatGPT, Codex, Copilot)
- [ ] Cross-reference with INFO-NSA-MCP-Security-Design-Considerations-May-2026
  -- the mcp-security package directly addresses NSA-documented attack patterns

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-28 | Created -- pairs with NSA MCP guidance; OWASP ASI 2026 taxonomy reference |
