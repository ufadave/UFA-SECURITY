---
title: INFO-NSA-MCP-Security-Design-Considerations-May-2026
date: 2026-05-27
source: Email attachment — CSI_MCP_SECURITY.pdf (NSA Cybersecurity Information Sheet U/OO/6030316-26 | PP-26-1834 | May 2026 Ver. 1.0)
tags:
  - "#resource"
  - "#status/draft"
  - "#cloud"
  - "#identity"
---

# INFO -- NSA: Model Context Protocol (MCP) Security Design Considerations (May 2026)

**Source:** NSA Cybersecurity Information Sheet U/OO/6030316-26 | PP-26-1834 | May 2026 Ver. 1.0
**Date:** 2026-05-27
**Author:** National Security Agency, Cybersecurity Directorate

---

## What It Is

Fifteen-page NSA Cybersecurity Information Sheet covering security design concerns
and mitigations for Model Context Protocol (MCP) deployments in production
environments. MCP is the Anthropic-originated protocol (November 2024) that has
become the de facto standard for connecting AI agents to external tools and services.
The NSA document covers observed security concerns from real-world deployments and
provides practical guidance for organisations adopting MCP in high-stakes environments.

**Classification:** Unclassified, approved for broad distribution.

---

## Relevance

**High and directly actionable.** Your environment currently has three active MCP
connections (Google Drive, Gmail, Microsoft Learn) operating in this Claude session.
The NSA document describes exactly the class of risks these connections introduce.
The GitHub MCP real-world example in the document (unrestricted private/public repo
access) is directly analogous to the Gmail and Google Drive MCP connections
currently active.

---

## Key Security Concerns (NSA findings)

**Access control gaps** -- MCP does not define session-to-identity association at the
protocol level. Authentication is optional in many implementations. No RBAC
enforcement between tasks or services. Multiple MCP servers share context freely from
the client, increasing data leakage risk.

**Insecure serialization** -- Structured objects pass through serialization without strict
schema validation. Serialized content including comments or prompts may enable
injection. Context windows can blend or misalign across tasks.

**Poor approval workflows** -- A change in capability or data access for an already-trusted
MCP server can be made without re-approval. End users are not notified. A previously
approved tool can silently expand its access after initial consent. This is the "rug pull"
risk -- the WhatsApp real-world example documents a malicious MCP server that
advertised benign instructions at installation and switched to malicious ones on second
use.

**Token/session security** -- OAuth bearer tokens without mandatory lifecycle management
(expiration, rotation, revocation). Session hijacking allows prompt injection or
undetected interaction with MCP servers. Idempotency not enforced.

**Prompt injection / output poisoning** -- Multi-agent pipelines where one agent's output
becomes another's input are vulnerable to cascading prompt injection. Hidden
instructions embedded in outputs can alter downstream agent behaviour. NSA cites
this as systemic rather than isolated.

**Missing audit logs** -- Most implementations omit logging or record only minimal metadata.
Without traceable logs, incident response is significantly harder.

---

## Real-World Examples Documented

| Example | What Happened |
|---------|--------------|
| Tool parameter injection | Open-source MCP agents exposed sensitive data via unsanitized parameters; arbitrary commands run via legitimate interfaces |
| Tool invocation path confusion | Naming collisions between public registry and local modules allowed attacker-controlled code execution |
| GitHub MCP unrestricted repo access | Blanket access grant gave tools unrestricted read/write across all private and public repos; sensitive content exfiltrated to public repos without user awareness |
| WhatsApp MCP exploitation | Malicious MCP server coerced client into exposing message history; server appeared benign on first use, turned malicious on second |
| Output poisoning | Chained MCP pipelines manipulated through hidden instructions in tool outputs, leading to downstream unauthorised actions |
| CVE-2025-49596 | RCE in MCP-Inspector toolchain via crafted messages; fixed in v0.14.1 |

---

## NSA Recommendations (summary)

1. **Choose supported, actively maintained MCP projects** -- many popular MCP servers
   are archived. Apply strictest code review to new integrations.
2. **Design for trust boundaries** -- treat agents, plugins, models, and users as different
   trust zones. Align tools with data classification zones. Use local MCP server
   instances for sensitive data processing.
3. **Use a filtering outbound proxy or DLP** -- prevent unintended data leakage from MCP
   environments to external services.
4. **Validate all parameters** -- enforce schema validation on every tool invocation.
   Block parameter forwarding from ambiguous sources.
5. **Constrain and sandbox tool execution** -- AppContainers (Windows), seccomp,
   AppArmor, SELinux. Least privilege on all MCP agent processes.
6. **Sign and verify MCP messages** -- extend with cryptographic signatures in JSON
   payload. Include expiration timestamps and replay protection.
7. **Filter and monitor output pipelines** -- treat every tool output as untrusted input.
   Detect indirect prompt injection in chained execution.
8. **Instrument for logging** -- log all tool and model invocations including parameters and
   identities. Integrate with SIEM.
9. **Track and patch MCP vulnerabilities** -- maintain inventory of all deployed MCP
   agents and tools with versioning and patch history.
10. **Scan local network for open/vulnerable MCP servers** -- unauthenticated instances,
    known flaws, unauthorised deployments, unregulated internet connectivity.

---

## Relevance to Current MCP Usage (Gmail, Google Drive, Microsoft Learn)

| Risk | Current Exposure |
|------|-----------------|
| Approval workflow drift | Gmail and Google Drive MCPs granted access at session start; scope could expand without re-consent if server capabilities change |
| Session token lifecycle | OAuth tokens used by Gmail/Drive MCP have no protocol-level lifecycle enforcement |
| Audit logging | MCP tool invocations in this session are not separately logged to Sentinel -- only Claude.ai audit trail |
| Data classification boundary | Gmail MCP accesses real mailbox content; Google Drive accesses real files -- high-sensitivity data processed by an external MCP server |
| Prompt injection from external content | Emails and documents retrieved via Gmail/Drive MCP could contain adversarial content designed to influence agent behaviour |

---

## Actions

- [ ] **Review active MCP connections** -- confirm Gmail, Google Drive, and Microsoft
  Learn MCPs are using actively maintained, vetted server implementations
- [ ] **Assess approval workflow posture** -- confirm whether server capability changes
  would trigger re-consent in the current Claude.ai MCP implementation
- [ ] **Evaluate prompt injection risk** -- emails and documents retrieved via Gmail MCP
  during triage runs could contain embedded adversarial instructions; consider whether
  sensitive email content should be processed differently
- [ ] **File as reference for future MCP adoption decisions** -- this guidance should inform
  any decision to add new MCP connections (e.g., Azure DevOps, GitHub, SharePoint)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-27 | Created -- PDF extracted from email attachment; NSA CSI May 2026 |
