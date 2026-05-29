# Claude Cowork & Claude Code – Audit Logging Overview

## What is Cowork?

Cowork brings Claude Code's agentic capabilities to the Claude Desktop app for non-coding knowledge work. Unlike Chat, Claude has permission to read, edit, and create files in folders you specify — completing tasks rather than just describing how to do them.

Claude picks the fastest execution path: a connector for Slack, Chrome for web research, or your screen to open apps when there's no direct integration. For recurring tasks, you define it once and it handles the rest.

---

## Requirements & Availability

- Claude Desktop app (macOS; Windows support planned)
- Paid Claude subscription (Pro, Max, Team, or Enterprise)
- Active internet connection throughout the session
- Currently macOS only

---

## Why Cowork Activity Is Not in Audit Logs

The reason is **architectural, not a policy choice**: Cowork conversation history is stored locally on users' machines. Because Cowork runs as a desktop agent working against the local filesystem, session data never transits Anthropic's cloud infrastructure the same way a Chat session does — there is nothing to capture server-side.

> **Anthropic's guidance:** Do not use Cowork for regulated workloads.

Cowork activity is **not captured** in:
- Audit Logs
- Compliance API
- Data Exports

---

## Compensating Control: OpenTelemetry (OTel)

Anthropic's mitigation is OTel. Cowork streams tool calls, file access, and approval states to your SIEM via OpenTelemetry. This is **not a replacement for audit logging**, but it does provide:

- Prompt content
- Tool execution details
- Cost
- User identity (real-time)
- A `prompt.id` traceability chain from user prompt → tool calls → API requests

For Sentinel integration, OTel is the only centralised visibility path if Cowork is deployed in your environment.

---

## Is Claude Code the Same?

**No.** Claude Code *is* captured in audit logs. This is a critical distinction.

### Claude Code audit coverage:
- Chat activity, connector usage, and Code tab activity all flow into audit logs
- With the Enterprise Compliance API, you can pull logs of who used Claude Code, what queries they ran, and what code was generated — and feed it into your SIEM
- Selective deletion supports retention policy enforcement (e.g. purge prompt data older than 30 days)

### Local session caveat:
Claude Code session transcripts also log locally in `~/.claude/`. Useful for individual debugging, but not suitable for enterprise audit — no central aggregation, no search, no retention enforcement. The Compliance API must be enabled and integrated for proper coverage.

### Important Compliance API limitation:
The Compliance API does **not** log inference activities. It covers:
- User login/logout events
- Account setting updates
- Workspace changes
- Other organisational admin events

It does **not** record the content of individual user–model interactions. For session-level content depth, OTel is required on top.

---

## Audit Coverage Comparison

| Surface | Audit Logs / Compliance API | OTel | Local Session Files |
|---|---|---|---|
| Chat | ✅ | — | — |
| Claude Code | ✅ | ✅ | ✅ (`~/.claude/`) |
| Cowork | ❌ | ✅ | ✅ (on-device only) |

---

## Security Implications

From a detection standpoint, if Cowork were used to exfiltrate or manipulate sensitive files:

- **MDE / Sentinel** would still see filesystem activity, process execution, and network calls
- There would be **no Claude-native audit trail** correlating activity back to a specific prompt or task
- OTel → Sentinel is the only mechanism for that correlation, and only if configured **before** the activity occurs

This should be factored into any AI acceptable use policy before Cowork is rolled out to an environment.

---

*Source: Anthropic support documentation, claude.com, claudeforoperators.com — April 2026*
