---
title: Claude Reference Notes — What They Are and How to Use Them
date_created: 2026-04-28
tags:
  - "#resource"
  - "#status/active"
icon: LiBookOpen
---

# Claude Reference Notes — What They Are and How to Use Them

Three notes live in `Research/Claude/` to support working with Claude effectively. Each solves a different problem.

---

## The Three Notes

### [[CLAUDE-Context-Brief]] — Session Orientation
Solves the *what Claude needs to know* problem.

Inside this project Claude has full context from the project instructions. Outside it — a new chat, a different device, a colleague's machine — Claude starts blank. Paste this note at the start of any session to restore full working context without re-explaining your stack, vault conventions, or current priorities.

**Two layers:**
- **Static layer** — environment facts, stack, router table, output conventions. Rarely changes.
- **Dynamic layer** — current threat priorities, active projects and their status, detection backlog. Update this weekly or when priorities shift.

**Maintenance:** Open it at the start of each week, update the Dynamic Layer, bump `last_updated`. Five minutes.

---

### [[CLAUDE-Prompt-Template]] — Complex Request Scaffold
Solves the *how to ask well* problem.

The project instructions cover output format and conventions. They don't give you a reusable scaffold for crafting a complex request. A poorly structured ask on a multi-step task wastes a full back-and-forth cycle.

**Structure:** Role → Context → Task → Output Format → Examples → Constraints

**When to use it:**

| Situation | Use Template? |
|-----------|--------------|
| Email check / triage | ❌ Just ask |
| Quick KQL tweak | ❌ Just ask |
| New detection from scratch | ✅ Yes |
| DFIR playbook | ✅ Yes |
| Complex hunting campaign note | ✅ Yes |
| OT/SCADA risk note | ✅ Yes |
| Single intel note from URL | ❌ Usually fine without |
| Batch of notes / complex research | ✅ Yes |

The note includes three worked examples for the most common complex scenarios: new KQL detection from intel, DFIR playbook, and intel note from URL.

---

### [[CLAUDE-KQL-Conventions]] — Schema Reference
Solves the *environment-specific schema gotchas* problem.

KQL schema issues keep surfacing across sessions — `RemoteIPType` existence, `parse_json()` requirements, `AADServicePrincipalSignInLogs` connectivity, `IpAddress` variance in SecurityEvent. This note consolidates all known-good and known-problematic columns per table so the same caveat doesn't need flagging from scratch every time.

**Contents:**
- Per-table column status (confirmed / flag for validation)
- Known app IDs (Azure CLI, Azure PowerShell, etc.)
- AccessMask decode table for SecurityEvent 4663
- Sentinel analytics rule severity/frequency defaults
- Standard account exclusion patterns
- `parse_json()` pattern reference for AdditionalFields, AuditLogs, CloudAppEvents

**Maintenance:** Add a row whenever a new schema issue surfaces during a query session. This note compounds in value over time.

---

## How They Work Together

The **Context Brief** orients Claude at the start of a session — background knowledge about your environment and current state.

The **Prompt Template** shapes a specific complex request — the structure of what you're asking.

The **KQL Conventions** note is a reference Claude can be pointed at — "use the schema notes in CLAUDE-KQL-Conventions" — to avoid re-validating columns that have already been confirmed.

Inside this Claude project, the project instructions carry most of the static context automatically. The notes earn their keep most when working outside the project, or when the Dynamic Layer has diverged significantly from what the project instructions say.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created |
