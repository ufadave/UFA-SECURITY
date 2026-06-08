---
title: INFO-kepano-obsidian-skills-Agent-Skills-Vault-2026-06
date: 2026-06-06
source: "https://github.com/kepano/obsidian-skills"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- kepano/obsidian-skills: Agent Skills for Obsidian

**Source:** https://github.com/kepano/obsidian-skills
**Date:** 2026-06-06
**Author:** Steph Ango (kepano) — Obsidian CEO
**License:** MIT
**Stars:** 34.8k

---

## What It Is

Agent skills library from Steph Ango (kepano), the CEO of Obsidian, teaching AI coding
agents how to correctly work with Obsidian vaults. Compatible with Claude Code, Codex CLI,
OpenCode, and any agentskills.io-compatible agent. Five skills included:

- **obsidian-markdown** — Obsidian Flavored Markdown including wikilinks, embeds, callouts,
  properties/frontmatter, and Obsidian-specific syntax distinctions from standard Markdown
- **obsidian-cli** — Obsidian CLI usage for vault operations
- **obsidian-bases** — Obsidian Bases (the new native database feature)
- **json-canvas** — JSON Canvas format for `.canvas` files
- **defuddle** — content extraction/parsing utility

**Install for Claude Code:**
```bash
# Add to .claude folder in vault root
git clone https://github.com/kepano/obsidian-skills.git .claude/obsidian-skills

# Or via npx
npx skills add kepano/obsidian-skills
```

**Install for Codex CLI:**
Copy the `skills/` directory to `~/.codex/skills/`.

---

## Relevance

High — directly applicable to the current vault workflow. When using Claude Code or Codex
against the UFA-Security vault, these skills teach the agent the correct Obsidian-specific
syntax (frontmatter properties, wikilinks, callouts) that differs from standard Markdown.
This would reduce schema errors when an agent generates vault notes — the exact pain point
encountered when Claude generates notes that look right but use incorrect frontmatter or
wikilink syntax.

**Source authority:** This is from Steph Ango, Obsidian's CEO — as authoritative as it gets
for correct Obsidian syntax conventions. Not a community interpretation.

**Relevance to current tools:**
- Claude Code (conditionally approved in AI use policy) — drop skills into `.claude/` folder
  in the vault root and Claude Code gains correct Obsidian syntax awareness
- Codex CLI (under evaluation) — install to `~/.codex/skills/`

**Caveat — same supply-chain consideration as all agent skills:** Review skill content before
installing into an agent with vault write access. MIT license and Obsidian CEO authorship are
strong trust signals, but consistent with the NSA MCP guidance, any third-party skills that
influence agent behaviour on production data deserve a read-through first.

---

## Actions

- [ ] Install in Claude Code `.claude/` folder in vault root if using Claude Code for vault note generation
- [ ] Review the `obsidian-markdown` skill specifically — most relevant for note generation workflows
- [ ] Cross-reference with INFO-mukul975-Anthropic-Cybersecurity-Skills for combined agent skill posture

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-06 | Created — kepano Obsidian skills; high relevance for Claude Code vault workflows |
