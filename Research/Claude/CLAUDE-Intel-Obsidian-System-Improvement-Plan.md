---
title: "Intel & Obsidian System — Improvement Plan"
date: 2026-05-03
type: claude
status: active
tags:
  - "#resource"
  - "#status/active"
---

# Intel & Obsidian System — Improvement Plan

Identified after review of inbox triage workflow performance. Five gaps, one highest-leverage fix.

---

## Gap 1 — Attachment Handling

**Problem:** Gmail API triage cannot read email attachments. Two of eight emails in the 2026-05-03 run required manual intervention — the Five Eyes PDF was only processed after manual upload; the OAI action plan is still a stub. At current volume that's ~25% manual fallthrough.

**Proposed fix:** Script on Mac watching Gmail account that pulls attachments and drops them into `~/Downloads/obsidian-inbox/` alongside a pre-named `.md` stub. Router already handles the file side. Alternatively, continue manual upload to Claude as needed — acceptable at current volume but doesn't scale.

**Priority:** Medium

---

## Gap 2 — No Action-Required Closure Loop

**Problem:** `#action-required` tags are applied consistently but there's no mechanism surfacing open items or confirming closure. Action items accumulate in notes with no visibility into whether they've been completed.

**Proposed fix:** Weekly note template with a Dataview query pulling all `#action-required` notes across the vault. Review during weekly note creation; remove tag from note when action is complete.

**Dataview snippet:**
```dataview
TABLE file.mtime as "Last Modified", tags
FROM #action-required
SORT file.mtime desc
```

**Priority:** Medium

---

## Gap 3 — KQL Stubs Never Promoted or Validated ← HIGHEST LEVERAGE

**Problem:** Every INTEL note contains KQL stubs with `- [ ] Tested in environment` checkboxes that remain perpetually unchecked. No clear path from "stub in an INTEL note" to "deployed analytics rule." Growing library of unvalidated detection candidates with no operational payoff.

**Fix:** Formal KQL promotion pipeline — see `[[CLAUDE-KQL-Promotion-Workflow]]` for full design.

**Priority:** High — action now

---

## Gap 4 — No Persistent Threat Actor Tracking

**Problem:** `#iran`, `#ransomware` etc. tags exist but each INTEL note is standalone. Multiple items touching the same threat actor (e.g. Handala/CL-STA-1128) don't accumulate into a living picture. No campaign-level view.

**Proposed fix:** Dedicated `HUNT-` campaign notes per tracked threat actor. Each new INTEL note that maps to a known actor gets a wikilink added to the relevant campaign note. Campaign note becomes the running intelligence picture; INTEL notes are the evidence trail.

**Priority actors to create campaign notes for:**
- `HUNT-Handala-CL-STA-1128` — Iranian APT, priority threat
- `HUNT-Agriculture-Ransomware-Landscape` — sector-relevant ransomware groups

**Priority:** Medium

---

## Gap 5 — No Processed-Thread Log

**Problem:** Gmail doesn't auto-mark threads as read after API fetch. Repeat triage runs can resurface already-processed threads. Currently handled by manual recognition — unreliable at scale.

**Proposed fix:** Small processed-threads log (JSON or `.md` in vault) recording thread IDs already triaged. Each run checks against it before generating notes.

**Implementation options:**
- Simple `.md` table in `Research/Claude/processed-threads.md`
- JSON sidecar file managed by the triage workflow

**Priority:** Low-Medium — not a problem at current volume, becomes one at 20+ threads/week

---

## Summary

| Gap | Priority | Effort | Status |
|---|---|---|---|
| KQL stub promotion pipeline | High | Medium | 🔴 In progress — see [[CLAUDE-KQL-Promotion-Workflow]] |
| Action-required closure loop | Medium | Low | ⚪ Not started |
| Threat actor campaign notes | Medium | Low | ⚪ Not started |
| Attachment handling | Medium | Medium | ⚪ Not started |
| Processed-thread log | Low | Low | ⚪ Not started |

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Initial note created |
