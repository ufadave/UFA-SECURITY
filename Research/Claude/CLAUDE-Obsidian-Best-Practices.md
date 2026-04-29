# Obsidian Best Practices & Guidelines

**Date:** 2026-04-25
**Vault:** UFA-Security

---

## Structure & Organisation

- Keep folder depth shallow — two levels maximum. Let tags and links do the heavy lifting instead of folders.
- Name notes for what they *are*, not where they live. `NTLMv2-Downgrade-Detection` beats `Detection-Query-003`.
- Use `YYYY-MM-DD` date format everywhere — sorts chronologically in the file system automatically.

---

## Linking

- Link liberally but intentionally. Every intel note links to related TTPs, every hardening control links to its paired KQL query, every project phase links back to the README.
- Don't create a note just to link to it. If something is a one-liner, put it inline in the parent note.
- The graph view only becomes useful once notes are connected — linking is what separates Obsidian from a folder of files.

---

## Writing & Capture

- Write notes for your future self six months from now, not for today. One sentence of "why" is worth more than a page of "what".
- Use the daily note as a capture buffer — jot things there first, then migrate to the right permanent note at end of day.
- Keep notes atomic where possible — one idea, one detection, one control per note. Makes linking and searching far more effective than long multi-topic documents.

---

## Adding Comments to Notes

### Write directly in the parent note when:
- It's a short observation, result, or follow-up (e.g. "Ran this query — 3 false positives from print spooler")
- It's a status update or changelog entry
- It's a validation result on a KQL column
- It's context that only makes sense alongside the original content
- Use the dedicated sections — **Test Results**, **Notes**, **Validated Columns** — that's what they're for

### Create a linked child note when:
- Your comment is substantial enough to stand on its own (full analysis, follow-up investigation, detailed finding)
- The same thought connects to multiple other notes
- You want it to show up independently in Dataview queries
- It's a decision or finding you'd want to search for directly

### Incidents — special case
If an investigation grows — lateral movement findings, timeline reconstruction, IOC list — create a case note in `IR-DFIR/Cases/` and link from the intel note rather than appending to it.

### Gut check
If your comment is something you'd want to find later by searching → own note or tagged section. If it's just context for the parent → write it inline.

---

## Maintenance

- Do a weekly review of `_Inbox` — anything that landed there needs a home. Let it accumulate and it becomes a graveyard.
- Tag consistently from the start — renaming tags across 200 notes later is painful even with Tag Wrangler.
- Review and close out completed project phases. Mark done in the README. An honest project tracker is more useful than an optimistic one.

---

## Keyboard Shortcuts

Learn these three first — everything else can wait:

| Shortcut | Action |
|----------|--------|
| `Cmd+O` | Open note by name |
| `Cmd+P` | Command palette |
| `[[` | Start a wikilink |

---

## Settings to Enable

| Setting | Location | Why |
|---------|----------|-----|
| Readable Line Length | Settings → Editor | Easier to read long notes |
| Spell Check | Settings → Editor | Typos in titles break wikilinks |
| Folder Templates | Settings → Templater | Auto-applies templates by folder |

---

## Plugins — Priority Order

| Plugin | Priority | Why |
|--------|----------|-----|
| Templater | Install now | Auto-fill dates, prompts, cursors |
| Dataview | Install now | Live dashboards and queries |
| Calendar | Install now | Click-to-create daily notes |
| Periodic Notes | Install now | Auto-create daily/weekly notes from templates |
| Tag Wrangler | Install soon | Rename/merge tags across vault |
| Obsidian Git | Optional | Auto-backup vault to git repo |
| Iconize | Optional | Folder icons for faster navigation |

---

## Dataview Tips

- Every note needs at minimum one **type tag** and one **status tag** for queries to work
- Use `LIMIT` on large vaults to keep dashboards fast
- Dataview re-renders automatically — your Home dashboard stays live
- Tag spelling is case-sensitive — `#status/draft` not `#status/Draft`
- Add `Status:: Active` as an inline field anywhere in a note body for custom queries

---

## Inbox Router — `#export` and Utility Tags

- `#export` is reserved — only tag a note when it's actually ready to share. Remove after export.
- `#action-required` — remove when the action is complete
- `#pending-review` — add when X/Twitter content couldn't be fetched; remove when manually completed

---

## Related Notes
- [[Research/Claude/CLAUDE-Tag-Taxonomy|Tag Taxonomy]]
- [[Research/Claude/CLAUDE-Dataview-Queries|Dataview Query Reference]]
- [[Research/Claude/CLAUDE-Templater-Cheatsheet|Templater Cheatsheet]]
- [[Research/Claude/CLAUDE-Obsidian-Tips|Claude & Obsidian Tips]]

---

## Tags
#resource #obsidian #best-practices

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
