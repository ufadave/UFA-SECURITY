---
title: Detection-KQL Folder Restructure
date: 2026-04-26
status: done
tags:
  - "#project"
  - "#detection"
  - "#status/done"
---

# Detection-KQL Folder Restructure

## Objective

Simplify the Detection-KQL vault structure by collapsing three subfolders (`Queries/`, `Analytics-Rules/`, `Hunting-Queries/`) into a single flat folder. Remove the need to remember three different filename prefixes. Use tags to differentiate content type. Dataview queries handle all slicing.

## Problem with Original Structure

The original setup required three prefixes for content that is fundamentally the same type — KQL:

| Prefix | Subfolder |
|--------|-----------|
| `KQL-` | `Detection-KQL/Queries/` |
| `RULE-` | `Detection-KQL/Analytics-Rules/` |
| `HUNTING-` | `Detection-KQL/Hunting-Queries/` |

This created friction at the point of filing — wrong prefix silently routes a note to the wrong subfolder with no error. Subfolders add no retrieval value that tags can't provide.

---

## Final Structure

### Folder

```
KQL-Detection/          ← All KQL content lives here, flat
```

Removed subfolders:
- ~~`Detection-KQL/Queries/`~~
- ~~`Detection-KQL/Analytics-Rules/`~~
- ~~`Detection-KQL/Hunting-Queries/`~~

### Single Prefix

All KQL notes use one prefix:

```
KQL-
```

### Tags Replace Subfolders

Every KQL note gets one content-type tag in addition to standard type/status/domain tags:

| Tag | Replaces |
|-----|---------|
| `#detection/query` | `Queries/` subfolder |
| `#detection/analytics-rule` | `Analytics-Rules/` subfolder |
| `#detection/hunting` | `Hunting-Queries/` subfolder |

All three inherit `#detection` for Dataview queries that don't need to differentiate.

---

## Updated Router Prefix Table

| Prefix | Vault Destination |
|--------|-------------------|
| `KQL-` | `KQL-Detection/` |
| `INTEL-` | `Threat-Hunting/TTPs` |
| `TTP-` | `Threat-Hunting/TTPs` |
| `HUNT-` | `Threat-Hunting/Campaigns` |
| `IR-` | `IR-DFIR/Cases` |
| `PLAYBOOK-` | `IR-DFIR/Playbooks` |
| `WDAC-` | `WDAC/Runbooks` |
| `OT-` | `OT-SCADA/Assets` |
| `SCADA-` | `OT-SCADA/Assets` |
| `HARD-` | `Hardening/Controls` |
| `INFO-` | `Research/Articles` |
| `TOOL-` | `Research/Tools` |
| `TRAINING-` | `Research/Training` |
| `RESEARCH-` | `Research/Articles` |
| `RES-` | `Research/Articles` |
| `CLAUDE-` | `Research/Claude` |
| `MTG-` | `Meetings` |
| `PROJ-` | `Projects` |

**Removed prefixes:** `RULE-`, `HUNTING-`

---

## Sample Dataview Queries

**All detection content:**
```dataview
TABLE file.mtime AS "Modified", tags AS "Tags"
FROM "KQL-Detection"
SORT file.mtime DESC
```

**Analytics rules only:**
```dataview
TABLE file.mtime AS "Modified"
FROM "KQL-Detection"
WHERE contains(tags, "#detection/analytics-rule")
SORT file.mtime DESC
```

**Hunting queries only:**
```dataview
TABLE file.mtime AS "Modified"
FROM "KQL-Detection"
WHERE contains(tags, "#detection/hunting")
SORT file.mtime DESC
```

**Standalone queries only:**
```dataview
TABLE file.mtime AS "Modified"
FROM "KQL-Detection"
WHERE contains(tags, "#detection/query")
SORT file.mtime DESC
```

---

## Migration Actions

- [x] Move all existing notes from `Detection-KQL/Queries/` → `KQL-Detection/`
- [x] Move all existing notes from `Detection-KQL/Analytics-Rules/` → `KQL-Detection/`
- [x] Move all existing notes from `Detection-KQL/Hunting-Queries/` → `KQL-Detection/`
- [ ] Add correct `#detection/query`, `#detection/analytics-rule`, or `#detection/hunting` tag to each migrated note
- [ ] Delete empty subfolders
- [x] Update `obsidian_router.py` — `KQL-` → `KQL-Detection/`
- [ ] Update Templater folder template mapping — point `KQL-Detection/` to KQL-Query-Template
- [ ] Verify router with a test file drop
- [ ] Update Home.md Dataview queries if they reference old subfolder paths

---

## Decisions Log

| Date | Decision |
|------|----------|
| 2026-04-26 | Collapse Detection-KQL subfolders into single flat folder. Tags replace subfolder differentiation. |
| 2026-04-26 | Prefix settled as `KQL-`. Folder renamed to `KQL-Detection/`. |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-26 | Project note created |
| 2026-04-26 | Updated to reflect final decisions — `KQL-` prefix, `KQL-Detection/` folder, status set to done |
