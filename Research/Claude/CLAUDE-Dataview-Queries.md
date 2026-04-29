# Dataview Query Reference

**Plugin:** Dataview | **Docs:** https://blacksmithgu.github.io/obsidian-dataview
**Install:** Settings → Community Plugins → Browse → search "Dataview"

---

## Setup
After installing, enable **Dataview JavaScript Queries** in plugin settings if you want to use `dataviewjs` blocks. Standard `dataview` blocks work out of the box.

---

## Syntax Basics

````
```dataview
TABLE|LIST|TASK
FROM [source]
WHERE [condition]
SORT [field] ASC|DESC
LIMIT [n]
```
````

**Sources:**
- `FROM #tag` — notes with a tag
- `FROM "folder/path"` — notes in a folder
- `FROM #tag AND "folder"` — combine both
- `FROM #tag OR #other-tag` — either tag

**Common fields:**
- `file.name` — note title
- `file.mtime` — last modified date
- `file.ctime` — creation date
- `file.folder` — folder path
- `file.tags` — all tags on the note

---

## Intel & Threat Hunting Queries

### All intel from last 14 days
````
```dataview
TABLE file.mtime AS "Updated", file.folder AS "Location"
FROM #intel
WHERE file.mtime >= date(today) - dur(14 days)
SORT file.mtime DESC
```
````

### Intel by threat actor
````
```dataview
LIST
FROM #intel AND #iran
SORT file.mtime DESC
```
````

### All pending review notes
````
```dataview
LIST
FROM #pending-review
SORT file.mtime DESC
```
````

### Active hunt campaigns
````
```dataview
TABLE file.mtime AS "Started"
FROM #hunt AND #status/active
SORT file.mtime DESC
```
````

---

## Detection & KQL Queries

### All draft detections
````
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #detection AND #status/draft
SORT file.mtime DESC
```
````

### All production detections
````
```dataview
TABLE file.folder AS "Location"
FROM #detection AND #status/done
SORT file.name ASC
```
````

### Detections by domain
````
```dataview
TABLE file.mtime AS "Updated"
FROM #detection AND #identity
SORT file.mtime DESC
```
````
> Swap `#identity` for `#endpoint`, `#network`, `#cloud` etc.

---

## Hardening Queries

### All hardening controls by status
````
```dataview
TABLE file.mtime AS "Updated"
FROM #hardening AND #status/done
SORT file.name ASC
```
````

### Controls still in draft
````
```dataview
LIST
FROM #hardening AND #status/draft
SORT file.mtime DESC
```
````

---

## Project Queries

### All active projects
````
```dataview
TABLE file.mtime AS "Last Updated"
FROM #project AND #status/active
SORT file.mtime DESC
```
````

### All project notes (any status)
````
```dataview
TABLE file.folder AS "Phase", file.mtime AS "Updated"
FROM "Projects"
SORT file.mtime DESC
```
````

---

## Incident & IR Queries

### Open incidents
````
```dataview
TABLE file.mtime AS "Opened"
FROM #ir AND #status/active
SORT file.mtime DESC
```
````

### All incidents (any status)
````
```dataview
TABLE file.folder AS "Type", file.mtime AS "Date"
FROM "IR-DFIR/Cases"
SORT file.mtime DESC
```
````

---

## Action & Export Queries

### Notes requiring action
````
```dataview
LIST
FROM #action-required
SORT file.mtime DESC
```
````

### Notes flagged for export
````
```dataview
LIST
FROM #export
SORT file.mtime DESC
```
````

---

## Weekly Summary Query
> Paste this in your weekly note to see everything touched that week

````
```dataview
TABLE file.folder AS "Area", file.mtime AS "Updated"
FROM ""
WHERE file.mtime >= date(today) - dur(7 days)
AND !contains(file.folder, "_Daily")
AND !contains(file.folder, "_Weekly")
SORT file.mtime DESC
LIMIT 25
```
````

---

## Training Queries (Personal Vault)

### All sessions this month
````
```dataview
TABLE file.mtime AS "Date"
FROM "Training/Sessions"
WHERE file.mtime >= date(today) - dur(30 days)
SORT file.mtime DESC
```
````

### Sessions by week
````
```dataview
TABLE file.name AS "Session"
FROM "Training/Sessions"
WHERE contains(file.tags, "#week4")
SORT file.name ASC
```
````

---

## Tips

- Dataview reads **inline fields** too. Add `Status:: Active` anywhere in a note body and query with `WHERE Status = "Active"`.
- Use `LIMIT` on large vaults to keep dashboards fast.
- Dataview re-renders automatically when notes change — your Home dashboard stays live.
- If a query returns nothing, check tag spelling — `#status/draft` not `#status/Draft`.
- Dataview doesn't create notes, only reads them. Safe to experiment.

---

## Tags
#resource #obsidian #dataview #cheatsheet

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
