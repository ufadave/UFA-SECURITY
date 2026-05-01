# Templater Cheatsheet

**Plugin:** Templater | **Docs:** https://silentvoid13.github.io/Templater

---

## Dates & Times

| Expression | Output | Example |
|-----------|--------|---------|
| `<% tp.date.now() %>` | Today's date (default format) | 2026-04-25 |
| `<% tp.date.now("YYYY-MM-DD") %>` | ISO date | 2026-04-25 |
| `<% tp.date.now("DD/MM/YYYY") %>` | UK format | 25/04/2026 |
| `<% tp.date.now("dddd") %>` | Full day name | Saturday |
| `<% tp.date.now("ddd") %>` | Short day name | Sat |
| `<% tp.date.now("MMMM YYYY") %>` | Month and year | April 2026 |
| `<% tp.date.now("HH:mm") %>` | 24hr time | 14:30 |
| `<% tp.date.now("WW") %>` | Week number | 17 |
| `<% tp.date.now("YYYY") %>` | Year only | 2026 |
| `<% tp.date.tomorrow("YYYY-MM-DD") %>` | Tomorrow's date | 2026-04-26 |
| `<% tp.date.yesterday("YYYY-MM-DD") %>` | Yesterday's date | 2026-04-24 |
| `<% tp.date.now("YYYY-MM-DD", 7) %>` | 7 days from now | 2026-05-02 |
| `<% tp.date.now("YYYY-MM-DD", -7) %>` | 7 days ago | 2026-04-18 |

---

## File & Note Info

| Expression | Output |
|-----------|--------|
| `<% tp.file.title %>` | Current note filename (without .md) |
| `<% tp.file.folder() %>` | Folder the note is in |
| `<% tp.file.path() %>` | Full path of the note |
| `<% tp.file.creation_date("YYYY-MM-DD") %>` | Note creation date |
| `<% tp.file.last_modified_date("YYYY-MM-DD") %>` | Last modified date |

### Manipulating the filename
```
<% tp.file.title.replace("KQL-", "") %>
→ strips "KQL-" prefix from filename

<% tp.file.title.replaceAll("-", " ") %>
→ replaces all dashes with spaces

<% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
→ chains both — useful for turning "KQL-NTLMv2-Detection" into "NTLMv2 Detection"
```

---

## User Input

| Expression | Behaviour |
|-----------|-----------|
| `<% tp.system.prompt("Your question here") %>` | Pops up a text input dialog |
| `<% tp.system.prompt("Week number?", "4") %>` | Same, with default value pre-filled |
| `<% tp.system.suggester(["Option A", "Option B"], ["A", "B"]) %>` | Dropdown picker — shows labels, inserts values |

### Suggester example — session type picker
```
<% tp.system.suggester(
  ["Upper A — Hypertrophy", "Lower A — Strength", "Upper B — Hypertrophy", "Lower B — Hypertrophy"],
  ["Upper-A", "Lower-A", "Upper-B", "Lower-B"]
) %>
```
Shows a menu, inserts the short value into the note.

---

## Cursor Placement

| Expression | Behaviour |
|-----------|-----------|
| `<% tp.file.cursor() %>` | Places cursor here after template runs |
| `<% tp.file.cursor(1) %>` | First cursor stop (Tab to jump) |
| `<% tp.file.cursor(2) %>` | Second cursor stop |

### Example — tabbing through a form
```
**Severity:** <% tp.file.cursor(1) %>
**Type:** <% tp.file.cursor(2) %>
**Status:** <% tp.file.cursor(3) %>
```
After template runs, cursor lands on stop 1. Press Tab to jump to 2, then 3.

---

## Conditionals

```
<%* if (tp.date.now("d") === "1") { %>
**Note:** Week starts today.
<%* } %>
```
> `d` = day of week (0=Sunday, 1=Monday … 6=Saturday)

---

## Running JavaScript

Wrap in `<%* ... %>` to run logic without outputting anything:

```
<%* const week = tp.system.prompt("Week number?") -%>
**Week:** <% week %>
```

The `-` after `%>` suppresses the newline.

---

## Moving & Renaming Files on Creation

```
<%* await tp.file.move("/Training/Sessions/" + tp.date.now("YYYY-MM-DD")) %>
<%* await tp.file.rename(tp.date.now("YYYY-MM-DD") + "-Upper-A") %>
```
Useful for auto-filing new notes into the right folder when created from a template.

---

## Practical Examples for This Vault

### Auto-generate Incident Case ID
```
**Case ID:** INC-<% tp.date.now("YYYY") %>-<% tp.date.now("MMDDHHmm") %>
```
→ `INC-2026-04251430`

### Auto-fill KQL note title from filename
```
# KQL — <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
```
→ File named `KQL-NTLMv2-Downgrade` becomes `# KQL — NTLMv2 Downgrade`

### Session note with day name and prompted week
```
**Week:** <% tp.system.prompt("Week number?", "4") %> | **Day:** <% tp.date.now("dddd") %>
```
→ `Week: 4 | Day: Saturday`

### Link to today's daily note
```
[[_Daily/<% tp.date.now("YYYY-MM-DD") %>|Today]]
```

### Link to yesterday
```
[[_Daily/<% tp.date.yesterday("YYYY-MM-DD") %>|Yesterday]]
```

---

## Triggering Templates

| Method | How |
|--------|-----|
| Command palette | `Cmd+P` → "Templater: Open Insert Template Modal" |
| Hotkey | Set in Settings → Hotkeys → search Templater |
| Folder template | Settings → Templater → Folder Templates — auto-applies a template when a note is created in a specific folder |
| New note shortcut | Settings → Templater → set a default template for new notes |

### Folder Templates (recommended setup)
| Folder | Template |
|--------|----------|
| `_Daily/` | Daily-Note-Template |
| `Detection-KQL/Queries/` | KQL-Query-Template |
| `Hardening/Controls/` | Hardening-Control-Template |
| `Threat-Hunting/Campaigns/` | Hunt-Campaign-Template |
| `IR-DFIR/Cases/` | Incident-Case-Template |
| `Training/Sessions/` | Session-Template |

With Folder Templates set, any new note created inside those folders automatically gets the right template applied — no manual triggering needed.

---

## Format Reference (Moment.js)

| Token | Output |
|-------|--------|
| `YYYY` | 2026 |
| `MM` | 04 |
| `MMMM` | April |
| `DD` | 25 |
| `dddd` | Saturday |
| `ddd` | Sat |
| `d` | 6 (day index, 0=Sun) |
| `HH` | 14 (24hr) |
| `hh` | 02 (12hr) |
| `mm` | 30 (minutes) |
| `WW` | 17 (week number) |
| `A` | PM |

---

## Tags
#resource #obsidian #templater #cheatsheet

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
