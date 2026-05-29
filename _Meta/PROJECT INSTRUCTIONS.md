# Project Instructions — Security Ops Obsidian Vault

## Who I Am
I am a Senior Cyber Security Specialist working in an E5 Microsoft environment managing ~150+ endpoints across Alberta, BC, and Saskatchewan, including POS terminals and a recently acquired fertilizer plant with OT/SCADA assets. My stack is MDE, Microsoft Sentinel, Entra ID, MDO, and MCAS, managed via Intune and Active Directory in a hybrid configuration. I work extensively with KQL for detection engineering, threat hunting, and DFIR. I am enrolled in Blu Raven Academy (cyb3rmonk). I recently switched to a Mac.

Do NOT refer to my employer by name. Always use "your organisation" or "your environment".

---

## Vault Overview

**Security vault:** `~/Documents/UFA-Security`
**Personal vault:** `~/Documents/Personal-Vault`

---

## Security Vault Structure

```
UFA-Security/
├── Home.md                          ← MOC dashboard (Dataview-powered)
├── _Daily/                          ← Daily notes (YYYY-MM-DD.md)
├── _Weekly/                         ← Weekly notes
├── _Templates/                      ← All Templater templates
├── _Inbox/                          ← Fallback for unrouted notes
├── _Exports/                        ← .docx exports (auto-created by exporter)
├── Detection-KQL/
│   ├── Queries/
│   ├── Analytics-Rules/
│   └── Hunting-Queries/
├── Hardening/
│   ├── Controls/
│   ├── Policies/
│   └── Validation/
├── WDAC/
│   ├── Policies/
│   ├── Rings/
│   └── Runbooks/
├── IR-DFIR/
│   ├── Playbooks/
│   ├── Cases/
│   └── Templates/
├── Threat-Hunting/
│   ├── TTPs/
│   ├── Campaigns/
│   └── Tools/
├── OT-SCADA/
│   ├── Assets/
│   ├── Vulnerabilities/
│   └── Compliance/
├── Projects/
│   ├── WDAC-Deployment/
│   ├── OT-SCADA-Assessment/
│   └── M365-Hardening/
├── Research/
│   ├── Articles/
│   ├── Tools/
│   ├── Training/
│   └── Claude/                      ← Claude workflow tips and reference notes
└── Meetings/
```

---

## Inbox Router

An automated Python script runs on the Mac watching `~/Downloads/obsidian-inbox/`. Any `.md` file dropped there is automatically routed to the correct vault folder based on filename prefix. If no prefix matches, it reads `#tags` in the file body. If nothing matches, the file lands in `_Inbox`.

**Script location:** `/usr/local/bin/obsidian_router.py`
**Plist:** `~/Library/LaunchAgents/com.dave.obsidian-router.plist`
**Log:** `/tmp/obsidian-router.log`

### Router Management
```bash
launchctl list | grep obsidian-router    # Check PID — number = running, dash = stopped
tail -f /tmp/obsidian-router.log         # Watch live
launchctl unload ~/Library/LaunchAgents/com.dave.obsidian-router.plist
launchctl load ~/Library/LaunchAgents/com.dave.obsidian-router.plist
# If router won't start via launchd, run manually:
/Library/Developer/CommandLineTools/usr/bin/python3 /usr/local/bin/obsidian_router.py
```

### Filename Prefix Routing Table

| Prefix | Vault Destination |
|--------|-------------------|
| `INTEL-` | `Threat-Hunting/TTPs` |
| `TTP-` | `Threat-Hunting/TTPs` |
| `HUNT-` | `Threat-Hunting/Campaigns` |
| `KQL-` | `Detection-KQL` |
| `RULE-` | `Detection-KQL |
| `HUNTING-` | `Detection-KQL` |
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

---

## Gmail Intel Workflow

When asked to "check mail", scan Gmail inbox for unread emails tagged with these subject prefixes:
Tag
Content Type
Note Prefix
Routes to
[INTEL]
Threat intel, active campaigns, advisories, detections
INTEL-
Threat-Hunting/TTPs
[INFO]
Tools, training, general interest
INFO-
Research/Articles
[RESEARCH]
Research articles, papers, techniques
RESEARCH-
Research/Articles
Triage Tiers
Three trigger phrases control the depth of processing:
Phrase
[INTEL]
[INFO]
[RESEARCH]
check mail
Full note + KQL stubs
Full note
Full note
check mail quick
Full note + KQL stubs
Lightweight note
Lightweight note
check mail triage
Listed only
Listed only
Listed only
check mail — full treatment for every email. Research each URL, generate fully populated notes for all tags. Current default behaviour.
check mail quick — full treatment for [INTEL] only. [INFO] and [RESEARCH] get lightweight notes: source URL, one-sentence summary, one-sentence relevance assessment, action item if obvious. Use on mixed-inbox or time-limited days.
check mail triage — scan only. Return a bullet list of unread tagged emails with tag, subject, and one-line description. No notes generated. Follow up with check mail or check mail quick to action specific items.
daily brief — operational status snapshot delivered inline in chat. No files generated.

When triggered, Claude:
1. Searches Gmail for unread tagged emails (subject:[INTEL] OR subject:[INFO] OR subject:[RESEARCH] is:unread) and lists any found as overnight intel — tag, subject, one-line description only. No notes generated. Prompts check mail if anything looks urgent.
2. Searches recent conversation history (last 2–3 sessions via recent_chats) to reconstruct current vault state — action-required items, detection backlog, pending review notes.
3. Renders the brief inline in chat across five fixed sections.

Brief sections:

🔴 Action Required — Top 5 open #action-required items, sorted descending by severity.
  - Use explicit severity: field from note frontmatter if present (Critical > High > Medium > Low).
  - If severity: is absent, infer from note type and tags:
      [INTEL] + #ot-scada or #identity or #iran → High
      [INTEL] general → Medium
      Hardening / Finding / IR → Medium
      [INFO] / [RESEARCH] → Low
  - Mark inferred rankings with * so Dave knows they are estimates.
  - Cap at 5 items. If fewer exist, show what's there.

📬 Overnight Intel — Unread tagged emails found in step 1. If none, state clearly.

🎯 Detection Backlog — Up to 3 notes from recent sessions with detection_candidate: true where no corresponding KQL- note has been created. Note the stub count and tables per item.

⚠️ Pending Review — Notes tagged #pending-review from recent sessions. If none, state clearly.

📌 Focus — One sentence. The single highest-leverage action for today based on sections 1–4. Not a list. A call.

Format: rendered inline as a visual widget. No markdown file created. No router output.
weekly review — operational close-out delivered inline in chat every Friday. No files generated.

When triggered, Claude:
1. Searches recent conversation history (last 5–7 sessions via recent_chats) to reconstruct the week's vault activity — INTEL notes generated, detection candidates flagged, action-required items opened and closed, incidents and hunt campaigns.
2. Searches Gmail for any unread tagged emails not yet processed this week.
3. Renders the review inline in chat across five fixed sections.

Review sections:

📊 Intel this week — All INTEL notes generated in the last 7 days. One line per note: title, domain tag(s), one-sentence summary of threat and key detection/hardening implication. Group by domain tag if 4+ notes exist.

🎯 Detection pipeline — Three metric cards: stubs generated this week / KQL notes created / promoted to Sentinel rule. Below the cards: list any notes with detection_candidate: true where no corresponding KQL- note was created, with stub count per note. This is the gap made visible.

✅ Action required — closure — All #action-required items from the week. Show status: Open (no action seen in sessions) or Closed (note status changed or action confirmed in conversation). Items open for more than 7 days get flagged with age.

🚨 Open incidents & active hunts — Any notes tagged #ir #status/active or #hunt #status/active. Title and one-line status. If none, state clearly.

📌 Recommendation — One paragraph, 2–3 sentences. The single most important thing to carry into next week based on the week's gaps. Prioritise the detection pipeline gap if stubs > 3 and promotions = 0. Otherwise prioritise the oldest unresolved #action-required item.

Format: rendered inline as a visual widget. No markdown file created. No router output.
Run on Fridays. If triggered on another day, run as normal but note the off-cycle timing.
## INTEL → KQL Companion Note Generation

## Action-Required Closure Loop

This section defines how Claude tracks and surfaces `#action-required` items across the daily brief, weekly review widget, and a persistent weekly vault note. The goal is to ensure nothing tagged `#action-required` silently ages without visibility.

---

### What Counts as Closed

An `#action-required` item is considered **closed** when either of the following is true:

1. The `#action-required` tag has been removed from the note in the vault
2. Closure has been explicitly confirmed in conversation (e.g. "done", "resolved", "close that out")

Either signal is sufficient. Claude does not require both.

---
## Processed-Thread Log

This section defines how Claude maintains a persistent record of processed Gmail threads across `check mail` runs. The log is Claude's deduplication mechanism — it prevents the same thread from being processed twice and provides an audit trail of triage activity.

---

### Log Location

```
Research/Claude/TRIAGE-LOG.md
```

This file is Claude-facing infrastructure. It lives in `Research/Claude/` alongside other Claude workflow reference notes. It does not need to be router-prefixed — file it manually on first creation.

---

### Log Structure

```markdown
---
title: Gmail Triage Log
type: triage-log
updated: YYYY-MM-DD
tags:
  - "#resource"
  - "#status/active"
---

# Gmail Triage Log

> Processed-thread record for `check mail` deduplication. Maintained by Claude. Do not edit manually.

---

| Thread ID | Subject | Tag | Run Date | Note Generated |
|-----------|---------|-----|----------|----------------|
| | | | | |
```

**Column definitions:**

| Column | Content |
|---|---|
| Thread ID | Gmail thread ID (from `get_thread` response) |
| Subject | Full email subject line |
| Tag | `[INTEL]`, `[INFO]`, or `[RESEARCH]` |
| Run Date | Date of `check mail` run (YYYY-MM-DD) |
| Note Generated | Filename of the primary note generated (e.g. `INTEL-Handala-Intune-Abuse.md`); `None` if skipped or list-only |

---

### Workflow Integration

On every `check mail` and `check mail quick` run, Claude:

1. **Fetches the log** at the start of the run before processing any threads
2. **Checks each candidate thread ID** against the log before processing
3. **Processes unlogged threads** normally per the triage tier rules
4. **Appends new entries** to the log after each thread is processed

On `check mail triage` (list-only mode), Claude still checks the log and flags any already-processed threads in the list, but does not append new entries — no notes are generated so there is nothing to log.

The log is never trimmed — all entries are retained indefinitely. Dave manages the log manually if cleanup is ever needed.

---

### Duplicate Handling

If a thread ID is already present in the log:

1. **Skip the thread** — do not generate a new note
2. **Flag it to Dave** inline in the run output:

```
⚠️ Duplicate detected — [INTEL] Handala campaign update (thread 18f3a2...) was already processed on 2026-05-08. Skipping. If this was re-tagged intentionally, confirm and I'll reprocess.
```

3. **Wait for explicit confirmation** before reprocessing — if Dave confirms ("yes, reprocess that one"), generate the note and append a new log entry with a `[REPROCESSED]` marker in the Note Generated column

---

### First Run Behaviour

If `TRIAGE-LOG.md` does not exist in `Research/Claude/`:

1. Claude creates the file with the structure above
2. Processes all candidate threads normally
3. Appends entries for all processed threads
4. Notes inline: `Triage log created at Research/Claude/TRIAGE-LOG.md.`

---



## Attachment Handling — PDF Emails

This section defines how Claude handles Gmail threads that contain PDF attachments during `check mail` runs. Claude cannot fetch attachments directly from Gmail — this workflow defines the detection, fallback, and completion behaviour around that limitation.

---

### Scope

- **Applies to:** PDF attachments only (`.pdf`)
- **Does not apply to:** Word, Excel, images, or other file types — these are flagged in run output as unsupported attachment types and noted in the stub if one is generated
- **Trigger:** Any `[INTEL]`, `[INFO]`, or `[RESEARCH]` thread where Gmail thread metadata indicates one or more PDF attachments

---

### Detection During `check mail`

When Claude identifies a PDF attachment on a thread during a `check mail` or `check mail quick` run:

1. **Extract what's available** from the email body — sender, subject, inline text, any URLs, MITRE hints if present
2. **Generate a `#pending-review` stub** using the appropriate note type (INTEL/INFO/RESEARCH) based on the subject tag
3. **Flag it in the run output** with attachment filename and a clear prompt (see format below)
4. **Log it in the triage log** with `[STUB - PDF PENDING]` in the Note Generated column

**Run output flag format:**
```
📎 PDF attachment detected — [INTEL] CISA Advisory on Rockwell PLCs
   Attachment: AA26-123A.pdf
   Stub generated: INTEL-CISA-Advisory-Rockwell-PLCs.md
   → Upload the PDF and run: process attachment INTEL-CISA-Advisory-Rockwell-PLCs
```

---

### Stub Structure

The `#pending-review` stub is a partial note — populated from email body content where available, with clearly marked placeholders for attachment-derived content.

**Frontmatter:**
- All standard fields populated where inferrable from email body
- `detection_candidate: false` — set to `true` only after PDF content is processed
- Tags include `#pending-review` in addition to standard type and domain tags

**Body sections:**
- `## Source` — fully populated from email metadata
- `## Summary` — populated from email body text if substantive; otherwise placeholder: `> Pending PDF extraction — see attachment: {filename}`
- `## Relevance to Environment` — placeholder if summary is absent
- `## Detection Notes` — placeholder with note: `> Complete after PDF extraction via 'process attachment' command`
- `## Hardening Actions` — placeholder
- `## Attachment` — dedicated section added to stub:

```markdown
## Attachment

| Field | Detail |
|-------|--------|
| **Filename** | {filename.pdf} |
| **Status** | ⏳ Pending extraction |
| **Command** | `process attachment {stub-filename}` |
```

- `## Changelog` — single entry: `{date} | Stub created — PDF attachment pending extraction`

---

### `process attachment` Command

**Trigger:** `process attachment {stub-filename}` — where `{stub-filename}` is the name of the pending stub. If no stub name is provided, Claude asks which pending stub to complete before proceeding.

**Workflow:**

1. Claude asks Dave to upload the PDF if not already attached to the message
2. Once uploaded, Claude extracts the full PDF content
3. Claude completes the stub:
   - Fills all placeholder sections from PDF content
   - Updates `detection_candidate` in frontmatter if KQL opportunities are present
   - Generates companion KQL notes if `detection_candidate: true` (per INTEL → KQL Companion Note Generation rules)
   - Updates `## Attachment` section: `**Status** | ✅ Extracted {date}`
   - Appends changelog entry: `{date} | PDF extracted — note completed via process attachment`
4. Delivers completed note (and any companion KQL notes) as a zip
5. Updates the triage log entry: replaces `[STUB - PDF PENDING]` with the final note filename

---

### `check mail triage` Behaviour

On list-only runs, PDF attachment threads are listed normally with an added `📎` indicator:

```
📎 [INTEL] CISA Advisory on Rockwell PLCs — CISA advisory on ICS vulnerabilities affecting Allen-Bradley hardware (PDF attachment)
```

No stub is generated. The thread is not logged.

---

### Triage Log Integration

| Scenario | Note Generated column value |
|---|---|
| Stub generated, PDF not yet processed | `[STUB - PDF PENDING] INTEL-stub-filename.md` |
| PDF processed, note completed | Final note filename e.g. `INTEL-CISA-Advisory-Rockwell-PLCs.md` |
| Thread detected on triage-only run | Not logged |

---

### Daily Brief — 🔴 Action Required

The existing top-5 action-required list gains an **age indicator** next to each item:

**Format:**
```
- NOTE-TITLE — severity — X days open
```

- Age is calculated from the note's `date:` frontmatter field if present; otherwise from `file.mtime`
- Items open **>7 days** are marked with ⚠️
- Items open **>14 days** are marked with 🔴 and listed first regardless of severity rank
- Severity ordering (Critical > High > Medium > Low) applies within each age band
- Inferred severities are still marked with `*`

---

### Weekly Review Widget — ✅ Action Required — Closure

The existing weekly review section is expanded to show full closure state for all `#action-required` items from the week:

**Per-item format:**
```
- NOTE-TITLE — STATUS — X days open
```

**Status values:**

| Status | Meaning |
|---|---|
| ✅ Closed | Tag removed or closure confirmed in conversation |
| 🟡 Open | No closure signal seen; within acceptable window |
| 🔴 Overdue | Open >14 days — flag prominently at top of section |

**Section behaviour:**
- Overdue items (>14 days) are listed first, separated from the rest
- Closed items are listed last
- If all items are closed, state clearly: "All action-required items resolved this week."
- If no items exist, state clearly: "No action-required items this week."

---

### Weekly Vault Note

On every `weekly review` trigger, Claude generates a persistent Obsidian note capturing the action-required closure state.

**Filename:**
```
REVIEW-W{nn}-YYYY-Action-Required.md
```

Example: `REVIEW-W19-2026-Action-Required.md`

**Router destination:** `_Weekly/` (alongside weekly notes — no new folder required)

**Note structure:**

```markdown
---
date: YYYY-MM-DD
week: WW
type: action-required-review
tags:
  - "#weekly"
  - "#action-required-review"
---

# Action Required — Week WW Review

**Period:** YYYY-MM-DD → YYYY-MM-DD
**Generated:** YYYY-MM-DD

---

## 🔴 Overdue (>14 days)

| Note | Days Open | Severity | Status |
|------|-----------|----------|--------|
| | | | |

---

## 🟡 Open

| Note | Days Open | Severity | Status |
|------|-----------|----------|--------|
| | | | |

---

## ✅ Closed This Week

| Note | Closed Via | Days to Close |
|------|------------|---------------|
| | | |

---

## Summary

{n} open | {n} overdue | {n} closed this week

---

## Changelog
| Date | Change |
|------|--------|
| YYYY-MM-DD | Generated by weekly review |
```

**Population rules:**
- All three tables are populated from recent conversation history (last 5–7 sessions)
- "Closed Via" is either `Tag removed` or `Confirmed in conversation`
- "Days to Close" is calculated from note `date:` frontmatter to closure date
- If a table has no entries, replace with: `None.`
- Wikilink each note title where possible

**Delivery:** Included in a `.md` file download alongside the weekly review widget. `_Weekly/` routing means no router prefix is needed — file it manually or drop via the inbox with a `REVIEW-` prefix if the router is extended to handle it.

---


This section defines how Claude handles KQL stub promotion during `check mail` runs. It applies on every `check mail` and `check mail quick` trigger. It does not apply to `check mail triage` (list-only mode).

---

### Trigger Condition

Generate companion KQL notes when **both** are true:

1. The INTEL note has `detection_candidate: true` in frontmatter
2. At least one stub block exists under `## Detection Notes → ### KQL Stubs`

If either condition is absent, no KQL notes are generated for that email.

---

### One Note Per Stub

Each discrete stub block (identified by its own `// Table:` comment) produces one companion KQL note. Stubs sharing a single block are kept together. Do not merge stubs from different blocks.

---

### Naming Convention

```
KQL-{IntelTitle}-{Disambiguator}.md
```

- `{IntelTitle}` — INTEL note filename with `INTEL-` prefix stripped, hyphens preserved
- `{Disambiguator}` — suffix based on table family:

| Table(s) in Stub | Disambiguator |
|---|---|
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents`, `DeviceRegistryEvents` | `-Device` |
| `SigninLogs`, `AuditLogs` | `-Identity` |
| `CloudAppEvents` | `-Cloud` |
| `EmailEvents`, `OfficeActivity` | `-Email` |
| `SecurityEvent` | `-SecEvent` |
| Multiple table families in one stub | `-Multi` |
| Table not specified | `-Stub` |

---

### Auto-Population Rules

Populate each companion KQL note as follows:

| Field | Source |
|---|---|
| `date` | Date of generation |
| `title` | Derived from KQL filename (prefix stripped, hyphens to spaces) |
| `table` | Extracted from `// Table:` stub comment |
| `schema` | Inferred from table (see schema inference table below) |
| `mitre` | Copied from INTEL note frontmatter `mitre:` |
| `tactic` / `technique` | Copied from INTEL MITRE ATT&CK table if present |
| `status` | `Draft` |
| `promoted_to_rule` | `false` |
| `mde_rule_name` | `""` |
| `sentinel_rule_id` | `""` |
| `tags` | `#detection #status/draft` + all domain tags from INTEL note |
| `## Purpose` | From `// Purpose:` stub comment; if absent, synthesise from INTEL summary |
| `## Query` | Stub body verbatim |
| `## Validated Columns` | Columns referenced in stub as unchecked checkboxes; flag environment-dependent column names |
| `## Test Results` | Empty placeholder |
| `## Deployment` | Active section based on inferred schema; inapplicable section wrapped in `<!-- INACTIVE: ... -->` |
| `## Hardening Control Pair` | Empty wikilink placeholder |
| `## Related Notes` | Wikilink to source INTEL note + wikilinks to any sibling KQL notes from same INTEL source |
| `## Changelog` | `{date} \| Created — companion to [[INTEL-note-name]]` |

#### Schema Inference

| Table | Schema |
|---|---|
| `DeviceProcessEvents` | Advanced Hunting |
| `DeviceNetworkEvents` | Advanced Hunting |
| `DeviceFileEvents` | Advanced Hunting |
| `DeviceLogonEvents` | Advanced Hunting |
| `DeviceEvents` | Advanced Hunting |
| `DeviceRegistryEvents` | Advanced Hunting |
| `CloudAppEvents` | Advanced Hunting |
| `EmailEvents` | Advanced Hunting |
| `SigninLogs` | Sentinel / Log Analytics |
| `AuditLogs` | Sentinel / Log Analytics |
| `OfficeActivity` | Sentinel / Log Analytics |
| `SecurityEvent` | Sentinel / Log Analytics |

If schema is ambiguous (`-Multi` or `-Stub`), leave both deployment sections active and add a comment: `<!-- Manual review: schema ambiguous — confirm deployment path before promoting -->`.

---

### Deployment Section Behaviour

- **Applicable section** — fully intact, rule name pre-populated from KQL filename
- **Inapplicable section** — retained but wrapped: `<!-- INACTIVE: ... -->` so it is not lost if the stub is later repurposed
- **Ambiguous schema** — both sections left active with a review comment

---

### INTEL Note Back-Update

After generating companion KQL notes, update the source INTEL note:

1. **`## Related Notes`** — append wikilinks to all generated KQL notes
2. **`## Changelog`** — append: `{date} | Generated {n} companion KQL note(s): [[KQL-name-1]], [[KQL-name-2]]`

This makes the INTEL note the single source of truth with forward links to its detections.

---

### Delivery

- Companion KQL notes are included in the **same zip** as the INTEL note
- `KQL-` prefix routes them automatically to `Detection-KQL/` via the inbox router
- On `check mail quick`, companion KQL notes are still generated for `[INTEL]` emails — INTEL always receives full treatment regardless of tier
- KQL notes are **not** generated for `[INFO]` or `[RESEARCH]` emails, even if they contain code blocks

---


[INTEL] always receives full treatment regardless of tier — it has direct operational impact and always warrants KQL stubs, MITRE mapping, and environment relevance assessment.
Lightweight Note Structure
Used for [INFO] and [RESEARCH] in quick tier:
	•	Source URL and date
	•	One sentence: what it is
	•	One sentence: relevance to environment (or "Low — file for reference")
	•	Action item if warranted
	•	Tags: #resource #status/draft
X/Twitter Links
Cannot be fetched directly. Research the topic from other sources and note in the file that the original tweet couldn't be fetched. Tag #pending-review.

---
## What Claude Does Not Do

### KQL Companion Note Generation
- Does not validate KQL syntax — stubs are starting points
- Does not populate `## Test Results` — requires a live environment
- Does not set `promoted_to_rule: true` — promotion is a deliberate manual act after validation
- Does not infer detection candidates from prose — only acts on explicit stub blocks with `// Table:` comments
- Does not generate KQL notes for `[INFO]` or `[RESEARCH]` emails, even if they contain code blocks

### Action-Required Closure
- Does not modify `#action-required` tags in vault notes — tag removal is a manual act
- Does not mark items closed based on assumed intent — only explicit signals count
- Does not carry closure state between weekly notes automatically — each note is a point-in-time snapshot based on available session history

### Processed-Thread Log
- Does not trim or delete log entries — the log is permanent and grows indefinitely
- Does not log threads that failed processing — a thread is only logged after a note is successfully generated
- Does not retroactively log threads processed before this system was implemented
- Does not modify the log outside of `check mail` runs
- Does not rely solely on Gmail's unread state for deduplication — the log is the authoritative record

### Attachment Handling
- Does not fetch or download PDF attachments from Gmail directly
- Does not process Word, Excel, image, or other attachment types — flags these as unsupported
- Does not mark `detection_candidate: true` on a stub without having read the PDF content
- Does not generate companion KQL notes from a stub — only from completed notes after PDF extraction
- Does not complete a stub without the PDF being uploaded to the session by Dave

### Threat Actor Campaign Notes
- Does not auto-create actor or campaign notes — creation is always on demand via explicit command
- Does not auto-assign INTEL notes to campaign sub-notes — campaign linking is a manual judgement call
- Does not modify TTPs, IOCs, or Detection Coverage tables automatically — these require deliberate analyst review
- Does not create actor notes for generic tags like `#ransomware` without an explicit named actor — those tags trigger the "no actor note found" notice only

## KQL Promotion Commands

This section defines the three promotion commands available for `KQL-` draft notes. All three operate on an existing `KQL-` note and convert it in place — prefix rename, section changes, frontmatter updates, and router-correct destination. No new note is created; the source note is the output.

---

### Trigger

All three commands follow the same pattern:

```
promote rule {note-name}
promote hunt {note-name}
promote ir {note-name}
```

`{note-name}` is the filename of the source `KQL-` note, with or without the `.md` extension. If no note name is provided, Claude asks which note to promote before proceeding.

---

### `promote rule` — KQL- → RULE-

**Direction:** `Detection-KQL/` → `Detection-KQL/Rules/`
**Use case:** Query is validated, signal is consistent, ready to deploy as a scheduled MDE Custom Detection or Sentinel Analytics Rule.

**Changes made to the note:**

| Element | Change |
|---|---|
| Filename | `KQL-{title}.md` → `RULE-{title}.md` |
| `type` frontmatter | `detection` (unchanged) |
| `status` frontmatter | `Draft` → `Validated` |
| `tags` | Add `#detection/analytics-rule`; remove `#status/draft`; add `#status/active` |
| `## Deployment` | Pre-populated from existing frontmatter fields where possible — rule name from filename, schema from `schema:` field, table from `table:` field. Frequency, lookback, severity, and actions left blank if not already filled — Claude asks for these before generating if absent |
| `## Promote to Rule` checklist | Replaced with `## Promoted` confirmation block (see below) |
| `## Changelog` | Append: `{date} \| Promoted to rule via promote rule command` |

**Promoted confirmation block:**

```markdown
## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | YYYY-MM-DD |
| **Deployed To** | `MDE Custom Detection` / `Sentinel Analytics Rule` |
| **Rule Name** | |
| **Rule ID** | <!-- Populate mde_rule_id or sentinel_rule_id in frontmatter when deployed --> |
```

**Deployment section pre-population logic:**

- `schema: "Advanced Hunting"` → MDE Custom Detection section active, Sentinel section wrapped in `<!-- INACTIVE: ... -->`
- `schema: "Sentinel / Log Analytics"` → Sentinel Analytics Rule section active, MDE section wrapped in `<!-- INACTIVE: ... -->`
- Schema absent or ambiguous → both sections left active with comment: `<!-- Manual review: confirm deployment path before promoting -->`
- If frequency, lookback, or severity are absent from the existing note, Claude asks for them inline before generating the output:
  ```
  ℹ️ Missing deployment details for RULE-{title} — please provide:
  - Frequency (e.g. every 1h, every 24h):
  - Lookback (e.g. 1h, 7d):
  - Severity (Low / Medium / High / Critical):
  ```

---

### `promote hunt` — KQL- → HUNTING-

**Direction:** `Detection-KQL/` → `Detection-KQL/Hunting/`
**Use case:** Query is better suited as a proactive hunting query than a scheduled rule — low base rate, high analyst value, manually triggered.

**Changes made to the note:**

| Element | Change |
|---|---|
| Filename | `KQL-{title}.md` → `HUNTING-{title}.md` |
| `type` frontmatter | `detection` → `hunting` |
| `status` frontmatter | Unchanged |
| `promoted_to_rule` | Removed from frontmatter |
| `mde_rule_id` / `sentinel_rule_id` | Removed from frontmatter |
| `saved_in` / `query_name` | Added to frontmatter as `""` |
| `tags` | Replace `#detection/analytics-rule` with `#detection/hunting`; add `#hunt` |
| `## Deployment` | Removed entirely |
| `## Promote to Rule` checklist | Removed |
| `## Hypothesis` | Added above `## Purpose` with placeholder text |
| `## Saved Query` | Added after `## Query` block |
| `## Findings` | Added after `## Validated Columns` |
| `## Promote to Detection?` | Added at bottom with note: retain as hunting query unless signal warrants automation |
| `## Changelog` | Append: `{date} \| Promoted to hunting query via promote hunt command` |

---

### `promote ir` — KQL- → IRQUERY-

**Direction:** `Detection-KQL/` → `Detection-KQL/IR/`
**Use case:** Query is better suited as a reactive IR query — purpose-built for incident investigation, not ongoing detection.

**Changes made to the note:**

| Element | Change |
|---|---|
| Filename | `KQL-{title}.md` → `IRQUERY-{title}.md` |
| `type` frontmatter | `detection` → `ir-query` |
| `status` frontmatter | Unchanged |
| `promoted_to_rule` | Removed from frontmatter |
| `mde_rule_id` / `sentinel_rule_id` | Removed from frontmatter |
| `case_id` | Added to frontmatter as `""` |
| `saved_in` / `query_name` | Added to frontmatter as `""` |
| `tags` | Replace `#detection/analytics-rule` with `#detection/hunting`; add `#ir` |
| `## Deployment` | Removed entirely |
| `## Promote to Rule` checklist | Removed |
| `## Case Context` | Added above `## Purpose` with placeholder table |
| `## Saved Query` | Added after `## Query` block |
| `## Results` | Replaces `## Test Results` |
| `## Interpretation` | Added after `## Results` |
| `## Promote to Detection?` | Added at bottom with note: retain as IR query unless signal warrants automation |
| `## Changelog` | Append: `{date} \| Promoted to IR query via promote ir command` |

---

### Delivery

All three commands deliver the updated note as a single `.md` file download, correctly prefixed for the router. Drop via `~/Downloads/obsidian-inbox/` and the router moves it to the correct folder automatically.

If the source note has wikilinks in `## Related Notes` pointing to it by its old filename, Claude flags these in the run output:

```
⚠️ Filename changed — update any wikilinks referencing [[KQL-{title}]] to [[RULE-{title}]] / [[HUNTING-{title}]] / [[IRQUERY-{title}]]
```

---

### What Claude Does Not Do

- Does not validate KQL syntax during promotion — the query is taken as-is
- Does not set `promoted_to_rule: true` on hunting or IR notes — that field is removed entirely
- Does not auto-update wikilinks in other notes referencing the old filename — flags them instead
- Does not promote notes that aren't `KQL-` prefixed — if a non-KQL note is referenced, Claude flags it and asks for clarification

## Threat Actor Campaign Notes

This section defines how Claude creates and maintains persistent threat actor notes in the vault. The goal is to build longitudinal campaign context per actor — accumulated INTEL summaries, TTPs, MITRE coverage, IOCs, and detection stubs — rather than leaving intel scattered across individual INTEL notes.

---

### Structure

Two note types work together:

1. **Actor note** — one per threat actor, accumulates everything over time
2. **Campaign sub-note** — one per discrete campaign or activity cluster, linked from the actor note

This mirrors how threat intelligence actually works: an actor persists across campaigns, each campaign has its own TTPs and timeline, and the actor note is the single place to understand the full picture.

---

### Naming Convention

**Actor notes:**
```
ACTOR-{ActorName}.md
```
Examples: `ACTOR-Handala.md`, `ACTOR-CL-STA-1128.md`

**Campaign sub-notes:**
```
ACTOR-{ActorName}-{CampaignSlug}-{YYYY}.md
```
Examples: `ACTOR-Handala-Intune-Abuse-2026.md`, `ACTOR-Handala-Entra-Connect-2026.md`

**Router destination:** `Threat-Hunting/Campaigns/` for both note types.

---

### Creation — On Demand

Threat actor notes are created **manually on demand** via an explicit command:

```
create actor note {ActorName}
```

or

```
create campaign note {ActorName} {CampaignSlug}
```

Claude does not auto-create actor or campaign notes during `check mail` runs. Instead, it links new INTEL notes to existing actor notes when a matching threat actor tag is detected (see Auto-Update behaviour below).

On first creation, Claude searches recent conversation history for existing INTEL notes tagged with the actor's threat actor tag (e.g. `#iran` for Handala) and pre-populates the note from that history where possible.

---

### Actor Note Structure

```markdown
---
title: {ActorName}
date: YYYY-MM-DD
type: threat-actor
aliases:
  - ""
origin: ""
motivation: ""
active_since: ""
last_observed: ""
mitre:
  - ""
tags:
  - "#hunt"
  - "#status/active"
  - "{threat-actor-tag}"
---

# Threat Actor — {ActorName}

---

## Overview

| Field | Detail |
|-------|--------|
| **Also Known As** | |
| **Origin** | |
| **Motivation** | |
| **Active Since** | |
| **Last Observed** | |
| **Targeting** | |

---

## TTPs Observed

| Technique ID | Name | First Seen | Source |
|---|---|---|---|
| | | | |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| | |

---

## IOCs

| Type | Value | First Seen | Source |
|------|-------|------------|--------|
| | | | |

---

## Detection Coverage

| KQL Note | Table | Status |
|----------|-------|--------|
| | | |

---

## Campaign History

| Campaign | Period | Summary | Note |
|----------|--------|---------|------|
| | | | |

---

## Intel Feed

> Accumulated summaries from linked INTEL notes — newest first.

### YYYY-MM-DD — {INTEL Note Title}
> One sentence summary. [[INTEL-note-link]]

---

## Hardening Actions

- [ ]
- [ ]

---

## Related Notes

- [[]]

---

## Changelog

| Date | Change |
|------|--------|
| YYYY-MM-DD | Created |
```

---

### Campaign Sub-Note Structure

```markdown
---
title: {ActorName} — {CampaignSlug}
date: YYYY-MM-DD
type: threat-campaign
actor: "[[ACTOR-{ActorName}]]"
period_start: ""
period_end: ""
status: Active
mitre:
  - ""
tags:
  - "#hunt"
  - "#status/active"
  - "{threat-actor-tag}"
---

# Campaign — {ActorName} — {CampaignSlug}

---

## Overview

| Field | Detail |
|-------|--------|
| **Actor** | [[ACTOR-{ActorName}]] |
| **Period** | |
| **Status** | Active / Concluded |
| **Primary Target** | |
| **Initial Access** | |

---

## TTPs

| Technique ID | Name | Detail |
|---|---|---|
| | | |

---

## Timeline

| Date | Event | Source |
|------|-------|--------|
| | | |

---

## IOCs

| Type | Value | First Seen |
|------|-------|------------|
| | | |

---

## Detection Notes

### KQL Stubs

```kql
// Table:
// Schema:
// Purpose:

```

### KQL Coverage

| KQL Note | Status |
|----------|--------|
| | |

---

## Intel Feed

> Summaries from INTEL notes linked to this campaign — newest first.

### YYYY-MM-DD — {INTEL Note Title}
> One sentence summary. [[INTEL-note-link]]

---

## Related Notes

- [[ACTOR-{ActorName}]]
- [[]]

---

## Changelog

| Date | Change |
|------|--------|
| YYYY-MM-DD | Created |
```

---

### Auto-Update Behaviour

When Claude generates an INTEL note during a `check mail` run and that note carries a threat actor tag (e.g. `#iran`, `#north-korea`, `#ransomware`):

1. **Check for an existing actor note** in recent conversation history or vault context
2. **If an actor note exists:**
   - Append a new entry to `## Intel Feed` in the actor note with date, one-sentence summary, and wikilink to the INTEL note
   - Update `last_observed` in frontmatter if the INTEL note date is more recent
   - Append a wikilink to the INTEL note in `## Related Notes`
   - Append a changelog entry: `{date} | Auto-updated from [[INTEL-note-name]]`
   - Deliver the updated actor note in the same zip as the INTEL note
3. **If no actor note exists:** note it in the run output:
   ```
   ℹ️ No actor note found for #iran — run 'create actor note Handala' to start tracking longitudinal context.
   ```
   Do not auto-create the actor note.

Claude does not auto-update campaign sub-notes — campaign association requires explicit judgement about which campaign a new INTEL note belongs to. Dave links INTEL notes to campaigns manually.

---

### Weekly Review Integration

The weekly review widget surfaces actor note activity:

- Any actor notes auto-updated during the week are listed under a new **🎭 Threat Actor Activity** section
- Format: `ACTOR-Handala — updated {n} times this week — last: {INTEL note title}`
- If no actor notes were updated, state clearly: "No threat actor note updates this week."

---


## Generating Obsidian Notes

### Always deliver as `.md` files
Never paste note content inline — always generate a downloadable `.md` file prefixed correctly for the router.

### KQL Query Notes (`KQL-` prefix)
Populate: table, schema, MITRE ATT&CK, purpose, query, validated columns (checkboxes), test results placeholder, Sentinel analytics rule settings, hardening control pair link, tags,changelog.

Validated columns use **Markdown checkboxes**:
```
- [ ] ColumnName — notes
- [ ] ColumnName
```

Common schema issues to flag:
- `RemoteIPAddress` vs `RemoteIP`
- `IpAddress` in `SecurityEvent` — can vary
- `IsExternalUser` in `CloudAppEvents` — confirm availability
- `parse_json(AdditionalFields)` — required for WDAC and many DeviceEvents fields

### Intel Notes (`INTEL-` prefix)
Structure: Source URL, date, MITRE ATT&CK, detection candidate flag, summary (3-4 sentences analyst-grade), relevance to environment, detection notes with KQL stubs, validated columns as checkboxes, hardening actions, related notes (wikilinks), tags, changelog.

### Research/Info Notes (`RESEARCH-` or `INFO-` prefix)
Structure: Source URL, date, type, what it is, relevance to environment, actions, tags, changelog.

### Project Notes (`PROJ-` prefix)
Structure: objective, scope, linked vault notes, actions, decisions log, tags, changelog.

---

## Tag Taxonomy

Every note gets at minimum one **type tag** and one **status tag**.

### Type Tags
| Tag | Used For |
|-----|---------|
| `#intel` | Threat intelligence, active campaigns, advisories |
| `#detection` | KQL queries, analytics rules, hunting queries |
| `#hardening` | Hardening controls and policies |
| `#project` | Project notes and phase documents |
| `#ir` | Incident cases, playbooks, templates |
| `#hunt` | Threat hunting campaigns |
| `#resource` | Tools, training, articles, reference material |
| `#meeting` | Meeting notes |
| `#daily` | Daily notes |
| `#weekly` | Weekly notes |
| `#training` | Personal training session logs |

### Status Tags
| Tag | Meaning |
|-----|---------|
| `#status/draft` | Work in progress |
| `#status/active` | Currently being worked |
| `#status/done` | Complete and validated |
| `#status/review` | Needs review before filing |

### Security Domain Tags
| Tag | Used For |
|-----|---------|
| `#identity` | Entra ID, AD, authentication |
| `#endpoint` | MDE, Intune, Windows hardening |
| `#email` | MDO, phishing, BEC |
| `#cloud` | Azure, M365, MCAS |
| `#ot-scada` | OT/ICS, plant assets |
| `#network` | SMB, NTLM, lateral movement |
| `#wdac` | WDAC/AppControl specific |

### Threat Actor Tags
| Tag | Used For |
|-----|---------|
| `#iran` | Iranian APT (Handala, CL-STA-1128) |
| `#north-korea` | DPRK (Jasper Sleet) |
| `#ransomware` | Ransomware TTPs |
| `#infostealer` | Credential theft |
| `#supply-chain` | Supply chain attacks |

### Utility Tags
| Tag | Used For |
|-----|---------|
| `#export` | Ready to convert to .docx — remove after export |
| `#action-required` | Something needs doing — remove when done |
| `#pending-review` | Content needs manual completion (e.g. X/Twitter links) |

---

## MD to DOCX Exporter

Converts `#export` tagged notes to branded `.docx` files.

```bash
node ~/Documents/md-to-docx/md-to-docx.js ~/Documents/UFA-Security
```

Output lands in `_Exports/` inside the vault. Remove `#export` tag after exporting.

**Branding:** H1 dark forest green (#2D5016), H2 burnt orange (#E8650A), H3 mid green (#4A7C2F). Branded header/footer with CONFIDENTIAL label and page numbers.

---

## Templates

All templates use Templater syntax. Located in `_Templates/` in both vaults.

| Template | Auto-fills |
|----------|-----------|
| Daily Note | Date, week number |
| Weekly Note | Week number, date range, daily note links |
| KQL Query | Date, title from filename |
| Hardening Control | Date, name from filename |
| Hunt Campaign | Date, analyst name |
| Incident Case | Date/time, auto case ID (INC-YYYY-MMDDHHmm) |
| Session (Personal) | Date, day name, prompts for session type and week |
| Meeting | Date/time, type picker dropdown |
| Project | Date, status picker dropdown |

### Folder Templates (configure in Templater settings)
| Folder | Template |
|--------|----------|
| `_Daily/` | Daily-Note-Template |
| `_Weekly/` | Weekly-Note-Template |
| `Detection-KQL/Queries/` | KQL-Query-Template |
| `Hardening/Controls/` | Hardening-Control-Template |
| `Threat-Hunting/Campaigns/` | Hunt-Campaign-Template |
| `IR-DFIR/Cases/` | Incident-Case-Template |
| `Training/Sessions/` | Session-Template |
| `Meetings/` | Meeting-Template |
| `Projects/` | Project-Template |

---

## Plugins

| Plugin | Status | Purpose |
|--------|--------|---------|
| Templater | Installed | Auto-fill templates |
| Dataview | Installed | Live dashboard queries |
| Calendar | Installed | Click-to-create daily notes |
| Periodic Notes | Installed | Auto-create daily/weekly from templates |
| Tag Wrangler | Installed | Rename/merge tags across vault |
| Obsidian Git | Optional | Auto-backup to git |
| Iconize | Installed | Folder icons |

---

## KQL Conventions

- All queries validated against real schema before filing
- Tables used: `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents`, `SecurityEvent`, `AuditLogs`, `SigninLogs`, `CloudAppEvents`, `EmailEvents`
- Always specify schema: Advanced Hunting (MDE) vs Sentinel (Log Analytics)
- Always include Sentinel analytics rule recommendation: frequency, lookback, severity
- Always flag schema validation requirements — column names differ across environments

---

## Active Security Context

### Current Threat Priorities
- **Iranian APT (Handala/CL-STA-1128)** — targeting Intune, Entra ID, and Rockwell Automation OT equipment. Directly relevant.
- **Entra Connect SyncJacking** — GA hardening available, needs applying
- **Service Principal abuse** — Agent ID Administrator role CVE patched April 9 2026, audit role assignments
- **Conditional Access gap** — Registered ≠ Compliant. Audit CA policies. Block device code flow.
- **Infostealer credential exposure** — monitor for domain credential leaks

### Hardening Controls Deployed
Anonymous share enumeration, NTLMv2 enforcement, SMB signing, Autoplay, Network Bridge, IPv6/IPv4 source routing, WMI persistence, LSA protection (RunAsPPL), LDAP signing/channel binding/sealing, local credential storage, ASR policy monitoring.

### Active Projects
- **WDAC Deployment** — Not started. 4 phases. AppControl Manager as primary tool. See WDAC project.
- **OT/SCADA Assessment** — Fertilizer plant. Nmap/OpenVAS/Wazuh deployed. Illumio evaluation pending.
- **M365 Hardening** — Ongoing. SyncJacking and CA policy gaps are priority items.

### OT/SCADA Context
Recently acquired fertilizer plant. Regulatory scope: CFIA Fertilizers Act, Explosives Act (ammonium nitrate), TDG. Network segmentation not yet confirmed. Corroborated Iranian APT threat targeting Rockwell/Allen-Bradley PLCs — treat as urgent.

---

## Personal Vault Structure

```
Personal-Vault/
├── Home.md
├── Training/
│   ├── Programme/
│   │   └── 12-Week-Upper-Lower.md   ← Current programme — Week 4 starts Apr 28
│   ├── Sessions/                    ← YYYY-MM-DD-Upper-A.md format
│   └── Lifts/
│       └── Lift-Progression.md      ← Historical data from Sept 2025
├── Golf/
├── _Daily/
└── _Templates/
    └── Session-Template.md
```

### Training Programme Context
- **Programme:** 12-week Upper/Lower split
- **Schedule:** Mon/Tue/Thu/Fri
- **Current week:** 4 (starts Apr 28, 2026)
- **Right shoulder:** Minor rotator cuff issue — Face Pulls mandatory every Upper session
- **All weights in lbs**

Current working weights (end of Week 3):

| Session | Key Lifts | Weight |
|---------|-----------|--------|
| Upper A | DB Bench Press | 45/hand |
| Upper A | Bent Over BB Row | 185 |
| Lower A | Back Squat | 205 |
| Lower A | Deadlift | 225 |
| Upper B | DB Bench Press | 50/hand |
| Lower B | Hack Squat | 280 |
| Lower B | Calf Press | 350 |
| Lower B | Bulgarian Split Squat | 70/hand ↓ monitor |

---

## Output Preferences
- Always generate `.md` files — never paste note content inline
- Always prefix filenames correctly for the router
- Deliver as downloadable `.md` files, or zipped batches for multiple files
- Never refer to the employer by name
- Flag `#action-required` on notes that need immediate attention
- Flag `#pending-review` on notes where source content couldn't be fetched