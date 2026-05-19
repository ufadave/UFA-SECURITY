---
date: <% tp.date.now("YYYY-MM-DD") %>
title: <% tp.file.title.replace("HUNTING-", "").replaceAll("-", " ") %>
type: hunting
table: ""
schema: ""
mitre: ""
tactic: ""
technique: ""
status: "Draft"
saved_in: ""
query_name: ""
tags:
  - "#detection"
  - "#detection/hunting"
  - "#hunt"
  - "#status/draft"
---

# KQL Hunting — <% tp.file.title.replace("HUNTING-", "").replaceAll("-", " ") %>

---

**Table:** | **Schema:** <% await tp.system.suggester(["Advanced Hunting", "Sentinel / Log Analytics"], ["Advanced Hunting", "Sentinel / Log Analytics"], false, "Select schema") %>
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** <% tp.date.now("YYYY-MM-DD") %> | **Status:** `Draft`

---

## Hypothesis

> "I believe [threat actor / behaviour] is occurring because [evidence / intuition], which I can test by [method]."


---

## Purpose


---

## Query

```kql

```

---

## Saved Query

| Field | Detail |
|-------|--------|
| **Saved In** | `Personal` / `Shared` / `Not saved` |
| **Query Name** | |

---

## Validated Columns
- [ ] 
- [ ] 

---

## Findings

| Timestamp | Host | User | Observation | Disposition |
|-----------|------|------|-------------|-------------|
| | | | | `Benign` / `Suspicious` / `Confirmed TTP` |

---

## Promote to Detection?

> If this query has consistent signal worth automating, run `promote detection <% tp.file.title %>`.
> This will create a new `KQL-` draft note with the deployment section pre-populated.

- [ ] Yes — signal is consistent and worth automating
- [ ] No — retain as hunting query

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[]]

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
