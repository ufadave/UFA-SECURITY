---
date: <% tp.date.now("YYYY-MM-DD") %>
title: <% tp.file.title.replace("IRQUERY-", "").replaceAll("-", " ") %>
type: ir-query
case_id: ""
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
  - "#ir"
  - "#status/draft"
---

# KQL IR — <% tp.file.title.replace("IRQUERY-", "").replaceAll("-", " ") %>

---

**Table:** | **Schema:** <% await tp.system.suggester(["Advanced Hunting", "Sentinel / Log Analytics"], ["Advanced Hunting", "Sentinel / Log Analytics"], false, "Select schema") %>
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** <% tp.date.now("YYYY-MM-DD") %> | **Status:** `Draft`

---

## Case Context

| Field | Detail |
|-------|--------|
| **Case ID** | |
| **Incident** | [[]] |
| **Question This Answers** | |
| **Timeframe** | |

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

## Results

| Timestamp | Host | User | Observation |
|-----------|------|------|-------------|
| | | | |

---

## Interpretation

> What do the results tell you? What does absence of results tell you?


---

## Promote to Detection?

> If this query surfaces consistent signal worth automating, run `promote detection <% tp.file.title %>`.
> This will create a new `KQL-` draft note with the deployment section pre-populated.

- [ ] Yes — signal is consistent and worth automating
- [ ] No — retain as IR query

---

## Related Notes
- [[]]

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
