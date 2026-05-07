---
date: <% tp.date.now("YYYY-MM-DD") %>
title: <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
table: ""
schema: ""
mitre: ""
tactic: ""
technique: ""
status: "Draft"
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
---

# KQL — <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>

---

**Table:** | **Schema:** <% await tp.system.suggester(["Advanced Hunting", "Sentinel / Log Analytics"], ["Advanced Hunting", "Sentinel / Log Analytics"], false, "Select schema") %>
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** <% tp.date.now("YYYY-MM-DD") %> | **Status:** `Draft`

---

## Purpose


---

## Query

```kql

```

---

## Validated Columns
- [ ] 
- [ ] 

---

## Test Results


---

## Sentinel Analytics Rule
- **Rule Name:** <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [ ]

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
