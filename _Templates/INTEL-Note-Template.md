---
title: <% tp.file.title %>
date: <% tp.date.now("YYYY-MM-DD") %>
source: ""
author: ""
mitre:
  - ""
detection_candidate: false
tags:
  - "#intel"
  - "#status/draft"
---

# <% tp.file.title %>

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | |
| **Author** | |
| **Date Observed** | <% tp.date.now("YYYY-MM-DD") %> |
| **Date Published** | |
| **Patch Available** | |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| | |

---

## Summary

> 3–4 sentences. Analyst-grade. What happened, how, and why it matters.

---

## Relevance to Environment

> How does this apply to your organisation specifically? Consider: Entra ID, MDE endpoints, OT/SCADA plant, POS terminals, hybrid AD, MDO email surface.

---

## Detection Notes

> Flag as `detection_candidate: true` in frontmatter if a KQL opportunity exists.

### KQL Stubs

```kql
// Table: 
// Schema: Advanced Hunting (MDE) / Log Analytics (Sentinel)
// Purpose: 

```

### Validated Columns
- [ ] — 
- [ ] — 

---

## Hardening Actions

- [ ] 
- [ ] 

---

## Related Notes

- [[]]
- [[]]

---

## Tags

> Review and update before changing status to active.
> Add threat actor tag if applicable: #iran #north-korea #ransomware #infostealer #supply-chain
> Add domain tag: #identity #endpoint #email #cloud #ot-scada #network #wdac

---

## Changelog

| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
