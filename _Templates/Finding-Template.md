---
title: "<% tp.file.title %>"
date: <% tp.date.now("YYYY-MM-DD") %>
case_id: 
alert_id: 
severity: <!--- Low | Medium | High | Critical --->
status: open
tags:
  - "#ir"
  - "#finding"
  - "#status/draft"
---

# <% tp.file.title %>

**Date:** <% tp.date.now("YYYY-MM-DD HH:mm") %>
**Analyst:** 
**Severity:** 
**Status:** Open

---

## Source

| Field | Value |
|-------|-------|
| Alert / Signal | |
| Platform | <!--- MDE \| Sentinel \| MDO \| MCAS \| Manual --->  |
| Affected Asset(s) | |
| Affected User(s) | |
| Detection Time | |
| Triage Time | |

---

## Observation

<!-- What did you see? Raw signal, alert title, or hunting result. 2-4 sentences. -->

---

## Investigation Notes

<!-- What did you do? Pivots, queries run, correlated events. Use sub-headings if needed. -->

### KQL Pivots

```kql
// Paste relevant queries here
```

### Timeline

| Time (UTC) | Event |
|------------|-------|
| | |
| | |

---

## Assessment

**Verdict:** <!--- True Positive \| False Positive \| Benign \| Undetermined --->

<!-- Why. What made this a TP/FP. -->

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | |
| Technique | |
| Sub-technique | |

---

## Actions Taken

- [ ] 
- [ ] 

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[]]
- [ ] No — closing as

---

## Related Notes

- 

---

## Changelog

| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Finding created |
