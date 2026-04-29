---
date: <% tp.date.now("YYYY-MM-DD") %>
title: <% tp.file.title.replace("HUNT-", "").replaceAll("-", " ") %>
analyst: Dave
mitre: ""
tactic: ""
technique: ""
status: "Active"
tags:
  - "#hunt"
  - "#status/active"
---

# Hunt Campaign — <% tp.file.title.replace("HUNT-", "").replaceAll("-", " ") %>

---

## Hypothesis
> "I believe [threat actor / behaviour] is occurring because [evidence / intuition], which I can test by [method]."


---

## Scope
- **Environment:** 
- **Timeframe:** <% tp.date.now("YYYY-MM-DD") %> → 
- **Data Sources:**

---

## Queries Used


---

## Findings
| Timestamp | Host | User | Observation | Disposition |
|-----------|------|------|-------------|-------------|
|  |  |  |  | `Benign` / `Suspicious` / `Confirmed TTP` |

---

## Conclusion


---

## Follow-on Actions
- [ ] 
- [ ] 

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
