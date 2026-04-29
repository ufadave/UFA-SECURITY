---
date: <% tp.date.now("YYYY-MM-DD HH:mm") %>
case_id: INC-<% tp.date.now("YYYY") %>-<% tp.date.now("MMDDHHmm") %>
severity: ""
type: ""
status: "Open"
closed: ""
tags:
  - "#ir"
  - "#status/active"
---

# Incident — <% tp.file.title.replace("IR-", "").replaceAll("-", " ") %>

---

## Summary


---

## Timeline
| Timestamp (UTC) | Event |
|-----------------|-------|
| <% tp.date.now("YYYY-MM-DD HH:mm") %> | Incident opened |

---

## Affected Assets
| Host | User | Impact |
|------|------|--------|
|  |  |  |

---

## Evidence Log
| Artifact | Source | Hash / Reference |
|----------|--------|-----------------|
|  |  |  |

---

## Actions Taken
- [ ] 
- [ ] 

---

## Root Cause


---

## Lessons Learned


---

## Linked Notes


---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
