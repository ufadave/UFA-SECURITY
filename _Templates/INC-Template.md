---
date: <% tp.date.now("YYYY-MM-DD") %>
title: <% tp.file.title %>
type: ticket
snow_id: <% tp.file.title %>
category: ""
status: "Open"
priority: ""
assigned_to: Dave
affected_user: ""
affected_asset: ""
closed: ""
tags:
  - "#ticket"
  - "#status/active"
---

# <% tp.file.title %>

**Opened:** <% tp.date.now("YYYY-MM-DD") %> | **Status:** `Open` | **Priority:** 
**Category:** <!--- Security Alert | User Request | System Issue | Other --->

---

## Description

> What is this ticket about? Copy the ServiceNow short description or summarise in 1-2 sentences.


---

## Affected

| Field | Detail |
|-------|--------|
| **User** | |
| **Asset / Host** | |
| **System / Service** | |

---

## Investigation Notes

> Steps taken, pivots, observations. Date-stamp each session.

### <% tp.date.now("YYYY-MM-DD") %>


---

## KQL Run

```kql

```

---

## Actions Taken
- [ ] 
- [ ] 

---

## Outcome

**Resolution:**
**Root Cause:**
**Closed:** 

---

## Escalate to IR Case?
- [ ] Yes — create `IR-` case note: [[]]
- [ ] No — resolving within ticket

---

## Related Notes
- [[]]

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
