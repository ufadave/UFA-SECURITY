---
date: <% tp.date.now("YYYY-MM-DD") %>
owner: Dave
status: ""
tags:
  - "#project"
  - "#status/active"
---

# Project — <% tp.system.prompt("Project name?") %>

---

## Objective
<% tp.file.cursor(1) %>

---

## Scope


---

## Linked Vault Notes


---

## Actions
- [ ] <% tp.file.cursor(2) %>
- [ ] 
- [ ] 

---

## Decisions Log
| Date | Decision |
|------|----------|
| <% tp.date.now("YYYY-MM-DD") %> | Project created |

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
