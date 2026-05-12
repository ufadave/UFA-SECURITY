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
mde_rule_name: ""
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

## Deployment

> Default path is MDE Custom Detection. Only use Sentinel Analytics Rule for signals that do not exist in Advanced Hunting — identity (SigninLogs, AuditLogs), cloud (CloudAppEvents), and email (EmailEvents).

### MDE Custom Detection Rule
<!-- Default for all device-based detections — DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, etc. -->
- **Rule Name:** <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Actions:** `<!-- Alert only | Isolate device | Restrict app execution | Run AV scan -->`
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- Use only for Log Analytics sources — SigninLogs, AuditLogs, CloudAppEvents, EmailEvents, OfficeActivity, SecurityEvent (if ingested) -->
- **Rule Name:** <% tp.file.title.replace("KQL-", "").replaceAll("-", " ") %>
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Changelog
| Date | Change |
|------|--------|
| <% tp.date.now("YYYY-MM-DD") %> | Created |
