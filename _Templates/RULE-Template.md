---
date: 2026-05-14
title: KQL RunMRU Deletion Detection
type: detection
table: ""
schema: ""
mitre: ""
tactic: ""
technique: ""
status: "Validated"
promoted_to_rule: true
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/active"
---

# RULE — KQL RunMRU Deletion Detection

---

**Table:** | **Schema:**
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** 2026-05-14 | **Status:** `Validated`

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

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-14 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | <!-- Must match name in MDE portal exactly — prefix "Custom - " required --> |
| **Deployed** | [ ] |

---

## Deployment

### MDE Custom Detection Rule
<!-- Default for all device-based detections — DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents -->
- **Rule Name:** <!-- "Custom - " prefix required for queue visibility -->
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Actions:** `<!-- Alert only | Isolate device | Restrict app execution | Run AV scan -->`
- **Deployed:** [ ]
- **Rule Name (frontmatter):** <!-- Populate mde_rule_name in frontmatter when deployed -->

<!-- INACTIVE: Sentinel Analytics Rule — remove this comment block if schema is Sentinel / Log Analytics
### Sentinel Analytics Rule
- **Rule Name:**
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->
-->

---

## Tuning Notes

> Document exclusions, known false positive patterns, and any AllowedLists here.

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
| 2026-05-14 | Created |
