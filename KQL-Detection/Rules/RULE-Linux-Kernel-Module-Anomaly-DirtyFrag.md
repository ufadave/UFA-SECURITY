---
date: 2026-05-13
title: Linux Kernel Module Anomaly DirtyFrag
table: "DeviceProcessEvents, DeviceInfo"
schema: "Advanced Hunting"
type: detection
mitre: "T1215"
tactic: "Persistence"
technique: "Kernel Modules and Extensions"
status: "Validated"
promoted_to_rule: false
mde_rule_name: "Custom - Linux Kernel Module Anomaly DirtyFrag"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
---

# RULE — Custom - Linux Kernel Module Anomaly DirtyFrag

---

**Table:** DeviceProcessEvents (joined with DeviceInfo) | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1215 | **Tactic:** Persistence | **Technique:** Kernel Modules and Extensions
**Created:** 2026-05-13 | **Status:** `Validated`

---

## Purpose

Detect kernel module loading and unloading activity targeting modules associated with the Dirty Frag vulnerability (CVE-2023-3776): `esp4`, `esp6`, `rxrpc`, and `xfrm`. 

Dirty Frag mitigation involves unloading these modules; an adversary who has achieved code execution may attempt to reload them to re-enable the vulnerable code path, or manipulate them to maintain access. `modprobe`, `insmod`, and `rmmod` targeting these specific modules have no routine administrative baseline in this environment.

Low expected volume — suitable as a scheduled MDE Custom Detection rule.

---

## Query

```kql
// Table: DeviceProcessEvents (joined with DeviceInfo for OSPlatform)
// Schema: Advanced Hunting (MDE)
// Purpose: Detect kernel module loading/unloading anomalies — esp4, esp6, rxrpc activity
// Dirty Frag mitigation involves unloading these modules; adversary may attempt to reload

let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceName;
DeviceProcessEvents
| where DeviceName in (LinuxDevices)
| where FileName in ("modprobe", "insmod", "rmmod")
| where ProcessCommandLine has_any ("esp4", "esp6", "rxrpc", "xfrm")
| project Timestamp, DeviceName,DeviceId, ReportId, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
---
## Validated Columns
- [x] `FileName` — confirm `modprobe`, `insmod`, `rmmod` are captured as process names on Linux MDE agents
- [x] `ProcessCommandLine` — confirm module name arguments are populated for kernel tool invocations on Linux agents
- [x] `OSPlatform` — in `DeviceInfo`, not `DeviceProcessEvents`; join via `let LinuxDevices` (implemented)

---

## Test Results

- [x] Ran against 30-day lookback — zero results (expected; no module manipulation baseline)
- [x] Confirmed `let LinuxDevices` join returns expected Linux hosts
- [ ] Validated module name strings fire on: `esp4`, `esp6`, `rxrpc`, `xfrm`

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-13 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | Linux Kernel Module Anomaly DirtyFrag |
| **Rule ID** | <!-- Populate mde_rule_id in frontmatter when deployed --> |

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Linux Kernel Module Anomaly DirtyFrag
- **Frequency:** Every 1 hour
- **Lookback:** 1 hour
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->

<!-- INACTIVE: Sentinel Analytics Rule — Advanced Hunting schema; deploy via MDE Custom Detection only
- **Rule Name:** Linux Kernel Module Anomaly DirtyFrag
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [ ]
- **Rule GUID:**
-->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes

- [[HUNTING-Linux-Unexpected-Privilege-Escalation]]
- [[HUNTING-Linux-SUID-Binary-Execution]]
- [[PLAYBOOK-Linux-Kernel-Module-Alert]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-13 | Created — promoted from KQL draft via `promote rule`; companion to Dirty Frag hunting queries |
