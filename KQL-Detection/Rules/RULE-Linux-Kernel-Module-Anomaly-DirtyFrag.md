---
date: 2026-05-13
title: Linux Kernel Module Anomaly DirtyFrag
table: "DeviceProcessEvents, DeviceInfo"
schema: "Advanced Hunting"
type: detection
mitre: "T1215"
tactic: "Persistence"
technique: "Kernel Modules and Extensions"
status: "Deployed"
promoted_to_rule: true
mde_rule_name: "Custom - Linux Kernel Module Anomaly DirtyFrag"
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/active"
  - "#endpoint"
---

# RULE — Linux Kernel Module Anomaly DirtyFrag

---

**Table:** DeviceProcessEvents (joined with DeviceInfo) | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1215 | **Tactic:** Persistence | **Technique:** Kernel Modules and Extensions
**Created:** 2026-05-13 | **Status:** `Deployed`

---

## Purpose

Detect kernel module loading and unloading activity targeting modules associated with the Dirty Frag vulnerability (CVE-2023-3776): `esp4`, `esp6`, `rxrpc`, and `xfrm`. 

Dirty Frag mitigation involves unloading these modules; an adversary who has achieved code execution may attempt to reload them to re-enable the vulnerable code path, or manipulate them to maintain access. `modprobe`, `insmod`, and `rmmod` targeting these specific modules have no routine administrative baseline in this environment.

Low expected volume — suitable as a scheduled MDE Custom Detection rule.

---

## Query

```kql
let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceName;
DeviceProcessEvents
| where DeviceName in (LinuxDevices)
| where FileName in ("modprobe", "insmod", "rmmod")
| where ProcessCommandLine has_any ("esp4", "esp6", "rxrpc", "xfrm")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `FileName` — confirm `modprobe`, `insmod`, `rmmod` are captured as process names on Linux MDE agents
- [ ] `ProcessCommandLine` — confirm module name arguments are populated for kernel tool invocations on Linux agents
- [ ] `OSPlatform` — in `DeviceInfo`, not `DeviceProcessEvents`; join via `let LinuxDevices` (implemented)

---

## Test Results

- [ ] Ran against 30-day lookback — zero results (expected; no module manipulation baseline)
- [ ] Confirmed `let LinuxDevices` join returns expected Linux hosts
- [ ] Validated module name strings fire on: `esp4`, `esp6`, `rxrpc`, `xfrm`

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-13 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | Custom - Linux Kernel Module Anomaly DirtyFrag |
| **Deployed** | 2026-05-14 |

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Linux Kernel Module Anomaly DirtyFrag
- **Frequency:** Every 1 hour
- **Lookback:** 1 hour
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [x] 2026-05-14

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

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-13 | Created — promoted from KQL draft via `promote rule`; companion to Dirty Frag hunting queries |
| 2026-05-14 | Deployed to MDE Custom Detection — rule name: Custom - Linux Kernel Module Anomaly DirtyFrag |
