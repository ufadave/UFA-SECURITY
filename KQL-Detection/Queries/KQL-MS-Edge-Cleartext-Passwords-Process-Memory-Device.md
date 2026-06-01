---
date: 2026-05-28
title: MS Edge Cleartext Passwords Process Memory Device
table: DeviceProcessEvents, DeviceFileEvents
schema: Advanced Hunting
mitre:
  - T1555.003
  - T1003
tactic: Credential Access
technique: "T1555.003 — Credentials from Web Browsers; T1003 — OS Credential Dumping"
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#endpoint"
  - "#identity"
---

# KQL — MS Edge Cleartext Passwords Process Memory Device

**Table:** DeviceProcessEvents, DeviceFileEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1555.003, T1003 | **Tactic:** Credential Access
**Created:** 2026-05-28 | **Status:** `Draft`

---

## Purpose

Three detection stubs covering the device-side signals for Microsoft Edge cleartext password extraction from process memory. An attacker with local access can dump the Edge renderer or utility process memory and extract plaintext credentials stored in the built-in password manager.

- **Stub 1 (DeviceProcessEvents):** Memory dump tools targeting Edge process names — procdump, Task Manager `comsvcs.dll MiniDump`, or similar
- **Stub 2 (DeviceProcessEvents):** Sysinternals `strings.exe` execution following an Edge dump — post-processing step to extract readable content from a dmp file
- **Stub 3 (DeviceFileEvents):** `.dmp` file creation in temp/appdata paths — the output artefact; catches dump tools not caught by Stub 1 (e.g. custom code)

> **Note:** A companion note `KQL-Edge-Password-Memory-Dump-Detection` is linked from the source INTEL note. Confirm whether that note covers different signals before deploying both — check for overlap and merge or deduplicate as appropriate.

---

## Query

```kql
// Stub 1 — Memory dump tools targeting Microsoft Edge process
// Covers: procdump, Task Manager, comsvcs.dll MiniDump via rundll32
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("procdump.exe", "procdump64.exe", "taskmgr.exe", "comsvcs.dll")
     or (FileName =~ "rundll32.exe" and ProcessCommandLine has "MiniDump")
| where ProcessCommandLine has_any ("msedge", "edge", "browser")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Stub 2 — Strings.exe execution after an Edge dump (credential extraction post-processing)
// Sysinternals strings on a .dmp file is a strong indicator of credential harvesting
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("strings.exe", "strings64.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

```kql
// Stub 3 — .dmp file creation in Temp/AppData/Downloads
// Catches custom dump tools and Task Manager dumps not covered by Stub 1
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".dmp"
| where FolderPath has_any ("Temp", "AppData", "Downloads")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath,
          InitiatingProcessFileName
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `FileName` — DeviceProcessEvents ✓ standard column
- [ ] `ProcessCommandLine` — DeviceProcessEvents ✓ standard column; confirm `has_any` on Edge process names matches your environment's Edge binary naming
- [ ] `InitiatingProcessFileName` — DeviceProcessEvents ✓ standard column
- [ ] `FolderPath` — DeviceProcessEvents, DeviceFileEvents ✓ standard column
- [ ] `ActionType` — DeviceFileEvents ✓ confirm `"FileCreated"` is a valid value
- [ ] `InitiatingProcessAccountName` — DeviceFileEvents — confirm field name (vs `AccountName`)

---

## Test Results

- [ ] Tested in environment
- [ ] Stub 1: check for legitimate procdump use by IT/support staff
- [ ] Stub 2: baseline — strings.exe is rare on corporate endpoints; low FP expected
- [ ] Stub 3: moderate FP risk from application crash dumps; tune `FolderPath` exclusions for known app crash dump paths
- [ ] FP rate acceptable

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Edge Process Memory Dump Credential Extraction
- **Frequency:** every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

> Consider deploying Stub 1 and Stub 2 together as one rule; Stub 3 separately with additional FP tuning.

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceProcessEvents and DeviceFileEvents are Advanced Hunting only -->
<!-- Deploy via MDE Custom Detection -->

---

## Hardening Control Pair
- **Control:** [[HARD-Disable-Edge-Built-In-Password-Manager]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-MS-Edge-Cleartext-Passwords-Process-Memory]]
- [[KQL-Edge-Password-Memory-Dump-Detection]] — check for overlap before deploying both

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-28 | Created — backfill companion to [[INTEL-MS-Edge-Cleartext-Passwords-Process-Memory]] via backfill stubs command; note [[KQL-Edge-Password-Memory-Dump-Detection]] also linked from source — confirm coverage before deploying |
