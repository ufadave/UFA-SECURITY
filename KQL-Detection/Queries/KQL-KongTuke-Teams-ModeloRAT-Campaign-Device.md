---
date: 2026-05-18
title: KongTuke Teams ModeloRAT Campaign Device
table: "DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents"
schema: "Advanced Hunting"
mitre: "T1059.001, T1105, T1547.001, T1053.005"
tactic: "Execution, Persistence, Command and Control"
technique: "PowerShell, Ingress Tool Transfer, Registry Run Keys, Scheduled Task"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#endpoint"
  - "#ransomware"
---

# KQL — KongTuke Teams ModeloRAT Campaign Device

---

**Table:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1059.001, T1105, T1547.001 | **Tactic:** Execution, Persistence, C2 | **Technique:** PowerShell, Ingress Tool Transfer, Run Key
**Created:** 2026-05-18 | **Status:** `Draft`

---

## Purpose

Detect ModeloRAT deployment artifacts from KongTuke's Microsoft Teams-based social engineering campaign. ModeloRAT uses a portable WinPython runtime dropped under `%APPDATA%`, launched by a PowerShell command delivered via Teams. Four queries covering process execution, network C2 beaconing, ZIP staging, and Run key persistence.

---

## Query — 1: Portable Python Execution from AppData

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect pythonw.exe executing from user-writable AppData paths — hallmark of ModeloRAT portable Python runtime

let suspiciousPythonPaths = dynamic(["\\AppData\\Roaming\\WPy", "\\AppData\\Local\\WPy", "\\AppData\\Roaming\\Python", "\\AppData\\Local\\Python"]);
DeviceProcessEvents
| where FileName =~ "pythonw.exe" or FileName =~ "python.exe"
| where FolderPath has_any (suspiciousPythonPaths)
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Query — 2: ModeloRAT C2 Beaconing

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect network connections from pythonw.exe running from AppData — ModeloRAT C2 beaconing

let suspiciousPythonPaths = dynamic(["\\AppData\\Roaming\\WPy", "\\AppData\\Local\\WPy"]);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "pythonw.exe"
| where InitiatingProcessFolderPath has_any (suspiciousPythonPaths)
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Query — 3: ZIP Staging Under AppData

```kql
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect ZIP file creation/extraction under %APPDATA% — initial staging of ModeloRAT toolkit

DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName endswith ".zip" or FolderPath has "\\AppData\\"
| where FolderPath has "\\AppData\\"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "explorer.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Query — 4: Run Key Persistence

```kql
// Table: DeviceRegistryEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Run key persistence pointing to pythonw.exe in AppData — ModeloRAT persistence mechanism

DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "\\CurrentVersion\\Run"
| where RegistryValueData has_any ("pythonw.exe", "WPy64", "AppData")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `FolderPath` — DeviceProcessEvents (confirm vs `ProcessFolderPath`)
- [ ] `InitiatingProcessFolderPath` — DeviceNetworkEvents
- [ ] `RemoteIPType` — DeviceNetworkEvents, confirm available
- [ ] `RegistryValueData` — DeviceRegistryEvents, confirm exact column name
- [ ] `ActionType` values in DeviceFileEvents — verify "FileCreated" vs schema

---

## Test Results

<!-- Run in Advanced Hunting. Expected: low-volume or zero results on healthy estate. Any hit on WPy64 paths warrants immediate investigation. -->

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** KongTuke Teams ModeloRAT Campaign Device
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** `Alert only` — escalate to Isolate if confirmed
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

<!-- INACTIVE: Sentinel Analytics Rule
Source table is Advanced Hunting — deploy as MDE Custom Detection, not Sentinel Analytics Rule. -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

## Related Notes
- [[INTEL-KongTuke-Teams-ModeloRAT-Campaign]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-18 | Created — companion to [[INTEL-KongTuke-Teams-ModeloRAT-Campaign]] |
