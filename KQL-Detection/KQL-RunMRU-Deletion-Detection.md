---
date: 2026-05-14
title: RunMRU Deletion Detection
table: "DeviceProcessEvents, DeviceRegistryEvents"
schema: "Advanced Hunting"
mitre: "T1070.001"
tactic: "Defense Evasion"
technique: "Indicator Removal: Clear Windows Event Logs"
status: "Draft"
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/query"
  - "#endpoint"
  - "#status/draft"
---

# KQL — RunMRU Deletion Detection

---

**Table:** `DeviceProcessEvents`, `DeviceRegistryEvents` | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1070.001 | **Tactic:** Defense Evasion | **Technique:** Indicator Removal — Clear Windows Event Logs
**Created:** 2026-05-14 | **Status:** `Draft`

---

## Purpose

Detects deletion or clearing of the Windows RunMRU registry key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`), a common post-exploitation cleanup step used to remove evidence of executed commands from the Run dialog history. Two detection branches are unioned: process-based telemetry catches `reg.exe` and PowerShell invocations via command line; registry event telemetry catches all deletion methods including `regedit.exe`, WMI-driven deletions, and direct API calls that bypass the process command line entirely.

---

## Query

```kql
// RunMRU Deletion Detection - Process & Registry Telemetry
// Covers reg.exe, PowerShell, and direct registry write events
// MITRE: T1070.001 — Indicator Removal: Clear Windows Event Logs

// Branch 1: Process-based detection (reg.exe + PowerShell)
let RunMRU_Key = @"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";

// Branch 1: Process-based detection (reg.exe + PowerShell)
let ProcessBased = DeviceProcessEvents
| where Timestamp > ago(24h)
| where (
    // reg.exe delete via CLI
    (FolderPath endswith @"\reg.exe"
        and ProcessCommandLine has_all ("delete", "RunMRU"))
    or
    // PowerShell via Remove-Item or reg delete
    (FileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has_any ("Remove-Item", "RemoveItem", "reg delete")
        and ProcessCommandLine has "RunMRU")
)
| extend DetectionSource = "ProcessEvent"
| project
    Timestamp,
    DetectionSource,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ReportId,
    DeviceId;

  

// Branch 2: Registry event telemetry (catches ALL deletion methods)
let RegistryBased = DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType in ("RegistryKeyDeleted", "RegistryValueDeleted")
| where RegistryKey has "RunMRU"
| extend DetectionSource = "RegistryEvent"
| project
    Timestamp,
    DetectionSource,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain,
    InitiatingProcessFileName,
    FileName = InitiatingProcessFileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    FolderPath = InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    LogonId = InitiatingProcessAccountName,
    ReportId,
    DeviceId;

  

// Union both branches and enrich
ProcessBased
| union RegistryBased
| extend
    // Flag highly suspicious initiating processes
    SuspiciousParent = InitiatingProcessParentFileName in~ (
        "wscript.exe", "cscript.exe", "mshta.exe",
        "winword.exe", "excel.exe", "outlook.exe",
        "cmd.exe", "powershell.exe", "pwsh.exe"
    ),
    // Flag non-interactive/service accounts
    IsServiceAccount = AccountName has_any ("$", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| extend RiskScore = case(
    SuspiciousParent == true and IsServiceAccount == false, "High",
    SuspiciousParent == false and IsServiceAccount == false, "Medium",
    "Low"
)

| project-reorder
    Timestamp, RiskScore, DetectionSource, DeviceName,
    AccountName, AccountDomain, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessParentFileName, SuspiciousParent,
    IsServiceAccount, LogonId, ReportId, DeviceId
| sort by Timestamp desc
```

---

## Validated Columns

### DeviceProcessEvents
- [ ] `FolderPath` — used to match `\reg.exe` path suffix
- [ ] `FileName` — case-insensitive match via `in~`
- [ ] `ProcessCommandLine` — `has_all` / `has_any` (index-aware)
- [ ] `InitiatingProcessFileName` — available ✓
- [ ] `InitiatingProcessCommandLine` — available ✓
- [ ] `InitiatingProcessParentFileName` — available ✓
- [ ] `LogonId` — available ✓
- [x] No columns called AccountName or AccountDomain. Correct columns are  InitiatingProcessAccountName  and  InitiatingProcessAccountDomain

### DeviceRegistryEvents
- [ ] `ActionType` — validate `"RegistryKeyDeleted"` and `"RegistryValueDeleted"` values against your tenant; ActionType values can vary by MDE sensor version
- [ ] `RegistryKey` — used with `has "RunMRU"` — confirm field contains full key path in your environment
- [ ] `InitiatingProcessFileName` — aliased to `FileName` for union compatibility ✓
- [ ] `InitiatingProcessCommandLine` — aliased to `ProcessCommandLine` for union compatibility ✓
- [ ] `InitiatingProcessFolderPath` — aliased to `FolderPath` ✓
- [ ] `InitiatingProcessLogonId` — aliased to `LogonId` ✓
- [ ] There is no column called InitiatingProcessLogonId either 

---

## Test Results

- [ ] ProcessBased branch tested
- [ ] RegistryBased branch tested
- [ ] Union output validated — no column mismatch errors
- [ ] `RiskScore` logic validated against sample data
- [ ] False positive rate assessed

---

## Deployment

> DeviceProcessEvents and DeviceRegistryEvents are both Advanced Hunting tables — deploy as MDE Custom Detection.

### MDE Custom Detection Rule
- **Rule Name:** `Custom - RunMRU Deletion Detection`
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** Medium
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule Name:** <!-- Populate mde_rule_name in frontmatter when deployed -->

<!-- INACTIVE: Sentinel Analytics Rule — not applicable; DeviceProcessEvents and DeviceRegistryEvents are Advanced Hunting tables only
### Sentinel Analytics Rule
- Not applicable for this query
-->

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
| 2026-05-14 | Created — hardened version covering reg.exe, PowerShell, and DeviceRegistryEvents telemetry |
