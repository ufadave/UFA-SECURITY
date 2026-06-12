---
date: 2026-06-11
title: "RoguePlanet MsMpEng Shell Spawn Detection"
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1068"
tactic: "Privilege Escalation"
technique: "Exploitation for Privilege Escalation"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#endpoint"
---

# KQL — RoguePlanet MsMpEng Shell Spawn Detection

---

## Purpose

Detects an interactive shell or scripting host (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `conhost.exe`, `cscript.exe`, `wscript.exe`) spawned by the Microsoft Defender engine (`MsMpEng.exe`) at SYSTEM integrity. This is the primary and highest-fidelity detection for RoguePlanet-class TOCTOU/path-redirection privilege escalation attacks against Defender. Defender never legitimately spawns interactive shells — a hit here is, for practical purposes, a confirmed exploitation event.

Covers the full Nightmare Eclipse toolchain (BlueHammer, RedSun, RoguePlanet) and any future variant of this exploit class.

---

## Query

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "cscript.exe",
    "wscript.exe"
)
| where ProcessIntegrityLevel == "System"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    ProcessIntegrityLevel
| order by Timestamp desc
```

---

## Validated Columns

- [x] `InitiatingProcessFileName` — `DeviceProcessEvents` — standard, confirmed
- [x] `FileName` — `DeviceProcessEvents` — standard, confirmed
- [x] `ProcessIntegrityLevel` — `DeviceProcessEvents` — confirm availability in your tenant (present in modern MDE schemas; values: Low, Medium, High, System)
- [x] `InitiatingProcessParentFileName` — `DeviceProcessEvents` — standard, confirm
- [x] `ProcessCommandLine` — `DeviceProcessEvents` — standard, confirmed

---

## Test Results

<!-- Paste CSV results here after running in Advanced Hunting -->

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - MsMpEng Spawning Interactive Shell (RoguePlanet LPE)` |
| **Table** | `DeviceProcessEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **MITRE** | T1068 — Exploitation for Privilege Escalation |
| **Actions** | Isolate device; alert SOC; tag entity |
| **False Positive Risk** | None expected — Defender does not spawn interactive shells in normal operation |

<!-- INACTIVE: Sentinel Analytics Rule — this table is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- [[PROJ-WDAC-Phase1-Audit]] — Application allowlisting is the complementary preventive control; confirmed to block RoguePlanet execution

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
