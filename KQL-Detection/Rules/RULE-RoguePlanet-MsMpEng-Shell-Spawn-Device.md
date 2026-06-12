---
date: 2026-06-11
title: "RoguePlanet MsMpEng Shell Spawn Detection"
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1068"
tactic: "Privilege Escalation"
technique: "Exploitation for Privilege Escalation"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - MsMpEng Spawning Interactive Shell (RoguePlanet LPE)"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
---

# RULE — RoguePlanet MsMpEng Shell Spawn Detection

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

Returned zero results

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-11 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | `Custom - MsMpEng Spawning Interactive Shell (RoguePlanet LPE)` |
| **Rule ID** | MDE Custom Detections are identified by rule name only — no persistent rule ID assigned |

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

<!-- INACTIVE: Sentinel Analytics Rule — DeviceProcessEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Response Guidance

This alert has no expected false positives — treat every hit as a confirmed exploitation event and act immediately. **Isolate the device** via MDE (the rule's automated action should trigger this, but verify isolation is enforced before proceeding). Pull the full process tree in Defender XDR to identify what `MsMpEng.exe` spawned, what commands ran in the shell, and whether any secondary processes (credential dumping tools, network connections, dropped files) followed the initial shell. Check `DeviceNetworkEvents` and `DeviceFileEvents` for the same device in the 10-minute window around the alert timestamp — RoguePlanet yields a SYSTEM shell, so the attacker's next move is typically credential access or persistence establishment. Pivot to `DeviceLogonEvents` to determine whether the SYSTEM context was used to create new local accounts or modify existing ones. Escalate to a full IR case immediately; do not return the device to service until a clean reimaging or confirmed-clean forensic review is complete, as a SYSTEM-level compromise cannot be reliably remediated in place.

---

## Hardening Control Pair

- [[PROJ-WDAC-Phase1-Audit]] — Application allowlisting is the complementary preventive control; confirmed to block RoguePlanet execution

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]
- [[ACTOR-Nightmare-Eclipse]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
| 2026-06-11 | Promoted to rule via promote rule command |
| 2026-06-11 | Added Response Guidance section; clarified MDE rule ID behaviour in Promoted table |
