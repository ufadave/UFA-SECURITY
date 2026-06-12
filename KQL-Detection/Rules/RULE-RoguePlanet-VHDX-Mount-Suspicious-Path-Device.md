---
date: 2026-06-11
title: "RoguePlanet VHDX Mount Suspicious Path Detection"
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1204.002"
tactic: "Execution"
technique: "User Execution: Malicious File"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - VHD/VHDX Mount from Suspicious Path (RoguePlanet Lure)"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
---

# RULE — RoguePlanet VHDX Mount Suspicious Path Detection

---

## Purpose

Detects `.vhd` / `.vhdx` disk image mount operations originating from user-writable or network paths — the delivery mechanism for the original RoguePlanet RCE vector and a lure technique for tricking users into triggering Defender file handling against attacker-controlled content. Covers `diskpart.exe`, `Mount-DiskImage` / `Mount-VHD` PowerShell cmdlets, and Explorer-triggered mounts from temp, download, appdata, or UNC/network paths.

Secondary-fidelity signal — correlate with the primary MsMpEng shell spawn detection (`RULE-RoguePlanet-MsMpEng-Shell-Spawn-Device`).

---

## Query

```kql
DeviceProcessEvents
| where (
    FileName =~ "diskpart.exe"
    or (FileName =~ "powershell.exe"
        and ProcessCommandLine has_any ("Mount-DiskImage", "Mount-VHD", ".vhd", ".vhdx"))
    or (FileName =~ "explorer.exe"
        and ProcessCommandLine has_any (".vhd", ".vhdx"))
)
| where ProcessCommandLine has_any (
    @"\Temp\",
    @"\Downloads\",
    @"\AppData\",
    "\\\\",       // UNC / network path
    "http",
    "ftp"
)
// Exclude Veeam installer/update diskpart scripts — confirmed legitimate noise (validated 2026-06-11)
| where not (ProcessCommandLine has @"C:\ProgramData\Veeam\Setup\Temp\diskpartsc.txt")
| project
    Timestamp,
    ReportId,
    DeviceName,
    DeviceId,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath
| order by Timestamp desc
```

---

## Validated Columns

- [ ] `FileName` — `DeviceProcessEvents` — standard, confirmed
- [ ] `ProcessCommandLine` — `DeviceProcessEvents` — standard, confirmed
- [ ] `InitiatingProcessFileName` — `DeviceProcessEvents` — standard, confirmed
- [ ] `FolderPath` — `DeviceProcessEvents` — standard, confirm in your tenant
- [ ] `AccountName` — `DeviceProcessEvents` — standard, confirmed

> ⚠️ **Tuning note:** Veeam installer/update activity excluded by command line (validated 2026-06-11). If further noise surfaces, add exclusions for known-legitimate initiating processes (e.g. OS deployment tooling).

---

## Test Results

**Validated 2026-06-11** — 8 results, all `diskpart.exe` spawned by `msiexec.exe` with command line `diskpart /s "C:\ProgramData\Veeam\Setup\Temp\diskpartsc.txt"` across 3 devices (`ufamgt201`, `cceap205`, `ufa-agr-vmpxy`). 100% Veeam installer/update activity. Excluded by command line. Zero residual results after exclusion applied.

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-11 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | `Custom - VHD/VHDX Mount from Suspicious Path (RoguePlanet Lure)` |
| **Rule ID** | MDE Custom Detections are identified by rule name only — no persistent rule ID assigned |

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - VHD/VHDX Mount from Suspicious Path (RoguePlanet Lure)` |
| **Table** | `DeviceProcessEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | Medium |
| **MITRE** | T1204.002 — User Execution: Malicious File |
| **Actions** | Alert SOC; tag entity for investigation |
| **False Positive Risk** | Low post-tuning — Veeam excluded; monitor for additional noise on first deployment week |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceProcessEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---
## Response Guidance

**On alert — a disk image mount operation has been detected from a user-writable or network path, which is the delivery mechanism for the RoguePlanet lure vector.**

Identify the user and device from the alert and determine whether the mount was user-initiated or triggered by a process. Check `InitiatingProcessFileName` in the alert detail — if the parent is a browser, email client, or Office application, treat this as a likely phishing lure and escalate; if it's an IT tool you don't recognise, pivot to the initiating process's own parent chain to establish legitimacy. Query `DeviceFileEvents` on the same device around the alert timestamp to see whether any files were written from the mounted image, and check `DeviceProcessEvents` for any processes spawned from a path matching a VHD/VHDX mount point (typically a drive letter assigned by Windows at mount time). Correlate immediately against the `RULE-RoguePlanet-MsMpEng-Shell-Spawn-Device` rule — if both fire on the same device within a short window, treat it as a confirmed RoguePlanet exploitation event and shift to full IR, including device isolation and reimaging. If the VHDX alert fires in isolation with no suspicious child processes or file writes, the risk is lower but the mount should still be confirmed as legitimate with the user or IT before closing.


---



## Hardening Control Pair

- Intune/GPO: Restrict automatic `.vhd`/`.vhdx`/`.iso` mounting for standard users
- MDO Safe Attachments: treat disk images as executables

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[RULE-RoguePlanet-MsMpEng-Shell-Spawn-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]
- [[ACTOR-Nightmare-Eclipse]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
| 2026-06-11 | Validated — 8 results, 100% Veeam noise; excluded C:\ProgramData\Veeam\Setup\Temp\diskpartsc.txt by command line |
| 2026-06-11 | Promoted to rule via promote rule command |
