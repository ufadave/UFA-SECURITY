---
date: 2026-06-11
title: "RoguePlanet VHDX Mount Suspicious Path Detection"
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1204.002"
tactic: "Execution"
technique: "User Execution: Malicious File"
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

# KQL — RoguePlanet VHDX Mount Suspicious Path Detection

---

## Purpose

Detects `.vhd` / `.vhdx` disk image mount operations originating from user-writable or network paths — the delivery mechanism for the original RoguePlanet RCE vector and a lure technique for tricking users into triggering Defender file handling against attacker-controlled content. Covers `diskpart.exe`, `Mount-DiskImage` / `Mount-VHD` PowerShell cmdlets, and Explorer-triggered mounts from temp, download, appdata, or UNC/network paths.

Secondary-fidelity signal — correlate with the primary MsMpEng shell spawn detection.

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
    DeviceName,
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

> ⚠️ **Tuning note:** Legitimate IT activity may mount disk images from network shares (e.g., OS deployment, patch baselines). Veeam installer/update activity excluded by command line (validated 2026-06-11). Baseline before enabling as a scheduled detection — consider adding further allowlist entries for known-legitimate initiating processes if additional noise surfaces.

---

## Test Results

**Validated 2026-06-11** — 8 results, all `diskpart.exe` spawned by `msiexec.exe` with command line `diskpart /s "C:\ProgramData\Veeam\Setup\Temp\diskpartsc.txt"` across 3 devices (`ufamgt201`, `cceap205`, `ufa-agr-vmpxy`). 100% Veeam installer/update activity. Excluded by command line. Zero residual results after exclusion applied.

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
| **False Positive Risk** | Medium — legitimate IT disk image mounts exist; baseline required before promoting |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceProcessEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- Intune/GPO: Restrict automatic `.vhd`/`.vhdx`/`.iso` mounting for standard users
- MDO Safe Attachments: treat disk images as executables

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
| 2026-06-11 | Validated — 8 results, 100% Veeam noise; excluded C:\ProgramData\Veeam\Setup\Temp\diskpartsc.txt by command line |
