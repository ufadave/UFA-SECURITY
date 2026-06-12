---
title: "RoguePlanet — Nightmare Eclipse Microsoft Defender TOCTOU LPE"
date: 2026-06-11
source: "https://www.picussecurity.com/resource/blog/rogueplanet-anatomy-of-the-nightmare-eclipse-microsoft-defender-zero-day"
author: "Sıla Özeren Hacıoğlu — Picus Security"
type: intel
severity: High
cve: ""
cvss: ""
detection_candidate: true
mitre:
  - "T1068"
  - "T1203"
  - "T1204.002"
  - "T1080"
tags:
  - "#intel"
  - "#endpoint"
  - "#action-required"
  - "#status/draft"
---

# INTEL — RoguePlanet: Nightmare Eclipse Microsoft Defender TOCTOU LPE

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.picussecurity.com/resource/blog/rogueplanet-anatomy-of-the-nightmare-eclipse-microsoft-defender-zero-day |
| **Published** | 2026-06-11 |
| **Author** | Sıla Özeren Hacıoğlu — Picus Security Labs |
| **Type** | Emerging Threat Analysis |

---

## MITRE ATT&CK

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Execution | T1203 | Exploitation for Client Execution (original RCE path) |
| Execution | T1204.002 | User Execution: Malicious File (.vhdx lure) |
| Lateral Movement | T1080 | Taint Shared Content (SMB share vector) |

---

## Summary

RoguePlanet is a public proof-of-concept local privilege escalation (LPE) exploit targeting a Time-of-Check to Time-of-Use (TOCTOU) race condition in Microsoft Defender's file-processing path (`MsMpEng.exe`). A successful run yields an interactive `cmd.exe` shell running as `NT AUTHORITY\SYSTEM` on a fully patched Windows 10 or Windows 11 endpoint — including builds carrying the June 2026 Patch Tuesday updates (validated against KB5094126). No CVE exists and no patch is available as of publication.

The exploit abuses the fact that Defender runs as SYSTEM to perform file operations, using NTFS junction/symlink redirection to redirect those privileged writes to attacker-controlled locations. It was released by the researcher **Nightmare Eclipse** (also tracked as Chaotic Eclipse / Dead Eclipse / MSNightmare) on the same day as June Patch Tuesday — a pattern this actor has repeated for three consecutive months. The exploit was specifically rewritten to bypass Defender hardening Microsoft silently deployed in mid-May 2026, meaning the June patches do not close it.

The exploit originated as an RCE via crafted `.vhd(x)` files or remote SMB shares; that path was partially hardened in May. The current public variant is LPE only, though the researcher does not rule out a return to RCE. Earlier Nightmare Eclipse tooling (BlueHammer, RedSun, UnDefend) has been observed in live intrusions, making this a near-term operational risk, not a research curiosity.

---

## Threat Actor — Nightmare Eclipse

| Field | Detail |
|-------|--------|
| **Aliases** | Chaotic Eclipse, Dead Eclipse, MSNightmare |
| **Motivation** | Retaliatory campaign against Microsoft's disclosure and bug-bounty practices |
| **Cadence** | ~1 new Defender/Windows zero-day every 10 days since early April 2026 |
| **Infrastructure** | projectnightcrawler.dev (self-hosted code platform), deadeclipse666.blogspot.com, GitHub: MSNightmare |
| **Prior tooling in the wild** | BlueHammer, RedSun, UnDefend confirmed in live intrusions (Huntress reporting) |

### Known Prior Releases

| Exploit | Target | CVE | Status |
|---------|--------|-----|--------|
| BlueHammer | Microsoft Defender | CVE-2026-33825, CVSS 7.8 | Patched April 2026; actively exploited |
| RedSun | Microsoft Defender | CVE-2026-41091 (disputed) | Actively exploited |
| UnDefend | Microsoft Defender | CVE-2026-45498 | Blocks Defender definition updates; in live intrusions |
| YellowKey | BitLocker/WinRE | CVE-2026-45585, CVSS 6.8 | Fixed June 2026 Patch Tuesday |
| GreenPlasma | CTFMON/Windows | CVE-2026-45586, CVSS 7.8 | Fixed June 2026 Patch Tuesday |
| MiniPlasma | Cloud Files Mini Filter Driver | CVE-2020-17103 | LPE regression — 2020 flaw |
| **RoguePlanet** | **Microsoft Defender** | **None** | **Unpatched** |

---

## Technical Detail

### Root Cause

TOCTOU race condition in Defender's file-handling logic within `MsMpEng.exe`. The engine validates a file path (check), then performs a SYSTEM-privileged write/remediation against it (use). An unprivileged attacker races to redirect the target path — via an NTFS junction or symlink — between the check and use, causing Defender to write attacker-controlled content to a protected location under SYSTEM privilege.

### Redirection Primitive

Low-privileged users can create NTFS reparse points (junctions, symlinks) pointing to paths they do not control. This is the same primitive used in BlueHammer (CVE-2026-33825). The attacker stages a directory, then flips it to a reparse point at the race-window moment so the SYSTEM writer follows the link to a sensitive destination (e.g. `C:\Windows\System32`).

### Affected Scope

| Detail | Value |
|--------|-------|
| Affected OS | Windows 10, Windows 11 (fully patched, incl. June 2026 KB5094126) |
| Not reliably affected | Windows Server (researcher notes adaptation may be possible) |
| Reliability | Probabilistic (race-dependent) — near-100% on some hardware; treat as loopable |
| Patch status | No targeted patch; OOB fix possible |

### Survivability

The mid-May 2026 Defender hardening patched `mpengine!SysIO*` APIs against junction attacks. RoguePlanet was rewritten specifically to bypass this. **Patch parity ≠ coverage parity.**

### SMB/VHDX Origin (Remote Paths)

The original form involved coercing a victim to open a crafted `.vhd(x)` from a remote SMB share, allowing remote symlinks to steer Defender's file operations into RCE. The May hardening closed these remote paths; the current public variant is LPE. The same attack surface (disk-image handling, remote SMB, symlink/junction resolution) underpins both variants.

---

## Relevance to Environment

**High.** Every Windows endpoint in the environment runs Microsoft Defender — the attack surface is the entire ~150-device Windows fleet. This is an unpatched LPE with no vendor remediation available at time of writing, exploitable by any user with a low-privilege foothold on a fully patched machine. The actor's prior tools have already appeared in live intrusions, making operationalization plausible on a short timeline. Key compounding factors:

- POS terminals running Windows likely carry Defender — assess whether those configurations have different MsMpEng behaviour or higher-value targets on-box
- OT/SCADA jump hosts at the fertilizer plant, if Windows-based, are in scope
- WDAC deployment is not yet started — application allowlisting (confirmed to block RoguePlanet) is the strongest near-term control and is currently absent

---

## Detection Notes

`detection_candidate: true`

### Primary Detection — MsMpEng Spawning Interactive Shell (SYSTEM Integrity)

This is the highest-fidelity signal. Defender never legitimately spawns interactive shells. Any such event is, for practical purposes, a confirmed exploitation event.

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect interactive shell or scripting host spawned by MsMpEng.exe at SYSTEM integrity — primary RoguePlanet-class LPE indicator
// MITRE: T1068 — Exploitation for Privilege Escalation

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

> **Deployment note:** This should be deployed as an MDE Custom Detection rule at High severity. Expected false-positive rate: zero. Defender does not spawn interactive shells in normal operation.

```kql
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect NTFS junction/reparse-point creation in user-writable staging paths — pre-exploitation indicator for TOCTOU attacks
// MITRE: T1068

DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any (
    @"\Temp\",
    @"\AppData\Local\Temp\",
    @"\AppData\Local\",
    @"\ProgramData\"
)
| where FileName endswith ".junction" or AdditionalFields has "ReparsePoint"
// Note: NTFS reparse-point creation may require parsing AdditionalFields — validate in environment
// Alternative: look for CreateFile calls with FILE_FLAG_OPEN_REPARSE_POINT in DeviceEvents
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

> ⚠️ **Schema note:** Reparse-point semantics in `DeviceFileEvents` / `DeviceEvents` `AdditionalFields` require validation in your tenant. This stub is a starting point — test `ActionType` values available for file system operations in your environment. Minifilter/EDR telemetry is more reliable for reparse-point detection than native logs.

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound SMB (TCP/445) from workstations to external/non-corporate hosts — enables the remote SMB/VHDX RCE vector
// MITRE: T1080

let CorporateSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| where not (ipv4_is_in_range(RemoteIP, "10.0.0.0/8"))
| where not (ipv4_is_in_range(RemoteIP, "172.16.0.0/12"))
| where not (ipv4_is_in_range(RemoteIP, "192.168.0.0/16"))
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by Timestamp desc
```

> ⚠️ **Schema note:** `ipv4_is_in_range()` availability in Advanced Hunting — validate; may need `startswith` approach for subnet matching in older schemas. `RemoteUrl` availability varies by MDE sensor version.

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect suspicious .vhd/.vhdx mount operations originating from temp or network paths — VHDX lure vector
// MITRE: T1204.002

DeviceProcessEvents
| where FileName =~ "diskpart.exe"
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Mount-DiskImage", "Mount-VHD", ".vhd", ".vhdx"))
    or (FileName =~ "explorer.exe" and ProcessCommandLine has_any (".vhd", ".vhdx"))
| where ProcessCommandLine has_any (
    @"\Temp\",
    @"\Downloads\",
    @"\AppData\",
    "\\\\",      // UNC/network path
    "http",
    "ftp"
)
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

### Validated Columns

- [ ] `ProcessIntegrityLevel` — `DeviceProcessEvents` — confirm availability in your tenant (available in modern MDE schemas)
- [ ] `InitiatingProcessFileName` — `DeviceProcessEvents` — standard, confirmed
- [ ] `AdditionalFields` for reparse-point semantics — `DeviceFileEvents` / `DeviceEvents` — **must validate**
- [ ] `ipv4_is_in_range()` — Advanced Hunting function — validate availability
- [ ] `RemoteUrl` — `DeviceNetworkEvents` — validate sensor version availability

---

## IOCs / Watchlist

| Type | Value | Context |
|------|-------|---------|
| Domain | `projectnightcrawler.dev` | Actor self-hosted PoC distribution platform — watchlist |
| Domain | `deadeclipse666.blogspot.com` | Actor blog / disclosure site |
| Handle | `MSNightmare` (GitHub, GitLab mirrors) | Actor code repositories |
| Binary | `MsMpEng.exe` as parent of shell | **Exploitation indicator** — not a static IOC; alert on this process relationship |

---

## Hardening Actions

- [ ] **PRIORITY: Deploy primary MsMpEng → shell detection as MDE Custom Detection rule** — High severity, no FP risk, covers confirmed exploitation — do this today
- [ ] **Assess WDAC readiness** — Application allowlisting in enforced mode is the single strongest compensating control; ThreatLocker confirmed it blocks RoguePlanet execution. WDAC deployment is not yet started — accelerate Phase 1 scoping.
- [ ] **Restrict .vhd/.vhdx/.iso handling** — Block automatic mounting of disk images delivered via email or from network locations via Intune/GPO; treat disk images as executables in MDO safe attachments policy
- [ ] **Verify outbound SMB blocking** — Confirm TCP/445 outbound from workstations is blocked at perimeter; close the remote SMB RCE vector
- [ ] **Verify symlink evaluation settings** — Run `fsutil behavior query SymlinkEvaluation` on representative endpoints; confirm Remote-to-Local (R2L) and Remote-to-Remote (R2R) remain Disabled
- [ ] **Watchlist actor infrastructure** — Add `projectnightcrawler.dev` and `deadeclipse666.blogspot.com` to Cisco Secure Access / Umbrella block/watchlist
- [ ] **Monitor for OOB Defender update** — Defender platform and engine update independently of monthly cumulative via the antimalware update channel; confirm engine/platform versions are current and watch for an accelerated fix
- [ ] **Review POS terminals and OT jump hosts** — Confirm Defender is running on these and that MDE Custom Detection coverage extends to them

---

## Related Notes

- [[KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device]]
- [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]
- [[PROJ-WDAC-Phase1-Audit]]
- [[ACTOR-Nightmare-Eclipse]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — Picus Security Labs analysis, same-day as RoguePlanet release |
