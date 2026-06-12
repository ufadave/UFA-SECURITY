---
title: "Nightmare Eclipse"
date: 2026-06-11
type: threat-actor
aliases:
  - "Chaotic Eclipse"
  - "Dead Eclipse"
  - "MSNightmare"
origin: "Unknown"
motivation: "Retaliatory campaign against Microsoft's vulnerability disclosure and bug-bounty practices"
active_since: "2026-04"
last_observed: "2026-06-11"
mitre:
  - "T1068"
  - "T1203"
  - "T1204.002"
  - "T1080"
tags:
  - "#hunt"
  - "#status/active"
  - "#endpoint"
---

# Threat Actor — Nightmare Eclipse

---

## Overview

| Field | Detail |
|-------|--------|
| **Also Known As** | Chaotic Eclipse, Dead Eclipse, MSNightmare |
| **Origin** | Unknown |
| **Motivation** | Retaliatory — openly adversarial campaign against Microsoft's vulnerability disclosure and bug-bounty practices; researcher frames releases as retaliation for bounty disputes and MSRC handling |
| **Active Since** | Early April 2026 |
| **Last Observed** | 2026-06-11 (RoguePlanet) |
| **Targeting** | Microsoft Defender, Windows OS components — attack surface is the entire Windows endpoint fleet by default |
| **Cadence** | ~1 new PoC every 10 days since campaign start; timed releases to Microsoft Patch Tuesday (three consecutive months) |
| **Threat Level** | High — prior tooling (BlueHammer, RedSun, UnDefend) confirmed in live intrusions; PoCs are being operationalized by real attackers |

---

## TTPs Observed

| Technique ID | Name | First Seen | Source |
|---|---|---|---|
| T1068 | Exploitation for Privilege Escalation | 2026-04 | BlueHammer, RedSun, MiniPlasma, GreenPlasma, RoguePlanet |
| T1203 | Exploitation for Client Execution | 2026-06 | RoguePlanet original RCE path (SMB/VHDX) |
| T1204.002 | User Execution: Malicious File | 2026-06 | RoguePlanet .vhdx lure vector |
| T1080 | Taint Shared Content | 2026-06 | RoguePlanet SMB share coercion |
| T1562.001 | Impair Defenses: Disable or Modify Tools | 2026-05 | UnDefend — blocks Defender definition updates |
| T1211 | Exploitation for Defense Evasion | 2026-04 | BlueHammer/RoguePlanet — abuses Defender's own SYSTEM-level file operations |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation |
| Execution | T1203 — Exploitation for Client Execution |
| Execution | T1204.002 — User Execution: Malicious File (.vhdx lure) |
| Lateral Movement | T1080 — Taint Shared Content (SMB share vector) |
| Defense Evasion | T1562.001 — Disable or Modify Tools (UnDefend) |
| Defense Evasion | T1211 — Exploitation for Defense Evasion |

---

## Campaign History

| Campaign | Period | Summary | Note |
|----------|--------|---------|------|
| BlueHammer | April 2026 | CVE-2026-33825 — Defender LPE via junction-based redirect into System32; CVSS 7.8; patched April 2026; now actively exploited in the wild | |
| RedSun | April–May 2026 | Defender SYSTEM-grade LPE PoC; CVE-2026-41091 (disputed); now actively exploited | |
| UnDefend | May 2026 | CVE-2026-45498; blocks Defender definition updates; observed in live intrusions | |
| MiniPlasma | May 2026 | CVE-2020-17103 — regression of 2020 LPE flaw in Cloud Files Mini Filter Driver | |
| YellowKey | May–June 2026 | CVE-2026-45585, CVSS 6.8 — BitLocker/WinRE security-feature bypass; requires physical access; fixed June 2026 Patch Tuesday | |
| GreenPlasma | May–June 2026 | CVE-2026-45586, CVSS 7.8 — CTFMON link-following EoP to SYSTEM; fixed June 2026 Patch Tuesday | |
| RoguePlanet | June 2026 | TOCTOU race condition in Defender file-handling; no CVE; no patch; released hours after June 2026 Patch Tuesday; bypasses May 2026 Defender hardening | [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |

---

## IOCs

| Type | Value | First Seen | Source |
|------|-------|------------|--------|
| Domain | `projectnightcrawler.dev` | 2026-05 | Actor self-hosted PoC distribution platform (post-GitHub/GitLab takedowns) |
| Domain | `deadeclipse666.blogspot.com` | 2026-04 | Actor blog / disclosure site |
| GitHub handle | `MSNightmare` | 2026-04 | Primary code repository (repeatedly taken down) |
| Process relationship | `MsMpEng.exe` → `cmd.exe` / `powershell.exe` at SYSTEM integrity | 2026-04 | Exploitation outcome — BlueHammer, RedSun, RoguePlanet class |

---

## Detection Coverage

| KQL Note | Table | Status |
|----------|-------|--------|
| [[KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device]] | `DeviceProcessEvents` | Draft — ready to promote (High severity, zero FP expected) |
| [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]] | `DeviceProcessEvents` | Draft — needs baseline validation before promoting |
| [[KQL-RoguePlanet-Outbound-SMB-External-Device]] | `DeviceNetworkEvents` | Draft — needs baseline validation before promoting |

---

## Infrastructure

| Asset | Type | Notes |
|-------|------|-------|
| `projectnightcrawler.dev` | Self-hosted code platform | Primary PoC distribution after GitHub/GitLab takedowns — watchlist/block |
| `deadeclipse666.blogspot.com` | Blog | Actor disclosure and commentary site |
| GitHub: `MSNightmare` | Code repository | Repeatedly taken down; may have active mirrors |

---

## Intel Feed

> Accumulated summaries from linked INTEL notes — newest first.

### 2026-06-11 — RoguePlanet: Nightmare Eclipse Microsoft Defender TOCTOU LPE
> Unpatched (no CVE) TOCTOU race condition LPE in Microsoft Defender's file-processing path yields SYSTEM shell via MsMpEng.exe; fully patched Windows 10/11 (incl. June 2026 KB5094126) in scope; released hours after June 2026 Patch Tuesday, bypassing May 2026 Defender hardening. [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]

---

## Hardening Actions

- [ ] **Deploy MsMpEng shell spawn detection immediately** — `KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device` → promote rule, High severity, zero FP risk
- [ ] **Watchlist / block `projectnightcrawler.dev`** in Cisco Secure Access — primary PoC distribution infrastructure
- [ ] **WDAC enforcement** — application allowlisting confirmed to block RoguePlanet execution; accelerate Phase 1 scoping
- [ ] **Verify outbound SMB blocked** — TCP/445 from workstations to non-corporate destinations at perimeter
- [ ] **Verify symlink evaluation** — `fsutil behavior query SymlinkEvaluation` on representative endpoints; R2L and R2R must be Disabled
- [ ] **Monitor for OOB Defender patch** — check Defender platform/engine version channel separately from monthly cumulative
- [ ] **Review POS terminals and OT jump hosts** — confirm MDE Custom Detection coverage extends to these devices

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device]]
- [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]]
- [[KQL-RoguePlanet-Outbound-SMB-External-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — pre-populated from RoguePlanet INTEL note; 7 known campaigns at time of creation |
| 2026-06-11 | Auto-updated from [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
