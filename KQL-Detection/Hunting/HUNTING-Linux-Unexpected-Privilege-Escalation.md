---
date: 2026-05-13
title: Linux Unexpected Privilege Escalation
table: "DeviceProcessEvents, DeviceInfo"
schema: "Advanced Hunting"
type: hunting
mitre: "T1068"
tactic: "Privilege Escalation"
technique: "Exploitation for Privilege Escalation"
status: "Draft"
saved_in: ""
query_name: ""
tags:
  - "#detection"
  - "#detection/hunting"
  - "#hunt"
  - "#status/draft"
  - "#endpoint"
---

# Hunting Query — Linux Unexpected Privilege Escalation

---

**Table:** DeviceProcessEvents (joined with DeviceInfo) | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1068 | **Tactic:** Privilege Escalation | **Technique:** Exploitation for Privilege Escalation
**Created:** 2026-05-13 | **Status:** `Draft`

---

## Hypothesis

> "I believe a non-root process may be spawning root-owned child processes through unexpected paths — either via direct exploitation (e.g. Dirty Frag / CVE-2023-3776) or post-exploitation LPE — which I can test by looking for non-root initiating processes producing root-owned children outside known legitimate escalation binaries."

---

## Purpose

Detect unexpected privilege escalation on Linux hosts where a non-root process spawns a root-level child process via a path other than known-good escalation mechanisms (sudo, su, pkexec, doas) or known legitimate service accounts (SolarWinds, Veeam, SAP HANA).

Intended as a **manual hunting query** scoped to specific hosts or time windows. Not suitable as a scheduled analytics rule in this environment — legitimate monitoring agents (SolarWinds ADM, Veeam) and SAP HANA service accounts generate high-volume, structurally identical telemetry that cannot be excluded cleanly without suppressing real attacker behaviour.

**Run this query when:**
- Investigating a specific Linux host following a Dirty Frag / kernel LPE alert
- A new Linux host is added to the estate and baseline is unknown
- Threat intel indicates active LPE exploitation targeting Linux kernel versions in your environment

---

## Query

```kql
let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceName;
DeviceProcessEvents
| where DeviceName in (LinuxDevices)
| where AccountName == "root"
| where InitiatingProcessAccountName != "root"
    and InitiatingProcessAccountName != ""
// Exclude known legitimate escalation binaries
| where InitiatingProcessFileName !in~ (
    "sudo", "su", "pkexec", "doas",
    // SolarWinds ADM probe — spawns root plugin workers by design
    "solarwinds.adm.agentplugin",
    "solarwinds.agent.jobengine.plugin",
    "solarwinds.agent.discovery.plugin"
)
// Exclude Veeam agent accounts — both Azure and Linux agent models
// Scoped to Veeam command lines only — localadmin doing non-Veeam work will still surface
| where not (
    InitiatingProcessAccountName in~ ("veeamazure", "localadmin")
    and ProcessCommandLine has_any ("veeam", "VeeamApp", "veeamagentconfig")
)
// Exclude SAP HANA service accounts — confirmed local service accounts, not AD-joined
// hd1crypt = HANA disk encryption account on saphdb1 (PosixUID 1003, no secondary groups)
// hd3adm = HANA instance HD3 admin account on saphdb3b ({SID}adm naming convention)
// Add additional {SID}adm accounts here as they are confirmed
| where not (
    InitiatingProcessAccountName =~ "hd1crypt"
    and DeviceName =~ "saphdb1.ad.corp.local"
)
| where not (
    InitiatingProcessAccountName =~ "hd3adm"
    and DeviceName =~ "saphdb3b.ad.corp.local"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `AccountName` — availability on Linux MDE agents varies by agent version; may be sparse
- [ ] `InitiatingProcessAccountName` — same caveat as above; confirm on target hosts before hunting
- [ ] `OSPlatform` — in `DeviceInfo`, not `DeviceProcessEvents`; join required (implemented via `let LinuxDevices`)
- [ ] `ProcessCommandLine` — confirm Veeam command line strings are consistent across agent versions in environment

---

## Tuning Notes

> Why this cannot be a scheduled analytics rule:

The following legitimate services generate structurally identical telemetry (non-root account spawning root child via bash/systemd) on a continuous scheduled basis:

| Account | Host(s) | Pattern | Frequency |
|---------|---------|---------|-----------|
| `veeamazure` | `cceut208` | `veeamagentconfig.sh` Azure blob config push | ~4 min poll cycle |
| `localadmin` | `ufaut220` | Veeam agent backup job — disk enumeration + `VeeamApp_*` binary drop to `/tmp` | Nightly ~11:30 PM |
| `hd1crypt` | `saphdb1` | SAP HANA disk encryption — cron jobs + xrdp admin sessions | Scheduled + ad hoc |
| `hd3adm` | `saphdb3b` | SAP HANA instance admin — systemd session logons | Scheduled |

Exclusion by account+host is fragile — a compromised `localadmin` running non-Veeam commands would be suppressed if excluded broadly. Current exclusion logic scopes to Veeam command line content to preserve that signal.

Additional `{SID}adm` accounts likely exist for other HANA instances. Enumerate and add to exclusions before widening the host scope.

---

## Findings

| Timestamp | Host | User | Observation | Disposition |
|-----------|------|------|-------------|-------------|
| | | | | `Benign` / `Suspicious` / `Confirmed TTP` |

---

## Saved Query

- **Saved In:** <!-- MDE Advanced Hunting / Sentinel -->
- **Query Name:** 

---

## Promote to Detection?

Retain as hunting query. Scheduled rule not viable — see Tuning Notes above. If a new Linux host joins the estate without SolarWinds/Veeam/SAP agents, a scoped version filtered to that host is viable as a temporary rule until baseline is established.

---

## Related Notes

- [[HUNTING-Linux-SUID-Binary-Execution]]
- [[HUNTING-Linux-Kernel-Module-Anomaly-DirtyFrag]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-13 | Created — promoted from KQL draft via `promote hunt`; tuning notes added from query validation sessions |
