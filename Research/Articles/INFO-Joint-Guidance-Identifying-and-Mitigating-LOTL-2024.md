---
title: INFO-Joint-Guidance-Identifying-and-Mitigating-LOTL-2024
date: 2026-06-19
source: "CISA/NSA/FBI Joint Guidance — Identifying and Mitigating Living Off the Land Techniques (Feb 2024)"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
  - "#network"
  - "#identity"
---

# INFO -- Joint Guidance: Identifying and Mitigating Living Off the Land (LOTL) Techniques

**Source:** Email attachment — Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf
**Publication date:** February 7, 2024 (foundational doctrine, not a new advisory)
**Authoring agencies:** CISA, NSA, FBI, DOE, EPA, TSA (US); ASD/ACSC (Australia);
Canadian Centre for Cyber Security; NCSC-UK; NCSC-NZ
**Classification:** TLP:CLEAR

> Note: Originally triaged as a possible recent advisory based on email arrival date
> (June 2026), but the document is the well-known Feb 2024 Five Eyes joint guide on
> LOTL. Filed as foundational reference rather than time-sensitive intel.

---

## What It Is

The authoritative Five Eyes joint guidance on Living Off the Land (LOTL) techniques --
the abuse of native, trusted OS tools and processes (LOLBins) to evade detection. Built
from CISA incident response engagements (including a case where actors maintained
persistent access to a compromised domain controller) and CISA red team assessments
where defenders rarely detected LOTL activity even at organizations with mature security
postures.

**Core thesis:** LOTL is effective because organizations lack behavioral baselines,
rely on untuned EDR and static IOCs, use default (insufficient) logging configurations,
and because security teams operate in silos separate from IT. The guide is structured
around detection best practices, hardening best practices, and tailored detection
examples for two specific LOLBins: `ntdsutil.exe` and `PsExec.exe`.

---

## Relevance -- Cross-Reference Against Deployed Detections

This guide is less "new intel" and more a benchmark to validate existing detection
coverage against. Mapping current rules to the guide's recommendations:

| Guide Recommendation | Current Coverage |
|---|---|
| Detect encoded/obfuscated PowerShell (Base64, `-EncodedCommand`) | ✅ [[RULE-Encoded-PowerShell-Commands-With-Web-Request-Tuned]] |
| Detect RPC-based lateral movement (service creation) | ✅ [[RULE-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]] |
| Detect RPC-based credential access (registry save) | ✅ [[RULE-MDE-RPC-Remote-Registry-Credential-Dump-Device]] |
| Detect VSS + `ntdsutil.exe` NTDS.dit extraction | ⚠️ Partial -- ransomware pre-encryption stub covers `vssadmin`; no dedicated `ntdsutil.exe` detection exists |
| Detect `PsExec.exe` / service-based lateral movement | ❌ Gap -- no dedicated PsExec detection; RPC service creation rule covers the RPC-layer mechanism PsExec uses, but not PsExec\'s specific process/file signature |
| Network scanning / discovery detection | ✅ `RULE-Network-Scanning-Detected` |
| SUID/SGID and unprivileged process spawning (Linux LOTL) | ✅ Linux playbooks and KQL notes already deployed |

**Two concrete gaps identified:**

1. **`ntdsutil.exe` NTDS.dit extraction** -- the guide\'s primary tailored detection example.
   The hallmark TTP (`vssadmin.exe Create Shadow` followed by `ntdsutil snapshot
   "activate instance ntds" create quit quit`) is not currently covered by a dedicated
   rule. The guide explicitly notes threat actors shorten this to `ntdsutil snapshot "ac i
   ntds" create quit quit` -- detection must account for argument abbreviation.

2. **`PsExec.exe` specific signature** -- while RPC service creation detection covers the
   underlying mechanism, a dedicated detection for PsExec\'s known command-line patterns
   (`-s` switch for SYSTEM execution, `\pstools\psexec.exe` path, admin$ share access)
   would add a second, independent detection layer per defense-in-depth.

---

## Detection Notes

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect ntdsutil.exe NTDS.dit extraction via volume shadow copy --
// the guide's primary tailored detection example. Accounts for command abbreviation
// (e.g. "ac i ntds" vs "activate instance ntds").

DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "vssadmin.exe"
| where ProcessCommandLine has "create" and ProcessCommandLine has "shadow"
| extend ShadowTime = Timestamp, ShadowDevice = DeviceId
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName =~ "ntdsutil.exe"
    | where ProcessCommandLine has "snapshot"
    | where ProcessCommandLine has_any ("activate instance", "ac i")
) on $left.ShadowDevice == $right.DeviceId
| where Timestamp between (ShadowTime .. (ShadowTime + 30m))
| project ShadowTime, Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
| order by ShadowTime desc
```

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect PsExec.exe execution -- specific signature independent of the
// RPC-layer service creation detection. Covers SYSTEM-level execution (-s switch)
// and standard PsTools path.

DeviceProcessEvents
| where FileName =~ "psexec.exe" or FileName =~ "psexec64.exe"
    or ProcessCommandLine has "pstools\\psexec"
| where ProcessCommandLine !has @"cmd /c ""net stop SAPHostControl & net start SAPHostControl"" "
| project Timestamp, ReportId,DeviceName,DeviceId, AccountName,AccountUpn,
ProcessCommandLine,InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Validated Columns
- [x] Confirm `vssadmin.exe` + `ntdsutil.exe` command abbreviation patterns against
  tenant baseline before deploying -- legitimate AD backup tooling may also trigger this
- [x] Confirm PsExec is/isn\'t part of approved admin tooling in the environment before
  deploying as alerting (vs hunting-only)
We have a custom detection for psexec, but I did modify it to closer resemble this query as ours wasn't returning some events. Here's what our old one looked like, that Garey exclusion should have been removed as well. 

DeviceProcessEvents
| where InitiatingProcessVersionInfoProductName == "Sysinternals PsExec"
| where ProcessCommandLine !has '"cmd" /c "net stop SAPHostControl & net start SAPHostControl"'
| where AccountName !has 'gfillo' // exclude Garey whilst he's doing some testing. Commented this out, as I thought it would be better to just suppress the alert. Aug 7th 2025 dcc

Hide full query
---

## Hardening Best Practices Worth Reviewing

The guide\'s hardening section maps onto several existing or partially-existing controls:

- **Domain admin login restriction** ("domain administrator accounts should never log
  into anything except domain controllers") -- worth validating against current CA/PAW posture
- **Privileged Access Workstations (PAWs)** -- confirm whether AD admin accounts use PAWs
- **kbrtgt double-reset guidance** -- relevant reference if DC compromise is ever suspected
  (two resets required due to two-password history; first reset must replicate before second)
- **Sysmon OriginalFileName checks** -- detect renamed LOLBins (e.g. `net.exe` → `net2.exe`)
  via PE header original filename vs on-disk filename mismatch
- **ESENT Application Log Event IDs 216, 325, 326, 327** -- may indicate NTDS.dit copying;
  worth confirming these are captured if DC logging is in scope

---

## Actions

- [ ] Build and validate the `ntdsutil.exe` NTDS.dit extraction detection stub
- [x] Build and validate the PsExec.exe specific-signature detection stub
- [ ] Confirm ESENT Application Log Event IDs (216, 325-327) are captured for domain controllers
- [ ] Review domain admin login restriction posture against the guide\'s recommendation
- [ ] Consider Sysmon OriginalFileName renamed-LOLBin detection as a future hunting query

---

## Related Notes
- [[RULE-Encoded-PowerShell-Commands-With-Web-Request-Tuned]]
- [[RULE-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]]
- [[RULE-MDE-RPC-Remote-Registry-Credential-Dump-Device]]
- [[RULE-Network-Scanning-Detected]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-19 | Stub created -- PDF attachment pending upload |
| 2026-06-19 | PDF extracted -- corrected publication date to Feb 7 2024 (not new intel); filed as foundational reference; cross-referenced against 12 deployed rules; 2 detection gaps identified (ntdsutil NTDS.dit extraction, PsExec specific signature); 2 new KQL stubs added |
