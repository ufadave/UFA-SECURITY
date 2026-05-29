---
title: INTEL-Ransomware-Pre-Encryption-Tools-45-Gangs-2026-05-23
date: 2026-05-27
source: "https://x.com/securityinbits/status/2057451479259291653"
author: "securityinbits"
mitre:
  - "T1562.001"
  - "T1490"
  - "T1486"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#pending-review"
  - "#endpoint"
  - "#ransomware"
---

# INTEL — Hunt Ransomware Before It Encrypts: Tools Used by 45+ Gangs

> ⚠️ **PENDING REVIEW** — Original source is an X/Twitter post which cannot be fetched
> directly. Note populated from secondary sources covering the same topic.
> Original tweet: https://x.com/securityinbits/status/2057451479259291653

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://x.com/securityinbits/status/2057451479259291653 |
| **Author** | @securityinbits |
| **Date Observed** | 2026-05-27 |
| **Date Published** | 2026-05-23 |
| **Patch Available** | N/A — TTP awareness |

**Corroborating references:**
- https://gbhackers.com/ransomware-gangs-use-byovd-and-edr/
- https://www.cybersecurity-insiders.com/ransomware-in-2026-kaspersky-state-of-ransomware-report/
- https://www.huntress.com/ransomware-guide/ransomware-trends

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1490 | Inhibit System Recovery |
| T1486 | Data Encrypted for Impact |

---

## Summary

Cross-industry threat intelligence on the three pre-encryption tools and techniques
consistently observed across 45+ ransomware gangs before payload deployment. Based on
corroborating 2026 sources, the three most common pre-encryption behaviours are:

1. **EDR killer / BYOVD** — Bring Your Own Vulnerable Driver to terminate security
   processes before encryption. Abuses legitimately signed drivers to bypass kernel
   protection. Active across Akira, LockBit, Qilin, DragonForce, and most RaaS
   affiliates in 2026. Blends into normal system activity while disabling defenses.

2. **VSS / backup destruction** — Volume Shadow Copy deletion (`vssadmin delete shadows`
   or `wmic shadowcopy delete`) and backup catalog wipe to prevent recovery without
   paying ransom. Near-universal across ransomware groups.

3. **Encryption-less extortion / data staging** — Growing subset of groups (ShinyHunters,
   others) skip encryption entirely, exfiltrating data and threatening leaks only. Data
   leak site count hit a record 91 in Q1 2026 (ReliaQuest). This renders backup-based
   recovery irrelevant as a defense — the leverage is regulatory/reputational, not
   operational.

**Emerging trend:** Post-quantum encryption in ransomware payloads (ML-KEM / Kyber1024
observed in PE32 family). Encrypted ransom keys designed to resist future quantum
decryption. Currently academic risk for most organisations but tracking warrants.

---

## Relevance to Environment

Medium-High. EDR killer / BYOVD techniques are directly relevant to the MDE-managed
endpoint estate. The detection opportunity is behavioural: vulnerable driver loading
followed by security process termination is huntable in DeviceProcessEvents and
DeviceDriverEvents. Backup destruction via `vssadmin` or `wmic` is huntable in
DeviceProcessEvents.

The encryption-less extortion trend is relevant to the data access threat model —
particularly given the ChatGPT `Mail.Read` + `Chat.Read` consent finding. Data exfil
leverage does not require endpoint compromise if cloud data is accessible via OAuth.

---

## Detection Notes

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect VSS / backup destruction commands -- near-universal ransomware pre-cursor
// NOTE: Validate wmic and vssadmin usage baseline before deploying

DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")
| where ProcessCommandLine has_any (
    "delete shadows", "shadowcopy delete", "delete catalog",
    "recoveryenabled no", "bootstatuspolicy ignoreallfailures"
)
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect security tool process termination -- potential EDR killer activity
// Flag taskkill / net stop targeting known security process names

DeviceProcessEvents
| where FileName in~ ("taskkill.exe", "net.exe", "sc.exe")
| where ProcessCommandLine has_any (
    "MsSense", "MsMpEng", "SenseIR", "SenseCncProxy",
    "SenseNdr", "SenseSampleUploader", "windefend",
    "SecurityHealthService", "MpCmdRun"
)
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### Validated Columns
- [ ] `FileName` -- confirm case-insensitive matching for vssadmin, wmic variants
- [ ] Original tweet content -- pending manual review of source URL

---

## Hardening Actions

- [ ] Run VSS destruction stub retroactively over 30 days to establish baseline
- [ ] Review MDE tamper protection status -- confirm enabled on all managed endpoints
- [ ] Validate ASR rules covering LSASS and VSS protection are active in Intune policy

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-27 | Created -- X/Twitter source unfetchable; populated from corroborating secondary sources; original tweet pending manual review |
