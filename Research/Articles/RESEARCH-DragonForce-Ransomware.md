---
title: DragonForce Ransomware — TTPs, Tools, and IOCs
date: 2026-04-29
source: https://github.com/trad16/dragonforce-research
author: ""
mitre:
  - T1486
  - T1490
  - T1489
  - T1082
  - T1083
  - T1021
  - T1078
  - T1562
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#ransomware"
  - "#endpoint"
  - "#identity"
  - "#network"
---

# DragonForce Ransomware — TTPs, Tools, and IOCs

> Requested via [Research] email. Treated as INTEL given ransomware relevance to environment.

---

## Source

| Field | Detail |
|-------|--------|
| **Request** | Gmail [Research] email — "Investigate DragonForce ransomware. Return tools techniques and tactics. Produce KQL if possible and list any IOC" |
| **Date Observed** | 2026-04-29 |
| **Research Sources** | Multiple — see below |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1486 | Data Encrypted for Impact |
| T1490 | Inhibit System Recovery |
| T1489 | Service Stop |
| T1082 | System Information Discovery |
| T1083 | File and Directory Discovery |
| T1021.002 | Remote Services: SMB/Windows Admin Shares |
| T1078 | Valid Accounts |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1070.001 | Indicator Removal: Clear Windows Event Logs |
| T1134 | Access Token Manipulation |

---

## Summary

DragonForce is a ransomware-as-a-service (RaaS) operation that emerged in late 2023 and escalated significantly through 2024–2025. The group operates a leak site and affiliate programme, with confirmed attacks across manufacturing, retail, critical infrastructure, and government sectors globally. DragonForce ransomware payloads have been observed in variants derived from leaked LockBit 3.0 and CONTI source code, making detection signatures partially transferable from those families. The group employs a double-extortion model — encrypting and exfiltrating data before demanding ransom, with threatened publication on their leak site if payment is refused.

Initial access typically involves exploitation of public-facing applications, phishing, or purchase of valid credentials from initial access brokers. Post-compromise, affiliates use living-off-the-land binaries (LOLBins), Cobalt Strike, and SystemBC for lateral movement and C2. Defence evasion includes disabling Windows Defender, clearing event logs, and deleting Volume Shadow Copies. The encryptor appends `.dragonforce_encrypted` to encrypted files and drops a ransom note named `readme.txt` or `DRAGONFORCE_README.html`.

---

## Relevance to Environment

High relevance. The manufacturing/industrial sector targeting is directly applicable given the fertilizer plant acquisition. The group's use of valid credential abuse aligns with current threat priorities around infostealer credential exposure and Entra ID hardening gaps. SMB lateral movement via admin shares is relevant given the hybrid AD environment. Shadow Copy deletion is a standard pre-encryption step that should be detectable via existing MDE telemetry.

---

## Tools Used by Affiliates

| Tool | Purpose |
|------|---------|
| Cobalt Strike | C2 and lateral movement |
| SystemBC | SOCKS5 proxy / C2 tunnel |
| Mimikatz / NanoDump | Credential dumping |
| rclone | Data exfiltration to cloud storage |
| PsExec | Lateral movement / remote execution |
| WinSCP | File transfer |
| AnyDesk / TeamViewer | Persistent remote access |
| vssadmin.exe | Shadow Copy deletion |
| wevtutil.exe | Event log clearing |
| net.exe / nltest.exe | Domain enumeration |

---

## IOCs

> Note: DragonForce IOCs rotate frequently across affiliates. Treat these as indicative rather than exhaustive. Verify against current threat feeds before alerting.

### File Indicators
| Indicator | Type | Notes |
|-----------|------|-------|
| `.dragonforce_encrypted` | File extension | Encrypted file suffix |
| `DRAGONFORCE_README.html` | Ransom note filename | |
| `readme.txt` | Ransom note filename | Older variant |

### Behavioural Indicators
| Behaviour | Notes |
|-----------|-------|
| `vssadmin delete shadows /all /quiet` | Shadow Copy deletion — pre-encryption |
| `wevtutil cl System` / `wevtutil cl Security` | Event log clearing |
| `net stop` targeting AV/backup services | Defence evasion |
| `nltest /domain_trusts` | Domain trust enumeration |
| `rclone.exe` outbound transfers | Data exfiltration |

---

## Detection Notes

### KQL Stubs

```kql
// Detect Volume Shadow Copy deletion — pre-ransomware indicator
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Alert on vssadmin or wmic shadow copy deletion commands

DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "wmic.exe")
| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete shadow")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```kql
// Detect event log clearing — common pre-encryption step
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)

DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any ("cl ", "clear-log")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

```kql
// Detect mass file rename/extension change — encryption activity
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: High volume of file renames in short window — tune threshold to environment

DeviceFileEvents
| where ActionType == "FileRenamed"
| where FileName endswith ".dragonforce_encrypted"
    or PreviousFileName !endswith ".dragonforce_encrypted"
| summarize RenameCount = count() by DeviceName, bin(Timestamp, 5m)
| where RenameCount > 50
| project Timestamp, DeviceName, RenameCount
```

```kql
// Detect rclone data exfiltration — large outbound transfers from rclone process
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "rclone.exe"
| where RemotePort in (443, 80, 21)
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```

```kql
// Detect Cobalt Strike beacon indicators — named pipe patterns
// Table: DeviceEvents
// Schema: Advanced Hunting (MDE)

DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where PipeName matches regex @"\\\\pipe\\\\[a-zA-Z0-9]{4,8}$"
| project Timestamp, DeviceName, AccountName, PipeName, InitiatingProcessFileName
```

### Validated Columns
- [ ] `PreviousFileName` — DeviceFileEvents, confirm availability
- [ ] `NamedPipeEvent` ActionType — confirm in MDE Advanced Hunting
- [ ] `PipeName` in `parse_json(AdditionalFields)` — validate field name

---

## Hardening Actions

- [ ] Confirm ASR rule for credential stealing from LSASS is enabled (already in deployed controls list)
- [ ] Verify VSS protection — confirm shadow copies are protected and cannot be deleted without admin elevation
- [ ] Block or alert on `rclone.exe` execution via ASR or WDAC (relevant to WDAC deployment project)
- [ ] Audit AnyDesk / TeamViewer installations — flag unauthorised remote access tools
- [ ] Confirm Defender tamper protection is enabled on all endpoints

---

## Related Notes

- [[WDAC/Runbooks/]]
- [[Hardening/Controls/]]
- [[IR-DFIR/Playbooks/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-29 | Created from Gmail [Research] triage — treated as INTEL given ransomware relevance |
