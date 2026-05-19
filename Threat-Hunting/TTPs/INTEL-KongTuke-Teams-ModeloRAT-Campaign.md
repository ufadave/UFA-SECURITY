---
title: INTEL-KongTuke-Teams-ModeloRAT-Campaign
date: 2026-05-18
source: "https://www.bleepingcomputer.com/news/security/kongtuke-hackers-now-use-microsoft-teams-for-corporate-breaches/"
author: "Bill Toulas / ReliaQuest"
mitre:
  - "T1566 — Phishing"
  - "T1059.001 — PowerShell"
  - "T1105 — Ingress Tool Transfer"
  - "T1547.001 — Registry Run Keys / Startup Folder"
  - "T1053.005 — Scheduled Task"
  - "T1078 — Valid Accounts"
detection_candidate: true
tags:
  - "#intel"
  - "#status/done"
  - "#endpoint"
  - "#identity"
  - "#email"
 
---

# INTEL-KongTuke-Teams-ModeloRAT-Campaign

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.bleepingcomputer.com/news/security/kongtuke-hackers-now-use-microsoft-teams-for-corporate-breaches/ |
| **Author** | Bill Toulas / ReliaQuest |
| **Date Observed** | 2026-05-18 |
| **Date Published** | 2026-05-14 |
| **Patch Available** | N/A — social engineering / configuration hardening required |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1566 | Phishing — via Teams external chat |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1105 | Ingress Tool Transfer — ZIP from Dropbox |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1078 | Valid Accounts — impersonation of IT helpdesk |

---

## Summary

KongTuke, a known initial access broker (IAB) previously documented for ClickFix/CrashFix web-based lures, has expanded into Microsoft Teams as a social engineering delivery channel. Attackers use external Teams federation to contact employees while impersonating IT helpdesk staff, using Unicode whitespace tricks to make display names appear internal. The victim is persuaded to paste a PowerShell command that downloads a ZIP from Dropbox containing a portable WinPython runtime, which launches ModeloRAT (Pmanager.py). ReliaQuest observed a cold outreach-to-persistent-foothold chain completing in under five minutes. The campaign has been active since at least April 2026, rotating through five Microsoft 365 tenants to evade blocking.

---

## Relevance to Environment

Direct relevance. Your environment uses Microsoft Teams with M365/E5, and Teams external federation is likely enabled by default. If external federation is not locked to an allowlist of trusted tenants, any external Teams user can initiate chat with your employees. The helpdesk impersonation angle is particularly dangerous given your distributed footprint across Alberta, BC, and Saskatchewan — remote users are accustomed to IT interactions over Teams. ModeloRAT achieves persistence via Run keys and scheduled tasks, both of which you have visibility on through MDE. Portable Python under `%APPDATA%` is a specific hunting signal. The Dropbox download vector is relevant if Dropbox access is not blocked at the endpoint.

**Priority action:** Audit Teams external access policy immediately and enforce allowlist-based federation.

---

## Detection Notes

> `detection_candidate: false queries were all too noisy. I did discover a user with Python installed in her AppData folder that we should get her to move. 

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect pythonw.exe executing from user-writable AppData paths — hallmark of ModeloRAT portable Python runtime

let suspiciousPythonPaths = dynamic(["\\AppData\\Roaming\\WPy", "\\AppData\\Local\\WPy", "\\AppData\\Roaming\\Python", "\\AppData\\Local\\Python"]);
DeviceProcessEvents
| where FileName =~ "pythonw.exe" or FileName =~ "python.exe"
| where FolderPath has_any (suspiciousPythonPaths)
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect network connections from pythonw.exe running from AppData — ModeloRAT C2 beaconing

let suspiciousPythonPaths = dynamic(["\\AppData\\Roaming\\WPy", "\\AppData\\Local\\WPy"]);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "pythonw.exe"
| where InitiatingProcessFolderPath has_any (suspiciousPythonPaths)
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect ZIP file creation/extraction under %APPDATA% — initial staging of ModeloRAT toolkit

DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName endswith ".zip" or FolderPath has "\\AppData\\"
| where FolderPath has "\\AppData\\"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "explorer.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Table: DeviceRegistryEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Run key persistence pointing to pythonw.exe in AppData — ModeloRAT persistence mechanism

DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "\\CurrentVersion\\Run"
| where RegistryValueData has_any ("pythonw.exe", "WPy64", "AppData")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

### Validated Columns
- [x] `FolderPath` — DeviceProcessEvents, confirm column exists (vs `ProcessFolderPath`)
- [x] `RemoteIPType` — DeviceNetworkEvents, available in MDE Advanced Hunting
- [x] `RegistryValueData` — DeviceRegistryEvents, confirm column name in your schema

---

## Hardening Actions

- [x] **PRIORITY** — Audit Microsoft Teams Admin Center → External Access. Restrict external federation to an approved allowlist. Block open federation from unknown tenants.
- [ ] Block or alert on Dropbox downloads from corporate endpoints via MCAS session policy or Intune compliance rule
- [x] Educate users via comms: IT helpdesk will never send technical instructions via Teams chat. Any request to paste a PowerShell command should be treated as a social engineering attempt.
- [ ] Hunt for `WPy64-*` directories under `%APPDATA%\Roaming\` across endpoint estate using MDE Advanced Hunting

---

## Related Notes

- [[]]
- [[KQL-KongTuke-Teams-ModeloRAT-Campaign-Device]]

---

## Tags

#endpoint #identity #email #ransomware

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-18 | Created |
| 2026-05-18 | Generated 4 companion KQL notes: [[KQL-KongTuke-Teams-ModeloRAT-Campaign-Device]] |
