---
date: 2026-05-18
title: TeamPCP FIRESCALE Supply Chain C2 Resilience Device
table: DeviceProcessEvents, DeviceNetworkEvents
schema: Advanced Hunting
mitre: T1552.001, T1567.001, T1083
tactic: Credential Access, Exfiltration, Discovery
technique: Credentials in Files, Exfiltration to GitHub, File and Directory Discovery
status: Done
promoted_to_rule: true
mde_rule_name: Custom -  Python Harvesting Credentials Detected
tags:
  - "#detection"
  - "#status/done"
  - "#endpoint"
  - "#cloud"
  - "#supply-chain"
---

# KQL — TeamPCP FIRESCALE Supply Chain C2 Resilience Device

---

**Table:** DeviceProcessEvents, DeviceNetworkEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1552.001, T1567.001, T1083 | **Tactic:** Credential Access, Exfiltration, Discovery
**Created:** 2026-05-18 | **Status:** Done

---

## Purpose

Detect TeamPCP / FIRESCALE credential harvesting and GitHub-based exfiltration patterns. The malware reads `.env` files, SSH keys, and Docker secrets via Python processes, then exfiltrates via the victim's own GitHub account as a C2 evasion technique.

---

## Query — 1: Python Credential File Access

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Python-based malware reading .env files and SSH configuration — FIRESCALE/TeamPCP credential harvesting pattern

DeviceProcessEvents
| where FileName in~ ("python.exe", "python3", "python")
| where ProcessCommandLine has_any (".env", "id_rsa", "id_ed25519", ".ssh/config", "docker.sock")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

## Query — 2: Python Outbound to GitHub API (Exfiltration)

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound connections from Python processes to GitHub API — potential exfiltration via victim's own GitHub account

DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("python.exe", "python3", "pythonw.exe")
| where RemoteUrl has "api.github.com" or RemoteUrl has "raw.githubusercontent.com"
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Validated Columns
- [x] `ProcessCommandLine` — DeviceProcessEvents
- [x] `FolderPath` — DeviceProcessEvents (vs `ProcessFolderPath`)
- [x] `RemoteUrl` — DeviceNetworkEvents
- [x] `RemoteIPType` — DeviceNetworkEvents

---

## Test Results

<!-- Note: Python to GitHub API may produce false positives on developer endpoints. Scope with exclusions for known-good developer machines if needed. -->

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom -  Python Harvesting Credentials Detected
- **Frequency:** NRT
- **Lookback:** 1h
- **Severity:** <Medium>
- **Actions:** `Alert only`
- **Deployed:** [ Yes]
- **Rule Name:** Custom -  Python Harvesting Credentials Detected

<!-- INACTIVE: Sentinel Analytics Rule — Advanced Hunting schema; deploy as MDE Custom Detection -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

## Related Notes
- [[INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-18 | Created — companion to [[INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience]] |
