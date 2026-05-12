---
title: INTEL-MS-Edge-Cleartext-Passwords-Process-Memory
date: 2026-05-07
source: "https://isc.sans.edu/diary/32954"
author: "Rob VandenBrink (SANS ISC)"
mitre:
  - "T1555.003"
  - "T1003"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#identity"
  - "#action-required"
---

# INTEL-MS-Edge-Cleartext-Passwords-Process-Memory

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://isc.sans.edu/diary/32954 |
| **Author** | Rob VandenBrink — SANS Internet Storm Center |
| **Date Observed** | 2026-05-07 |
| **Date Published** | 2026-05-04 (Updated 2026-05-05) |
| **Patch Available** | No — Microsoft classifies as "intended behavior" |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers |
| T1003 | OS Credential Dumping (via memory dump) |

---

## Summary

Microsoft Edge loads all saved browser passwords into process memory as cleartext at launch — regardless of whether those credentials have been used in the current session. A memory dump of the Edge `browser` subprocess (via Task Manager → Create Memory Dump, or programmatically) exposes the full plaintext credential set. Researcher @L1v1ng0ffTh3L4N confirmed this via Sysinternals Strings against the dump file. Microsoft has acknowledged the behaviour and classified it as by-design. Edge is reportedly the only Chromium-based browser exhibiting this credential pre-loading behaviour.

---

## Relevance to Environment

High. Edge is the default browser across your managed Windows estate (MDE/Intune). If any user has saved credentials in Edge's built-in password manager — particularly domain credentials, Entra ID sessions, or M365 service accounts — those are trivially extractable post-compromise with no elevated privilege required for the dump step. This substantially lowers the post-exploitation bar on any MDE-managed endpoint. OT jump hosts at the fertilizer plant are an additional concern if Edge is deployed there. Priority: audit Edge password manager usage and push credential hygiene guidance.

---

## Detection Notes

`detection_candidate: true` — Two distinct detection surfaces: process-level memory dump creation targeting Edge, and Strings/credential scraping tool execution.

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect memory dump creation targeting the Microsoft Edge browser subprocess
// T1003 / T1555.003

DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("procdump.exe", "procdump64.exe", "taskmgr.exe", "comsvcs.dll")
     or (FileName =~ "rundll32.exe" and ProcessCommandLine has "MiniDump")
| where ProcessCommandLine has_any ("msedge", "edge", "browser")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Sysinternals Strings or similar tool execution post-Edge dump
// T1555.003

DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("strings.exe", "strings64.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

```kql
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect .dmp file creation in Temp paths (output of Task Manager memory dump)
// Adjust path filter to match your environment

DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".dmp"
| where FolderPath has_any ("Temp", "AppData", "Downloads")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

### Validated Columns
- [ ] `ProcessCommandLine` — confirm in `DeviceProcessEvents` (standard column)
- [ ] `InitiatingProcessFileName` — confirm in `DeviceProcessEvents` (standard column)
- [ ] `FolderPath` — confirm in `DeviceFileEvents` (standard column)
- [ ] `ActionType == "FileCreated"` — validate `ActionType` values available in your tenant

---

## Hardening Actions

- [ ] **Audit Edge password manager usage** — Identify users with saved credentials via Intune device compliance or MDE advanced hunting; encourage migration to a dedicated password manager
- [ ] **Push credential hygiene guidance** — Users should not save domain or M365 credentials in Edge's built-in password manager
- [ ] **Consider disabling Edge built-in password manager via Intune/GPO** — `PasswordManagerEnabled` policy (Chromium-based GPO) — evaluate operational impact before enforcing
- [ ] **Review OT jump hosts** — Confirm Edge deployment status at fertilizer plant; if present, flag for immediate credential audit
- [ ] **Monitor for procdump / memory dump activity** — Promote detection stub above to hunting query; assess for analytics rule if signal is low-noise

---

## Related Notes

- [[KQL-Edge-Password-Memory-Dump-Detection]]
- [[HARD-Disable-Edge-Built-In-Password-Manager]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Created — email tagged [[INTEL]] SANS ISC diary 32954 |
