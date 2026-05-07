---
title: INC13862806 - Weird icon for explorer
date: 2026-05-04
case_id:
alert_id:
severity: <! Medium --->
status: closed
tags:
  - "#ir"
  - "#finding"
  - "#status/Done"
---

# Untitled

**Date:** 2026-05-04 14:31
**Analyst:** 
**Severity:** 
**Status:** Open

---

## Source

| Field             | Value                                               |
| ----------------- | --------------------------------------------------- |
| Alert / Signal    |                                                     |
| Platform          | <!--- MDE \| Sentinel \| MDO \| MCAS \| Manual ---> |
| Affected Asset(s) |                                                     |
| Affected User(s)  |                                                     |
| Detection Time    |                                                     |
| Triage Time       |                                                     |

---

## Observation

<!-- What did you see? Raw signal, alert title, or hunting result. 2-4 sentences. -->

---

## Investigation Notes

<!-- What did you do? Pivots, queries run, correlated events. Use sub-headings if needed. -->

### KQL Pivots

```kql
// // Suspicious explorer.exe - wrong path or parent

DeviceProcessEvents

| where FileName =~ "explorer.exe"

| where DeviceName =~ 'lt13061.ad.corp.local'

| where not(FolderPath has_any (@"C:\Windows\explorer.exe", @"C:\Windows\SysWOW64\explorer.exe"))

| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256

// Process hollowing indicator - explorer with unusual parent

DeviceProcessEvents

| where FileName =~ "explorer.exe"

| where DeviceName =~ 'lt13061.ad.corp.local'

| where InitiatingProcessFileName !in~ ("userinit.exe", "winlogon.exe", "explorer.exe")

| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

### Timeline

| Time (UTC) | Event |
|------------|-------|
| | |
| | |

---

## Assessment

**Verdict:** <!--- True Positive \| False Positive \| Benign \| Undetermined --->

<!-- Why. What made this a TP/FP. -->

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | |
| Technique | |
| Sub-technique | |

---

## Actions Taken

- [ ] 
- [ ] 

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[]]
- [ ] No — closing as

---

## Related Notes

- 

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-04 | Finding created |
