---
title: "IR-2026-05-07-lt13069-net-user-tcai"
date: 2026-05-07
case_id: IR-2026-05-07-lt13069-01
alert_id: 
severity: Medium
status: open
tags:
  - "#ir"
  - "#finding"
  - "#endpoint"
  - "#identity"
  - "#action-required"
  - "#status/active"
---

# IR-2026-05-07-lt13069-net-user-tcai

**Date:** 2026-05-07
**Analyst:** Dave
**Severity:** Medium (pending IT confirmation of user roles)
**Status:** Open

---

## Source

| Field | Value |
|-------|-------|
| Alert / Signal | Manual review of `DeviceProcessEvents` export |
| Platform | MDE (Advanced Hunting) |
| Affected Asset(s) | `lt13069.ad.corp.local` |
| Affected User(s) | `ad\tsandqui` (initiator), `tcai` (target) |
| Detection Time | 2026-05-06 15:16:31 (local) |
| Triage Time | 2026-05-07 |

---

## Observation

A `net user tcai *` command was executed on `lt13069.ad.corp.local` by `ad\tsandqui` running at Medium integrity. The command was issued from an interactive `cmd.exe` session that was launched ~33 minutes earlier from `explorer.exe`. The asterisk argument is the interactive password-change syntax, indicating `tsandqui` was prompted to enter a new password for the `tcai` account. No `/domain` switch was used — this is a local SAM password modification, not a domain operation.

---

## Investigation Notes

### Process Lineage

```
winlogon.exe
  └── userinit.exe
        └── explorer.exe                          [tsandqui — Medium IL — 12:29:08]
              └── cmd.exe                          [tsandqui — Medium IL — 14:43:28]
                    └── net.exe user tcai *        [tsandqui — Medium IL — 15:16:31]
                          └── net1.exe user tcai * [tsandqui — Medium IL — 15:16:31]
```

### KQL Pivots

```kql
// 1. All net.exe / net1.exe activity by tsandqui — last 30 days
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName == "tsandqui"
| where FileName in~ ("net.exe", "net1.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          ProcessIntegrityLevel
| sort by Timestamp desc
```

```kql
// 2. Anyone touching the tcai account anywhere in the estate — last 30 days
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "tcai"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| sort by Timestamp desc
```

```kql
// 3. Did tcai actually log on to lt13069 around or after this time?
DeviceLogonEvents
| where Timestamp > datetime(2026-05-06)
| where DeviceName == "lt13069.ad.corp.local"
| where AccountName == "tcai"
| project Timestamp, LogonType, ActionType, RemoteDeviceName, RemoteIP
| sort by Timestamp desc
```

```kql
// 4. Any local account add/modify on this host? (lateral expansion check)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName == "lt13069.ad.corp.local"
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("/add", "/active", "localgroup", "administrators")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

```kql
// 5. SecurityEvent corroboration — Windows event log perspective
//    4720 = account created, 4722 = enabled, 4723 = self password change,
//    4724 = admin password reset, 4738 = account modified
SecurityEvent
| where TimeGenerated > datetime(2026-05-06)
| where Computer startswith "lt13069"
| where EventID in (4720, 4722, 4723, 4724, 4726, 4738)
| project TimeGenerated, EventID, Activity, TargetAccount, SubjectAccount
| sort by TimeGenerated desc
```

### Timeline (UTC offsets unverified — times as recorded in MDE)

| Time | Event |
|------|-------|
| 2026-05-06 12:29:08 | `tsandqui` interactive logon — `explorer.exe` started via `userinit` → `winlogon` |
| 2026-05-06 14:40:33 | Intune Proactive Remediation `detect.ps1` ran as SYSTEM (unrelated context) |
| 2026-05-06 14:43:28 | `tsandqui` opened `cmd.exe` from `explorer.exe` |
| 2026-05-06 15:16:31 | `net user tcai *` executed → `net1.exe user tcai *` |

### Open Questions for IT

1. Is `ad\tsandqui` a help-desk / IT operator with delegated administrative responsibility?
2. Is `tcai` a local account on `lt13069`, a shared/break-glass account, or a domain user?
3. Does `tsandqui` hold local admin rights on `lt13069`? (If yes — separate hardening conversation re: local admin distribution.)
4. Is there a documented help-desk workflow that uses `net user *` against local SAM accounts on user laptops? (If no — this is a deviation from standard practice regardless of intent.)

---

## Assessment

**Verdict:** Undetermined — pending IT confirmation

**Reasoning:**
- Behaviour fits ATT&CK [T1098 — Account Manipulation] as a primitive, but no other indicators of compromise are present in this dataset (no `/add`, no `/active:yes`, no group membership change, no follow-on lateral movement).
- The action being interactive (Medium IL, parent `cmd.exe`, parent of that `explorer.exe`) is consistent with either a benign hands-on-keyboard help-desk operation or a user exceeding their authority. Process lineage alone cannot distinguish.
- Whether `tsandqui` had the right to do this is an authorisation question, not a detection question. IT/HR can resolve it in one conversation.

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | TA0003 — Persistence / TA0004 — Privilege Escalation |
| Technique | T1098 — Account Manipulation |
| Sub-technique | (none — local SAM password change is the base technique) |

---

## Actions Taken

- [ ] Confirm `tsandqui` role with IT manager
- [ ] Confirm `tcai` account scope (local vs domain) on `lt13069`
- [ ] Run pivot queries 1–5 and attach results
- [ ] If unauthorised — escalate to `IR-` case and notify HR
- [ ] If authorised — close as Benign with rationale documented
- [ ] Cross-reference with [[HUNTING-net-user-password-change]] as sample case

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[]]
- [ ] No — closing as: _pending IT response_

---

## Related Notes

- [[HUNTING-net-user-password-change]] — reusable hunt this finding seeded

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Finding created from MDE export review of `lt13069.ad.corp.local` process events |
