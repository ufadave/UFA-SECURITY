---
title: "IR-2026-05-07-lt13069-net-user-tcai"
date: 2026-05-07
case_id: IR-2026-05-07-lt13069-01
alert_id: 145243
severity: Medium
status: done
tags:
  - "#ir"
  - "#finding"
  - "#endpoint"
  - "#identity"
  - "#status/done"
  - "#net.exe"
---

# IR-2026-05-07-lt13069-net-user-tcai

**Date:** 2026-05-07
**Analyst:** Dave
**Severity:** Medium (pending confirmation that password change executed successfully)
**Status:** Review — pending IT/HR follow-up

---

## Source

| Field | Value |
|-------|-------|
| Alert / Signal | Manual review of `DeviceProcessEvents` export |
| Platform | MDE (Advanced Hunting) |
| Affected Asset(s) | `lt13069.ad.corp.local` |
| Affected User(s) | `ad\tsandqui` (initiator — financial analyst, per user statement), `tcai` (target — relationship to initiator unconfirmed) |
| Detection Time | 2026-05-06 15:16:31 (local) |
| Triage Time | 2026-05-07 |

---

## Observation

A `net user tcai *` command was executed on `lt13069.ad.corp.local` by `ad\tsandqui` running at Medium integrity. The command was issued from an interactive `cmd.exe` session that was launched ~33 minutes earlier from `explorer.exe`. The asterisk argument is the documented interactive password-change syntax, indicating `tsandqui` was prompted to enter a new password for the `tcai` account. No `/domain` switch was used — this is a local SAM password modification, not a domain operation.

---

## User Statement vs. Observed Behaviour

> ⚠️ This section captures the user's contemporaneous explanation alongside the technical reality. The mismatch is itself evidence and is documented here for future reference.

### User's Stated Explanation

When questioned, `tsandqui` (financial analyst) stated he was attempting to determine **what group access** another user (`tcai`) had.

### Technical Reality

The command executed was:

```
net user tcai *
```

This command has exactly one documented function: it triggers an **interactive password change prompt** for the local `tcai` account. The asterisk is not a wildcard, not a query operator, and not related to group enumeration. It is Microsoft-documented syntax for "prompt the operator for a new password and apply it."

Group-membership inspection commands are syntactically distinct:

| Intent | Correct Command |
|--------|----------------|
| View user details (incl. group memberships) | `net user tcai` (no asterisk) |
| View domain user details | `net user tcai /domain` |
| List members of a local group | `net localgroup administrators` |
| List current user's groups | `whoami /groups` |

### Analytical Assessment of the Mismatch

The stated intent (group enumeration) is not consistent with the command executed (password change). Three observations follow:

1. **The asterisk is unambiguous.** `net user <name> *` is not a syntactic neighbour of any group-lookup command — it is a different command class entirely.
2. **The interactive prompt is unmissable.** If the command was executed, the operator was presented with a password entry prompt. Continuing past that prompt requires entering a value twice. Backing out requires a deliberate `Ctrl+C`.
3. **The 33-minute gap between `cmd.exe` opening and the command executing** is consistent with research/preparation rather than an accidental keystroke.

### Disposition of the Statement

The user's explanation is documented but is not assessed as credible given the technical specifics. This finding proceeds on the basis of observed behaviour, not stated intent.

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
//    Establishes whether this is a one-off or a pattern.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName == "tsandqui"
| where FileName in~ ("net.exe", "net1.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          ProcessIntegrityLevel
| sort by Timestamp desc
```
Pivot 1 returned 12 rows multiple users. 
```kql
// 2. Anyone touching the tcai account anywhere in the estate — last 30 days
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "tcai"
| where AccountName != 'tcai'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| sort by Timestamp desc
```
Pivot 2 - Modified query to exclude 'tcai'
        - only returned tsandqui net.exe activity on the 6th.
```kql
// 3. Did tcai actually log on to lt13069 around or after this time?
//    Confirms whether tcai is a local account on this device.
DeviceLogonEvents
| where Timestamp > datetime(2026-05-06)
| where DeviceName == "lt13069.ad.corp.local"
| where AccountName == "tcai"
| project Timestamp, LogonType, ActionType, RemoteDeviceName, RemoteIP
| sort by Timestamp desc
```
Pivot 3 - No rows returned
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
Pivot 4 returned 0 rows
```kql
// 5. SecurityEvent corroboration — did the password change actually succeed?
//    4723 = self-service change, 4724 = admin reset, 4738 = account modified,
//    4625 = failed logon (privilege denial would surface here),
//    4720 = account created, 4726 = account deleted
SecurityEvent
| where TimeGenerated > datetime(2026-05-06)
| where WorkStationName startswith "lt13069"
| where EventID in (4625, 4720, 4723, 4724, 4726, 4738)
| project TimeGenerated, EventID, Activity, TargetAccount, SubjectAccount
| sort by TimeGenerated desc
```
Pivot 5 Returned 0 rows
```kql
// Pivot 6 — full child-process history of tsandqui's cmd.exe session
DeviceProcessEvents
| where Timestamp between (datetime(2026-05-06 14:43:00) .. datetime(2026-05-06 23:59:59))
| where DeviceName == "lt13069.ad.corp.local"
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessAccountName == "tsandqui"
| project Timestamp, FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by Timestamp asc
```
 
Pivot 6 returned net.exe activity and whoami / groups which does jive with the users story. He also ran sudo with no parameters. 
### Timeline (UTC offsets unverified — times as recorded in MDE)

| Time | Event |
|------|-------|
| 2026-05-06 12:29:08 | `tsandqui` interactive logon — `explorer.exe` started via `userinit` → `winlogon` |
| 2026-05-06 14:40:33 | Intune Proactive Remediation `detect.ps1` ran as SYSTEM (unrelated context) |
| 2026-05-06 14:43:28 | `tsandqui` opened `cmd.exe` from `explorer.exe` |
| 2026-05-06 15:16:31 | `net user tcai *` executed → `net1.exe user tcai *` |
| 2026-05-07 _(time)_ | User questioned; provided "group access lookup" explanation |

### Key Questions for Follow-up

1. **Did the password change succeed?** Pivot 5 (`SecurityEvent` corroboration) answers this directly. If 4724 or 4738 appears for `tcai` at 15:16:31, the change committed. If 4625 or no SAM-modification event appears, the command likely failed due to insufficient rights.
     Did not succeed. 
2. **Does `tsandqui` have local admin on `lt13069`?** If yes — separate hardening conversation about local admin distribution to non-IT roles. A financial analyst with local admin is a finding in its own right.
     Does not have local admin
3. **Is `tcai` a local-only account, or shared/used elsewhere?** Pivot 3 confirms local logon history. If `tcai` is also a domain account used at other endpoints (POS, OT, shared kiosk), scope expands accordingly.
   No to both
4. **Has `tsandqui` done this before?** Pivot 1 surfaces 30-day history. A clean history reduces this to a one-off; any pattern materially escalates the finding.
     He hasn't done this before. 
---

## Assessment

**Verdict:** True Positive — unauthorised user action (pending corroboration of execution success)

**Reasoning:**

- The command executed (`net user tcai *`) is a Microsoft-documented interactive password change. There is no plausible alternative interpretation of the syntax.
- The user-supplied explanation (group-access enumeration) is not consistent with the command class. Group enumeration uses different syntax that does not include the asterisk operator.
- Whether the change committed (admin rights present) or failed (no rights) does not alter the verdict on intent — it only adjusts the operational severity. Even a failed attempt represents a deliberate action by `tsandqui` to modify another user's credential, justified to the analyst with an inaccurate explanation.
- Disposition is **policy/HR matter**, not malware/intrusion. No evidence of external actor involvement; no follow-on lateral movement, account creation, or group membership change observed in this dataset.

---

## MITRE ATT&CK

| Field         | Value                                                    |
| ------------- | -------------------------------------------------------- |
| Tactic        | TA0003 — Persistence / TA0004 — Privilege Escalation     |
| Technique     | T1098 — Account Manipulation                             |
| Sub-technique | (none — local SAM password change is the base technique) |

---

## Actions Taken

- [x] Run pivot 5 (`SecurityEvent` 4723/4724/4738/4625) — confirm whether password change committed or failed
- [x] Run pivot 3 (`DeviceLogonEvents`) — confirm `tcai` is local account on `lt13069`
- [x] Run pivot 1 (`tsandqui` `net.exe` history) — confirm one-off vs. pattern
- [x] If change committed: notify `tcai`, force password reset to value unknown to `tsandqui`
- [x] If `tcai` is shared/used elsewhere: scope expansion (POS, OT, kiosk usage)
- [x] Confirm `tsandqui` local admin status on `lt13069` (independent finding if true)
- [ ] Capture user statement verbatim in writing (not just analyst paraphrase)
- [ ] Engage IT manager and HR — policy violation regardless of execution outcome
- [x] Document final disposition and close

---

## Escalate to Case?

- [x] Yes — **escalate to formal `IR-` case once pivot 5 confirms success/failure of the password change**. The case title and severity will depend on the outcome:
    - **If committed against a local-only account** → keep as Medium-severity policy/HR case
    - **If committed against a shared/privileged account** → escalate severity, expand scope
    - **If failed (no rights)** → still escalate to HR but lower operational urgency
- [ ] Linked case: [[]]

---

## Related Notes

- [[KQL-net-user-password-change]] — reusable hunt this finding seeded; this case becomes the documented sample positive
- [[KQL - HUNTING Net1 Net activity]]
 
---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Finding created from MDE export review of `lt13069.ad.corp.local` process events |
| 2026-05-07 | User questioned — stated explanation captured; verdict moved from Undetermined to True Positive based on syntactic mismatch between stated intent and command executed; status moved to review pending pivot 5 corroboration |
