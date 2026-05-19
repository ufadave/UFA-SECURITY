---
date: 2026-05-06
title: Query Template
table: ""
schema: MDE
mitre: ""
tactic: TA0003 — Persistence / TA0004 — Privilege Escalation
technique: T1098 — Account Manipulation
status: promoted
promoted_to_rule: true
mde_rule_id: Advanced Hunting Query
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/active"
---

# KQL — Query Template

---

**Table:** | **Schema:** Advanced Hunting
**MITRE ATT&CK:** | **Tactic:** | **Technique:**
**Created:** 2026-05-06 | **Status:** `Done`
Source:[[IR-DFIR/Cases/IR-2026-05-07-lt13069-net-user-tcai|IR-2026-05-07-lt13069-net-user-tcai]]

---

## Purpose
	Used for investigating net.exe or net1 activity
	 Saved in Advanced Hunting queries under Shared/Hunt/HUNTING - Net1 Activity
---

## Query

```kql
// 1. All net.exe / net1.exe activity by tsandqui — last 30 days
//    Establishes whether this is a one-off or a pattern.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName == "tsandqui"
| where FileName in~ ("net.exe", "net1.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          ProcessIntegrityLevel
| sort by Timestamp desc

  
  

// 2. Anyone touching the tcai account anywhere in the estate — last 30 days
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "tcai"
| where AccountName != 'tcai'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| sort by Timestamp desc

  

// 3. Did tcai actually log on to lt13069 around or after this time?
//    Confirms whether tcai is a local account on this device.
DeviceLogonEvents
| where Timestamp > datetime(2026-05-06)
| where DeviceName == "lt13069.ad.corp.local"
| where AccountName == "tcai"
| project Timestamp, LogonType, ActionType, RemoteDeviceName, RemoteIP
| sort by Timestamp desc

  

// 4. Any local account add/modify on this host? (lateral expansion check)

DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName == "lt13069.ad.corp.local"
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("/add", "/active", "localgroup", "administrators")
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp desc

  

/ 5. SecurityEvent corroboration — did the password change actually succeed?
//    4723 = self-service change, 4724 = admin reset, 4738 = account modified,
//    4625 = failed logon (privilege denial would surface here),
//    4720 = account created, 4726 = account deleted
SecurityEvent
| where TimeGenerated > datetime(2026-05-06)
| where WorkstationName startswith "lt13069"
| where EventID in (4625, 4720, 4723, 4724, 4726, 4738)
| project TimeGenerated, EventID, Activity, TargetAccount, SubjectAccount
| sort by TimeGenerated desc
  

// Pivot 6 — full child-process history of tsandqui's cmd.exe session
DeviceProcessEvents
| where Timestamp between (datetime(2026-04-06 14:43:00) .. datetime(2026-05-06 23:59:59))
| where DeviceName == "lt13069.ad.corp.local"
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessAccountName == "tsandqui"
| project Timestamp, FileName, ProcessCommandLine, ProcessIntegrityLevel
| sort by Timestamp asc
```

---

## Validated Columns
- [ ] 
- [ ] 

---

## Test Results


---

## Deployment

> Default path is MDE Custom Detection. Only use Sentinel Analytics Rule for signals that do not exist in Advanced Hunting — identity (SigninLogs, AuditLogs), cloud (CloudAppEvents), and email (EmailEvents).

### MDE Custom Detection Rule
<!-- Default for all device-based detections — DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, etc. -->
- **Rule Name:** Query Template
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Actions:** `<!-- Alert only | Isolate device | Restrict app execution | Run AV scan -->`
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- Use only for Log Analytics sources — SigninLogs, AuditLogs, CloudAppEvents, EmailEvents, OfficeActivity, SecurityEvent (if ingested) -->
- **Rule Name:** Query Template
- **Frequency:**
- **Lookback:**
- **Severity:**
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-06 | Created |
