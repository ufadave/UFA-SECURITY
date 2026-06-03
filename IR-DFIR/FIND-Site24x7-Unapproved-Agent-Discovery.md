---
title: "FIND-Site24x7-Unapproved-Agent-Discovery"
date: 2026-05-26
case_id: 
alert_id: 
severity: Medium
status: open
tags:
  - "#ir"
  - "#finding"
  - "#status/done"
  - "#endpoint"
  
---

# FIND — Site24x7 Unapproved Agent Discovery

**Date:** 2026-05-26
**Analyst:** Dave
**Severity:** Medium
**Status:** done

---

## Source

| Field | Value |
|-------|-------|
| Alert / Signal | Command line submitted for analysis — PowerShell spawning child process executing Site24x7 plugin |
| Platform | MDE |
| Affected Asset(s) | TBD — fleet-wide scope query pending |
| Affected User(s) | TBD |
| Detection Time | TBD |
| Triage Time | 2026-05-26 |

---

## Observation

A PowerShell command line was submitted for analysis referencing the Site24x7 WinAgent monitoring plugin path (`C:\Program Files (x86)\Site24x7\WinAgent\monitoring\Plugins\windows_security\security_events.ps1`). The outer PowerShell spawns a child PowerShell process with `-ExecutionPolicy Bypass`, executes the plugin with a 25-second watchdog timeout, and collects security telemetry including malware detections, account lockouts, failed logins, and RDP/remote connection data. Site24x7 is not listed as an approved tool in this environment — no procurement record, IT approval, or security assessment exists at time of writing.

---

## Technical Breakdown

### Command Line Observed

```
powershell -Command "$process= Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File ""C:\Program Files (x86)\Site24x7\WinAgent\monitoring\Plugins\windows_security\security_events.ps1""' -PassThru -NoNewWindow -ErrorAction SilentlyContinue; $process | Wait-Process -Timeout 25 -ErrorAction SilentlyContinue; if ($process.ExitCode -ne 0 -or-not $process.HasExited) { Write-Output '{\"Malware Detections\":-1,...}'; Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }"
```

### Behavioural Characteristics

- Outer PowerShell spawns child PowerShell — classic LOLBin parent-child chain pattern
- `-ExecutionPolicy Bypass` circumvents script execution policy
- Plugin path: `C:\Program Files (x86)\Site24x7\WinAgent\monitoring\Plugins\windows_security\security_events.ps1`
- 25-second watchdog timeout with JSON fallback on failure or non-zero exit code
- Collects: Malware Detections, Account Lockouts, Failed Logins, RDP Connections, Remote Connections (with process detail)
- Kill signal issued to child process on timeout

### Software Identification

Site24x7 is a SaaS infrastructure and APM platform by Zoho Corporation / ManageEngine. The agent installs as a Windows service and executes plugins to collect and ship telemetry to the Site24x7 cloud platform.

---

## Risk Assessment

### Risk Factors

- Software is **not approved** — no procurement, IT, or security record
- Agent actively collects sensitive security telemetry (lockouts, failed logins, RDP sessions) and exfiltrates to a cloud platform
- `-ExecutionPolicy Bypass` and parent-child PowerShell chain are TTPs commonly observed in malicious activity
- Scope of deployment across the fleet is unknown
- Presence on OT/SCADA assets or POS terminals would be critical

### Mitigating Factors

- Install path (`Program Files (x86)`) is consistent with a legitimate MSI deployment, not a dropped payload
- JSON fallback structure is complex and highly specific — not characteristic of malware
- Site24x7 is a legitimate, well-known commercial product
- Plugin timeout watchdog pattern matches Site24x7 documented plugin architecture

### Current Rating

**Medium** — legitimate software profile, but unapproved and actively exfiltrating security telemetry. Escalation criteria defined below.

---

## Investigation Notes

### KQL Pivots

#### 4.1 — Fleet-Wide Scope

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "Site24x7"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by LastSeen desc
```

#### 4.2 — Parent Process Validation

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "Site24x7"
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

#### 4.3 — File System — Plugin Script

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "Site24x7"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

#### 4.4 — Network Egress

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "Site24x7WindowsAgent.exe"
    or InitiatingProcessCommandLine has "Site24x7"
| summarize Connections=count(), Bytes=sum(SentBytes)
    by DeviceName, RemoteIP, RemotePort, RemoteUrl
| order by Connections desc
```

#### 4.5 — Service Installation

```kql
DeviceEvents
| where Timestamp > ago(90d)
| where ActionType == "ServiceInstalled"
| where AdditionalFields has "Site24x7" or AdditionalFields has "site24x7"
| project Timestamp, DeviceName, ActionType, AdditionalFields
| order by Timestamp asc
```

### Timeline

| Time (UTC) | Event |
|------------|-------|
| TBD | Agent installation date (check installer logs / file creation timestamps) |
| TBD | First execution observed in MDE telemetry |
| 2026-05-26 | Command line flagged for analysis — this finding opened |

---

## Assessment

**Verdict:** Undetermined

Behaviour is consistent with a legitimate Site24x7 deployment. However, the software is unapproved and the deployment source is unconfirmed. Verdict depends on parent process validation, hash verification, and IT attribution. Do not contain until attribution is confirmed.

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | Discovery, Collection, Exfiltration |
| Technique | T1518 — Software Discovery; T1041 — Exfiltration Over C2 Channel (conditional) |
| Sub-technique | T1059.001 — Command and Scripting Interpreter: PowerShell |

---

## Immediate Actions

- [ ] Run 4.1 fleet-wide query — determine scope of deployment
- [ ] Run 4.2 parent process validation — confirm initiating process is `Site24x7WindowsAgent.exe`
- [ ] Hash `security_events.ps1` (SHA256) — compare against Site24x7 published or clean-install values
- [ ] Hash `Site24x7WindowsAgent.exe` (SHA256) — verify against known-good
- [ ] Review installation date — Windows installer logs and file creation timestamps
- [ ] Contact IT/Operations — determine if deployed via Intune, SCCM, or manual change request
- [ ] Run 4.4 network egress query — confirm all outbound destinations are Site24x7 cloud endpoints
- [ ] Check Site24x7 portal — if an account exists, confirm enrolled hosts and account owner
- [ ] Run 4.5 service installation query — confirm install date and scope

## Escalation Criteria

Escalate to **High** and initiate full IR if any of the following are confirmed:

- [ ] Parent process is **not** `Site24x7WindowsAgent.exe`
- [ ] Plugin script hash does not match a clean Site24x7 installation
- [ ] Installation cannot be attributed to a known change request
- [ ] Agent is present on **OT/SCADA assets or POS terminals**
- [ ] Network traffic observed to non-Site24x7 destinations
- [ ] No Site24x7 account exists but agent is actively reporting

## Containment Options

> ⚠️ Do NOT contain until attribution is confirmed.

If agent is determined to be unauthorised:

- [ ] Isolate affected host(s) via MDE — device isolation
- [ ] Block `Site24x7WindowsAgent.exe` hash via MDE indicator
- [ ] Block outbound traffic to Site24x7 cloud endpoints at proxy/firewall
- [ ] Remove agent and plugin files — engage IT for uninstall via Intune if MSI-deployed
- [ ] Preserve artefacts before removal — plugin script, agent binary, installer logs

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[]]
- [ ] No — closing as

---

## Related Notes

- [[]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-26 | Finding created from IR note submission |
