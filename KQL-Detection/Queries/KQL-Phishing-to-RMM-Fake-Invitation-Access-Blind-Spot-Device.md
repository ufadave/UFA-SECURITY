---
date: 2026-05-28
title: Phishing to RMM Fake Invitation Access Blind Spot Device
table: DeviceProcessEvents, DeviceNetworkEvents
schema: Advanced Hunting
mitre:
  - T1566.002
  - T1219
  - T1556
tactic: "Initial Access, Command and Control"
technique: "T1219 — Remote Access Software; T1566.002 — Spearphishing Link"
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#endpoint"
  - "#network"
---

# KQL — Phishing to RMM Fake Invitation Access Blind Spot Device

**Table:** DeviceProcessEvents, DeviceNetworkEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1219, T1566.002 | **Tactic:** Initial Access, Command and Control
**Created:** 2026-05-28 | **Status:** `Draft`

---

## Purpose

Two device-side detection stubs for the phishing-to-RMM access blind spot technique — attackers deliver a fake meeting/event invitation that leads to installation of a legitimate RMM tool, establishing persistent remote access that bypasses traditional C2 detection because the traffic is signed and trusted.

- **Stub 1 (DeviceProcessEvents):** Execution of known RMM tools not in your approved software baseline. Adjust the process name list to match any RMM tools that ARE approved in your environment — the exclusion is equally important as the detection list.
- **Stub 2 (DeviceNetworkEvents):** Outbound connections from known RMM tool processes to their control infrastructure.

See `KQL-Phishing-to-RMM-Fake-Invitation-Email` for the MDO-side email signal (fake invitation lure patterns).

> **Important:** If your organisation uses any of the listed RMM tools legitimately (e.g. a managed IT provider), add those binaries to an exclusion list scoped to the devices or device groups where they're expected. Blind deployment of this query will generate noise proportional to your approved RMM footprint.

---

## Query

```kql
// Stub 1 — RMM tool execution outside approved baseline
// Adjust exclusion list for any tools your organisation uses legitimately
// Add device group scoping if a managed IT provider uses approved RMM tools on specific devices
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe",
    "ConnectWiseControl.ClientService.exe",
    "DattoRMM.exe",
    "ITarian.exe",
    "LogMeInRescue.exe",
    "Action1.exe",
    "NetSupportManager.exe",
    "MeshAgent.exe",
    "SimpleHelp.exe",
    "RustDesk.exe",
    "Splashtop.exe"
)
// Add exclusions for approved RMM tools here:
// | where not(FileName =~ "ApprovedTool.exe" and DeviceName in ("managed-device-1", "managed-device-2"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Stub 2 — Outbound connections from RMM tool processes
// Detects C2 registration and session establishment from unapproved RMM installations
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "ScreenConnect.ClientService.exe",
    "MeshAgent.exe",
    "Action1.exe",
    "RustDesk.exe",
    "SimpleHelp.exe"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `FileName` — DeviceProcessEvents ✓ standard column
- [ ] `ProcessCommandLine` — DeviceProcessEvents ✓ standard column
- [ ] `FolderPath` — DeviceProcessEvents ✓ standard column
- [ ] `InitiatingProcessFileName` — DeviceNetworkEvents ✓ standard column
- [ ] `RemoteUrl` — DeviceNetworkEvents — **validate in your environment**; may not be populated; `RemoteIP` more reliable
- [ ] `InitiatingProcessAccountName` — DeviceNetworkEvents — confirm field name vs `AccountName`
- [ ] RMM baseline — confirm which (if any) RMM tools are approved before deploying

---

## Test Results

- [ ] Tested in environment
- [ ] Confirm no approved RMM tools in use that would generate immediate FPs
- [ ] Stub 1: check IT/admin devices for legitimate remote support tools
- [ ] Stub 2: lower FP risk than Stub 1 — network connection from these processes is the stronger signal
- [ ] FP rate acceptable

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Unapproved RMM Tool Execution or Network Activity
- **Frequency:** every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceProcessEvents and DeviceNetworkEvents are Advanced Hunting only -->
<!-- Deploy via MDE Custom Detection -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot]]
- [[KQL-Phishing-to-RMM-Fake-Invitation-Email]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-28 | Created — backfill companion to [[INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot]] via backfill stubs command |
