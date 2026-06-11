---
date: 2026-06-10
title: MDE RPC Remote Service Creation Lateral Movement Device
table: "DeviceEvents"
schema: "Advanced Hunting"
mitre: "T1543.003"
tactic: "Persistence, Lateral Movement"
technique: "Create or Modify System Process: Windows Service"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - RPC Remote Service Creation Lateral Movement"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
  - "#network"
---

# RULE -- MDE RPC Remote Service Creation Lateral Movement Device

---

**Table:** DeviceEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1543.003 | **Tactic:** Persistence, Lateral Movement | **Technique:** Create or Modify System Process: Windows Service
**Created:** 2026-06-10 | **Status:** Validated

---

## Promoted

| Field           | Detail                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| **Promoted**    | 2026-06-10                                                             |
| **Deployed To** | MDE Custom Detection                                                   |
| **Rule Name**   | Custom - RPC Remote Service Creation Lateral Movement                  |
| **Rule ID**     | <!-- Populate mde_rule_name in frontmatter when deployed in portal --> |

---

## Purpose

Detects inbound remote RPC calls to the Service Control Manager (svcctl) interface using
opcodes associated with remote service creation. Covers the Impacket PSExec/SMBExec lateral
movement pattern and similar tooling that creates services remotely to execute commands on
a target host.

Leverages the `InboundRemoteRpcCall` ActionType introduced in MDE on June 8, 2026.

**Signal:** Remote service creation via RPC is a reliable lateral movement indicator.
Legitimate remote service creation is rare outside IT management tooling (SCCM, RMM agents).
If RemoteIP is not a known management host, treat as lateral movement.

**Triage checklist:**
1. Is RemoteIP a known SCCM, Intune management, or RMM host (Site24x7, TeamViewer)?
2. Was a software deployment or patch cycle active at the time?
3. Is the target DeviceName a high-value asset (DC, server, finance workstation)?

If RemoteIP is a user workstation or unknown host — lateral movement in progress. Escalate.

---

## Query

```kql
// svcctl interface UUID -- Service Control Manager
let remoteServicesInterface = '367abb81-9844-35f1-ad32-98f038001003';
// OpNums: RCreateServiceW=12, RCreateServiceA=24,
//         RCreateServiceWOW64A=44, RCreateServiceWOW64W=45, RCreateWowService=60
let serviceCreationOpnums = dynamic([12, 24, 44, 45, 60]);
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == 'InboundRemoteRpcCall'
| extend RpcInterface = tostring(parse_json(AdditionalFields).RpcInterfaceUuid)
| extend OpNum = toint(parse_json(AdditionalFields).RpcOpNum)
| where RpcInterface =~ remoteServicesInterface
| where OpNum in (serviceCreationOpnums)
| project
    Timestamp,
    ReportId,
    DeviceName,
    DeviceId,
    RemoteIP = tostring(parse_json(AdditionalFields).RemoteIP),
    RpcInterface,
    OpNum,
    AdditionalFields
| order by Timestamp desc
```

---

## Validated Columns

- [x] `ActionType == 'InboundRemoteRpcCall'` -- confirmed flowing in tenant 2026-06-10
- [x] `parse_json(AdditionalFields).RpcInterfaceUuid` -- confirmed populated
- [x] `parse_json(AdditionalFields).RpcOpNum` -- confirmed populated
- [x] `parse_json(AdditionalFields).RemoteIP` -- confirmed populated

---

## Test Results

**7-day validation -- 2026-06-03 to 2026-06-10**

| Result | Detail |
|--------|--------|
| Events | 0 |
| Disposition | Clean baseline — no remote service creation via RPC detected |
| Telemetry confirmed | Yes — InboundRemoteRpcCall events confirmed flowing in tenant |

**FP note:** If alerts fire on IT management tooling (SCCM, RMM), add RemoteIP exclusions:
```kql
| where RemoteIP !in ("<sccm_server_ip>", "<rmm_server_ip>")
```

---

## Deployment

<!-- INACTIVE: Sentinel Analytics Rule -- DeviceEvents is Advanced Hunting only -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - RPC Remote Service Creation Lateral Movement`
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[KQL-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]] -- source KQL note
- [[RULE-MDE-RPC-Remote-Registry-Credential-Dump-Device]]
- [[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-10 | Created -- promoted from KQL note; 7-day clean baseline; telemetry confirmed |
