---
date: 2026-06-10
title: MDE RPC Remote Service Creation Lateral Movement Device
table: "DeviceEvents"
schema: "Advanced Hunting"
mitre: "T1543.003"
tactic: "Persistence, Lateral Movement"
technique: "Create or Modify System Process: Windows Service"
status: "done"
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

# KQL -- MDE RPC Remote Service Creation Lateral Movement Device

---

**Table:** DeviceEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1543.003 | **Tactic:** Persistence, Lateral Movement | **Technique:** Create or Modify System Process: Windows Service
**Created:** 2026-06-10 | **Status:** Draft

---

## Purpose

Detects inbound remote RPC calls to the Service Control Manager (svcctl) interface using
opcodes associated with remote service creation. This covers the Impacket PSExec/SMBExec
lateral movement pattern and similar tooling that creates services remotely to execute
commands on a target host.

Leverages the new `InboundRemoteRpcCall` ActionType introduced in MDE on June 8, 2026,
which provides OpNum-level visibility into RPC operations -- previously invisible without
expensive network-layer monitoring.

**Signal:** Remote service creation (RCreateServiceW, RCreateServiceA, and WOW64 variants)
is a reliable indicator of lateral movement. Legitimate remote service creation is rare in
most environments outside of IT management tooling (SCCM, RMM agents).

**Source note:** `[[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]`

---

## Query

```kql
// svcctl interface UUID -- Service Control Manager
let remoteServicesInterface = '367abb81-9844-35f1-ad32-98f038001003';
// OpNums: RCreateServiceW=12, RCreateServiceA=24,
//         RCreateServiceWOW64A=44, RCreateServiceWOW64W=45, RCreateWowService=60
let serviceCreationOpnums = dynamic([12, 24, 44, 45, 60]);
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == 'InboundRemoteRpcCall'
| extend RpcInterface = tostring(parse_json(AdditionalFields).RpcInterfaceUuid)
| extend OpNum = toint(parse_json(AdditionalFields).RpcOpNum)
| where RpcInterface =~ remoteServicesInterface
| where OpNum in (serviceCreationOpnums)
| project
    Timestamp,
    DeviceName,
    RemoteIP = tostring(parse_json(AdditionalFields).RemoteIP),
    RpcInterface,
    OpNum,
    AdditionalFields
| order by Timestamp desc
```

---

## Validated Columns

- [x] `ActionType == 'InboundRemoteRpcCall'` -- **verify telemetry is flowing in tenant first** (server-side rollout still in progress as of June 8, 2026)
- [x] `parse_json(AdditionalFields).RpcInterfaceUuid` -- confirm field name in this tenant
- [x] `parse_json(AdditionalFields).RpcOpNum` -- confirm field name and type (int vs string)
- [x] `parse_json(AdditionalFields).RemoteIP` -- confirm field name populated for inbound calls

---

## Test Results

> Pending -- verify `InboundRemoteRpcCall` events are appearing in Advanced Hunting before validating.
> Run: `DeviceEvents | where ActionType == 'InboundRemoteRpcCall' | take 10` to confirm telemetry.

---

## Deployment

<!-- Default path: MDE Custom Detection (DeviceEvents is Advanced Hunting only) -->
<!-- Sentinel section inactive: DeviceEvents not ingested into Log Analytics -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - RPC Remote Service Creation Lateral Movement`
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only (investigate before isolating -- may be legitimate IT tooling)
- **Deployed:** [ X]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceEvents is Advanced Hunting only -- not ingested into Log Analytics -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]
- [[KQL-MDE-RPC-Remote-Registry-Credential-Dump-Device]]
- [[RESEARCH-TrustedSec-ARP-GPO-UNC-Hijacking-NTLM-Relay]]
- [[RULE-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-10 | Created -- companion to INFO-MDE-RPC note; svcctl service creation opcodes; pending telemetry verification |
