---
title: INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06
date: 2026-06-10
source: "https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/microsoft-defender-now-monitors-rpc-activity/4523368"
tags:
  - "#resource"
  - "#status/done"
  - "#endpoint"
  - "#network"
  - "#detection"
---

# INFO -- MDE Now Monitors RPC Activity (June 8, 2026)

**Source:** https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/microsoft-defender-now-monitors-rpc-activity/4523368
**Date:** 2026-06-10
**Author:** Microsoft Defender for Endpoint team

---

## What It Is

Microsoft announced on June 8, 2026 that MDE now monitors inbound remote RPC activity at
OpNum (operation number) level granularity via a new `DeviceEvents` ActionType:
`InboundRemoteRpcCall`. This closes a long-standing visibility gap — RPC has been one of the
most abused lateral movement, credential theft, and privilege escalation vectors in Windows
environments, but monitoring it at the network level was expensive and defeated by SMB3
transport encryption.

**How it works:** MDE's existing Windows Filtering Platform (WFP) integration was extended
to capture RPC calls at the interface UUID and OpNum level — giving defenders visibility into
*which specific operation* was called on *which RPC interface*, rather than just seeing that
an RPC connection was made.

---

## Attack Techniques Now Detectable

| Technique | RPC Interface | OpNums | Notes |
|-----------|--------------|--------|-------|
| Lateral movement — remote service creation | `367abb81-9844-35f1-ad32-98f038001003` (svcctl) | 12, 24, 44, 45, 60 | RCreateServiceW/A, WOW64 variants |
| Credential theft — LSA secrets / registry dump | `338cd001-2244-31f1-aaaa-900038001003` (winreg) | 20, 31 | BaseRegSaveKey / BaseRegSaveKeyEx — used by Impacket SecretsDump |
| Credential theft — DCsync | MS-DRSR replication interface | various | AD replication RPC abused to extract credential material |
| Authentication coercion | Various benign interfaces | various | Forces servers to authenticate to attacker |
| Discovery — session/share enumeration | srvsvc | various | SharpHound and similar recon tools |

---

## New ActionType in DeviceEvents

```kql
// New ActionType: InboundRemoteRpcCall
// AdditionalFields contains: RpcInterfaceUuid, RpcOpNum

// Example 1 -- Remote service creation (lateral movement indicator)
let remoteServicesInterface = '367abb81-9844-35f1-ad32-98f038001003';
let serviceCreationOpnums = dynamic([12, 24, 44, 45, 60]);
DeviceEvents
| where ActionType == 'InboundRemoteRpcCall'
| extend RpcInterface = tostring(parse_json(AdditionalFields).RpcInterfaceUuid)
| extend OpNum = toint(parse_json(AdditionalFields).RpcOpNum)
| where RpcInterface == remoteServicesInterface
| where OpNum in (serviceCreationOpnums)
| project Timestamp, DeviceName, RemoteIP, RpcInterface, OpNum

// Example 2 -- Remote registry key save (credential dumping indicator)
let remoteRegistryInterface = '338cd001-2244-31f1-aaaa-900038001003';
let credDumpOpnums = dynamic([20, 31]);
DeviceEvents
| where ActionType == 'InboundRemoteRpcCall'
| extend RpcInterface = tostring(parse_json(AdditionalFields).RpcInterfaceUuid)
| extend OpNum = toint(parse_json(AdditionalFields).RpcOpNum)
| where RpcInterface == remoteRegistryInterface
| where OpNum in (credDumpOpnums)
| project Timestamp, DeviceName, RemoteIP, RpcInterface, OpNum
```

---

## Relevance

High — directly applicable and immediately deployable. This closes the biggest gap in the
current Impacket/lateral movement detection coverage. The lt13069 incident involved a
`net user tcai` event — if the attacker used Impacket SMBExec or similar RPC-based lateral
movement tooling, this new telemetry would have surfaced it directly in `DeviceEvents`.

**Practical implications:**
- The remote registry OpNum queries (winreg interface, OpNums 20/31) are the Impacket
  SecretsDump detection — directly relevant to the AiTM BEC case and credential theft
  threat priority
- The remote service creation query is an Impacket PSExec/SMBExec detection — covers the
  primary lateral movement toolchain used by most threat actors in this environment's
  threat profile
- MDE attack disruption may now automatically interrupt these RPC-based attacks; verify
  in the Defender portal

**Note:** Server-side rollout is still ongoing per the Microsoft post — verify `InboundRemoteRpcCall`
events are appearing in your tenant before building scheduled rules on them.

---

## Actions

- [x] **Verify telemetry** — run a quick Advanced Hunting query for `ActionType == 'InboundRemoteRpcCall'` to confirm events are flowing in the tenant
- [x] **Review existing RPC-based alerts** — check the Incidents queue for any new MDE alerts tied to this new detection class
- [x] **Build KQL hunting queries** for the two high-value scenarios above (remote service creation + remote registry credential dump) once telemetry is confirmed
- [x] **Consider promoting to RULE-** once validated — both are high-fidelity, low-FP detections

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-10 | Created — MDE RPC monitoring announced June 8, 2026; new InboundRemoteRpcCall ActionType; KQL stubs included; #action-required to verify telemetry |
