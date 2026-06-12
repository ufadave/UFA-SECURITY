---
title: "Microsoft Defender Now Monitors RPC Activity"
date: 2026-06-11
source: "https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/microsoft-defender-now-monitors-rpc-activity/4523368"
author: "Microsoft Defender for Endpoint Team"
type: info
tags:
  - "#resource"
  - "#endpoint"
  - "#network"
  - "#identity"
  - "#status/draft"
---

# INFO — Microsoft Defender Now Monitors RPC Activity

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/microsoft-defender-now-monitors-rpc-activity/4523368 |
| **Published** | 2026-06-08 (updated 2026-06-09) |
| **Author** | Microsoft Defender for Endpoint Blog |

---

## What It Is

Microsoft has added native RPC monitoring to Defender for Endpoint. Rather than network-level inspection (which is blocked by SMB3 encryption and carries performance overhead), telemetry is collected directly on the endpoint via audit-only WFP filters. The capability covers inbound remote RPC calls only — local inter-process communication and outbound RPC are excluded.

Monitored interfaces include Remote Registry, Service Control Manager, Task Scheduler, and WMI. Visibility is at the operation level (OpNum), meaning analysts can see which specific RPC functions are being invoked, not just that an RPC interface was touched. Telemetry surfaces in Advanced Hunting via the `InboundRemoteRpcCall` action type in `DeviceEvents`.

Built-in detections shipping with this update include:

- Hands-on-keyboard attacks via Impacket toolkit
- Suspicious remote service creation (lateral movement)
- LSA secrets extraction (credential theft via Remote Registry)
- Unusual account and session enumeration
- Authentication coercion attacks

**Availability:** Generally available for workstations; gradual rollout underway for servers.

---

## Relevance to Environment

**High.** This directly addresses one of the most commonly exploited lateral movement vectors — remote service creation, Impacket-based attacks, and credential dumping via Remote Registry. The environment has ~150 Windows endpoints and a hybrid AD that is an attractive target for lateral movement. Key hunting queries to build immediately:

- Remote registry saves (OpNums 20 and 31 on interface `338cd001-2244-31f1-aaaa-900038001003`) — indicative of `secretsdump`-style credential dumping
- Remote service creation (OpNums 12, 24, 44, 45, 60 on interface `367abb81-9844-35f1-ad32-98f038001003`) — lateral movement via SCM

---

## Actions

- [ ] **Verify `InboundRemoteRpcCall` is populating in `DeviceEvents`** — query the table for the action type and confirm telemetry is flowing for workstations
- [ ] **Build hunting queries** for Remote Registry credential dump and remote service creation OpNums — these are the highest-value starting points
- [ ] **Check server rollout status** — confirm whether any server-class devices in the estate have received the capability yet; DC and management servers are highest priority

---

## KQL Starting Point

```kql
// Table: DeviceEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Surface InboundRemoteRpcCall telemetry — validate data availability and review for suspicious RPC operations

DeviceEvents
| where ActionType == "InboundRemoteRpcCall"
| extend RpcDetails = parse_json(AdditionalFields)
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    ActionType,
    RpcDetails
| order by Timestamp desc
| take 100
```

> ⚠️ **Schema note:** `AdditionalFields` structure for `InboundRemoteRpcCall` requires validation — field names for interface UUID, OpNum, and procedure name may vary. Run the above first to inspect the raw JSON before building targeted detections.

---

## Related Notes

- [[HUNT-GapAnalysis-T1078-T1569-T1105]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — Microsoft announcement 2026-06-08 |
