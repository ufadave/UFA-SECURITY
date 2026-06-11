---
date: 2026-06-10
title: MDE RPC Remote Registry Credential Dump Device
table: "DeviceEvents"
schema: "Advanced Hunting"
mitre: "T1003.002"
tactic: "Credential Access"
technique: "OS Credential Dumping: Security Account Manager"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - RPC Remote Registry Credential Dump"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
  - "#identity"
---

# RULE -- MDE RPC Remote Registry Credential Dump Device

---

**Table:** DeviceEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1003.002 | **Tactic:** Credential Access | **Technique:** OS Credential Dumping: Security Account Manager
**Created:** 2026-06-10 | **Status:** Validated

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-10 |
| **Deployed To** | MDE Custom Detection |
| **Rule Name** | Custom - RPC Remote Registry Credential Dump |
| **Rule ID** | <!-- Populate mde_rule_name in frontmatter when deployed in portal --> |

---

## Purpose

Detects inbound remote RPC calls to the Windows Remote Registry (winreg) interface using
opcodes associated with registry key save operations. This covers the Impacket SecretsDump
pattern -- remotely saving the SAM and SYSTEM registry hives to extract credential material
(NTLM hashes, LSA secrets) without writing to disk on the target.

Leverages the `InboundRemoteRpcCall` ActionType introduced in MDE on June 8, 2026, which
provides OpNum-level visibility into RPC operations.

**Signal:** Remote registry key save (BaseRegSaveKey / BaseRegSaveKeyEx) is a high-confidence
credential theft indicator. Legitimate remote registry saves outside of backup tooling are
very rare. Near-zero FP rate.

**Triage checklist:**
1. Is the RemoteIP a known IT management server, backup system, or SCCM/RMM host?
2. Was a scheduled backup or maintenance window active at the time?
3. Is the target DeviceName a domain controller or server with credential stores?

If none of the above — treat as active credential theft attempt and escalate immediately.

---

## Query

```kql
// winreg interface UUID -- Windows Remote Registry
let remoteRegistryInterface = '338cd001-2244-31f1-aaaa-900038001003';
// OpNums: BaseRegSaveKey=20, BaseRegSaveKeyEx=31
let credDumpOpnums = dynamic([20, 31]);
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == 'InboundRemoteRpcCall'
| extend RpcInterface = tostring(parse_json(AdditionalFields).RpcInterfaceUuid)
| extend OpNum = toint(parse_json(AdditionalFields).RpcOpNum)
| where RpcInterface =~ remoteRegistryInterface
| where OpNum in (credDumpOpnums)
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
| Disposition | Clean baseline — no remote registry credential dump activity detected |
| Telemetry confirmed | Yes — InboundRemoteRpcCall events confirmed flowing in tenant |

---

## Deployment

<!-- INACTIVE: Sentinel Analytics Rule -- DeviceEvents is Advanced Hunting only -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - RPC Remote Registry Credential Dump`
- **Frequency:** Every 1h
- **Lookback:** 4h
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [ X]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- **Linked:** [ ]

---

## Related Notes
- [[KQL-MDE-RPC-Remote-Registry-Credential-Dump-Device]] -- source KQL note
- [[RULE-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]]
- [[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-10 | Created -- promoted from KQL note; 7-day clean baseline; telemetry confirmed |
