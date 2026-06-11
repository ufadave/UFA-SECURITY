---
date: 2026-06-10
title: MDE RPC Remote Registry Credential Dump Device
table: "DeviceEvents"
schema: "Advanced Hunting"
mitre: "T1003.002"
tactic: "Credential Access"
technique: "OS Credential Dumping: Security Account Manager"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#endpoint"
  - "#identity"
---

# KQL -- MDE RPC Remote Registry Credential Dump Device

---

**Table:** DeviceEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1003.002 | **Tactic:** Credential Access | **Technique:** OS Credential Dumping: Security Account Manager
**Created:** 2026-06-10 | **Status:** Draft

---

## Purpose

Detects inbound remote RPC calls to the Windows Remote Registry (winreg) interface using
opcodes associated with registry key save operations. This covers the Impacket SecretsDump
pattern -- remotely saving the SAM and SYSTEM registry hives to extract credential material
(NTLM hashes, LSA secrets) without writing to disk on the target.

Leverages the new `InboundRemoteRpcCall` ActionType introduced in MDE on June 8, 2026.

**Signal:** Remote registry key save (BaseRegSaveKey / BaseRegSaveKeyEx) is a high-confidence
credential theft indicator. Legitimate remote registry saves outside of backup tooling are
very rare. Combined with the source IP being a non-management workstation, this is near-certain
malicious activity.

**Relationship to current incidents:** This detection would have surfaced Impacket SecretsDump
activity in the AiTM BEC investigation if the attacker used RPC-based credential extraction.

**Source note:** `[[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]`

---

## Query

```kql
// winreg interface UUID -- Windows Remote Registry
let remoteRegistryInterface = '338cd001-2244-31f1-aaaa-900038001003';
// OpNums: BaseRegSaveKey=20, BaseRegSaveKeyEx=31
let credDumpOpnums = dynamic([20, 31]);
DeviceEvents
| where Timestamp > ago(1d)
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

- [ ] `ActionType == 'InboundRemoteRpcCall'` -- **verify telemetry is flowing in tenant first** (server-side rollout still in progress as of June 8, 2026)
- [ ] `parse_json(AdditionalFields).RpcInterfaceUuid` -- confirm field name in this tenant
- [ ] `parse_json(AdditionalFields).RpcOpNum` -- confirm field name and type
- [ ] `parse_json(AdditionalFields).RemoteIP` -- confirm field name populated

---

## Test Results

> Pending -- verify `InboundRemoteRpcCall` events are appearing in Advanced Hunting before validating.
> Run: `DeviceEvents | where ActionType == 'InboundRemoteRpcCall' | take 10` to confirm telemetry.

---

## Deployment

<!-- Default path: MDE Custom Detection (DeviceEvents is Advanced Hunting only) -->
<!-- Sentinel section inactive: DeviceEvents not ingested into Log Analytics -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - RPC Remote Registry Credential Dump`
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only (investigate immediately -- near-zero FP rate outside backup tooling)
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceEvents is Advanced Hunting only -- not ingested into Log Analytics -->

---

## Hardening Control Pair
- **Control:** [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]
- [[KQL-MDE-RPC-Remote-Service-Creation-Lateral-Movement-Device]]
- [[RULE-MDE-RPC-Remote-Registry-Credential-Dump-Device]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-10 | Created -- companion to INFO-MDE-RPC note; winreg BaseRegSaveKey/Ex opcodes; Impacket SecretsDump pattern; pending telemetry verification |
