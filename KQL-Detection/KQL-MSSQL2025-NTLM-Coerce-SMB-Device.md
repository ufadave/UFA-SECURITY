---
date: 2026-06-11
title: "MSSQL2025 NTLM Coercion via SMB from sqlservr"
table: "DeviceNetworkEvents"
schema: "Advanced Hunting"
mitre:
  - "T1557.001"
tactic: "Credential Access"
technique: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#endpoint"
  - "#network"
---

# KQL — MSSQL2025 NTLM Coercion via SMB from sqlservr

---

## Purpose

Detects outbound SMB (TCP/445) connections originating from `sqlservr.exe`. SQL Server 2025's `CREATE EXTERNAL MODEL` supports ONNX Runtime models loaded from UNC paths — an attacker with sysadmin access can specify an attacker-controlled UNC path to coerce NTLM authentication from the SQL Server service account over SMB. Microsoft declined to patch this, classifying it as working as intended. SQL Server does not normally make outbound SMB connections during normal operation; any such connection is suspicious regardless of SQL Server version.

---

## Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by Timestamp desc
```

---

## Validated Columns

- [ ] `InitiatingProcessFileName` — `DeviceNetworkEvents` — standard, confirmed
- [ ] `RemotePort` — `DeviceNetworkEvents` — standard, confirmed
- [ ] `RemoteIP` — `DeviceNetworkEvents` — standard, confirmed
- [ ] `RemoteUrl` — `DeviceNetworkEvents` — validate sensor version availability

---

## Test Results

<!-- Paste CSV results here after running in Advanced Hunting -->

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - sqlservr.exe Outbound SMB (NTLM Coercion via EXTERNAL MODEL)` |
| **Table** | `DeviceNetworkEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **MITRE** | T1557.001 |
| **Actions** | Alert SOC; tag entity; investigate SQL Server service account for NTLM hash exposure |
| **False Positive Risk** | Very low — sqlservr.exe making outbound SMB connections has no legitimate normal-operation use case |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- Block outbound TCP/445 from SQL Server hosts at perimeter and host-based firewall
- Verify SQL Server service account is not a domain admin — limit blast radius if hash is captured and cracked

---

## Related Notes

- [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]]
- [[KQL-MSSQL2025-AI-Outbound-HTTPS-C2-Device]]
- [[KQL-MSSQL2025-xp-cmdshell-Spawn-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]] |
