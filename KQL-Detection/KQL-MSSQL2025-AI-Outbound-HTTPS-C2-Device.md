---
date: 2026-06-11
title: "MSSQL2025 AI Outbound HTTPS C2 Detection"
table: "DeviceNetworkEvents"
schema: "Advanced Hunting"
mitre:
  - "T1048.003"
  - "T1071.001"
tactic: "Exfiltration / Command and Control"
technique: "Exfiltration Over Unencrypted Protocol / Application Layer Protocol: Web Protocols"
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

# KQL — MSSQL2025 AI Outbound HTTPS C2 Detection

---

## Purpose

Detects outbound HTTPS (TCP/443) connections from `sqlservr.exe` to non-RFC1918 destinations. SQL Server 2025 introduced `sp_invoke_external_rest_endpoint` which enables the database engine to make arbitrary HTTPS REST calls — this is the transport channel for data exfiltration and C2 in SpecterOps's proof-of-concept. In environments not using SQL Server 2025 AI features, any external HTTPS from `sqlservr.exe` is anomalous. In environments using the features legitimately (internal model hosting), the exclusion list should be extended to cover internal model infrastructure IPs.

---

## Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
| where not (RemoteIP startswith "10.")
| where not (RemoteIP startswith "192.168.")
| where not (
    RemoteIP startswith "172.16." or RemoteIP startswith "172.17." or
    RemoteIP startswith "172.18." or RemoteIP startswith "172.19." or
    RemoteIP startswith "172.20." or RemoteIP startswith "172.21." or
    RemoteIP startswith "172.22." or RemoteIP startswith "172.23." or
    RemoteIP startswith "172.24." or RemoteIP startswith "172.25." or
    RemoteIP startswith "172.26." or RemoteIP startswith "172.27." or
    RemoteIP startswith "172.28." or RemoteIP startswith "172.29." or
    RemoteIP startswith "172.30." or RemoteIP startswith "172.31."
)
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
- [ ] `InitiatingProcessCommandLine` — `DeviceNetworkEvents` — validate availability

---

## Test Results

<!-- Paste CSV results here after running in Advanced Hunting -->

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - sqlservr.exe Outbound HTTPS to External Host` |
| **Table** | `DeviceNetworkEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **MITRE** | T1048.003, T1071.001 |
| **Actions** | Alert SOC; tag entity |
| **False Positive Risk** | Low if SQL Server 2025 AI features are not enabled; Medium if legitimately in use — extend exclusions to cover known model endpoints |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- Block outbound HTTPS from `sqlservr.exe` at host firewall (Intune/GPO Windows Firewall rule) if AI features are not in use
- Set `external rest endpoint enabled = 0` via `sp_configure`

---

## Related Notes

- [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]]
- [[KQL-MSSQL2025-NTLM-Coerce-SMB-Device]]
- [[KQL-MSSQL2025-xp-cmdshell-Spawn-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]] |
