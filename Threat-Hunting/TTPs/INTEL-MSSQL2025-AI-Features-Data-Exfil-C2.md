---
title: "SpecterOps — Abusing AI Features in SQL Server 2025 for Exfil and C2"
date: 2026-06-11
source: "https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/"
author: "Justin Kalnasy — SpecterOps"
type: intel
severity: High
cve: ""
cvss: ""
detection_candidate: true
mitre:
  - "T1048.003"
  - "T1071.001"
  - "T1557.001"
  - "T1059.007"
  - "T1543.003"
tags:
  - "#intel"
  - "#cloud"
  - "#endpoint"
  - "#network"
  - "#status/draft"
---

# INTEL — SpecterOps: Abusing AI Features in SQL Server 2025 for Exfil and C2

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/ |
| **Published** | 2026-06-10 |
| **Author** | Justin Kalnasy — SpecterOps |
| **PoC Repo** | https://github.com/gershsec/mssql2025-poc |
| **Type** | Offensive Research / Proof-of-Concept |

---

## MITRE ATT&CK

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols (HTTPS) |
| Credential Access | T1557.001 | NTLM Relay via SMB coercion (UNC path in EXTERNAL MODEL) |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript / T-SQL |
| Persistence | T1543.003 | Trigger-based persistence via SQL TRIGGER + REST exfil |

---

## Summary

SQL Server 2025 introduced three native AI features — `sp_invoke_external_rest_endpoint`, `CREATE EXTERNAL MODEL`, and `AI_GENERATE_EMBEDDINGS` — that, when combined with existing MSSQL primitives, create a practical data exfiltration and C2 channel running entirely within the database engine under HTTPS. SpecterOps researcher Justin Kalnasy demonstrated four attack chains: bulk table exfiltration (up to 100MB per request), file exfiltration via `OPENROWSET`, persistent trigger-based credential harvesting, and a full CLR-based C2 agent that encodes commands as AI embedding vectors to blend with legitimate model traffic. An additional primitive coerces NTLM auth over SMB by specifying UNC paths in `EXTERNAL MODEL` — Microsoft declined to patch this, classifying it as working as intended.

The core shift in risk posture is that outbound HTTPS from a SQL Server engine, historically a reliable indicator of compromise, now has a legitimate feature driving it. Security tooling and analyst assumptions built around "egress from DB = bad" will need to adapt. The CLR C2 agent in particular is operationally significant: it loads in-memory from hex bytes (no disk drop), uses `context connection=true` to reuse the existing SQL session, and traffic closely mimics real qwen3-embedding API calls.

---

## Relevance to Environment

**Medium.** SQL Server 2025 is not yet confirmed deployed in the environment — assess current SQL Server version inventory before treating as an immediate operational risk. However, the trajectory is clear: SQL Server 2025 GA'd November 2025 and is on the upgrade path for any organization running modern Windows infrastructure. Key factors:

- If any SQL Server instance is upgraded to 2025, `sp_invoke_external_rest_endpoint` is disabled by default but trivial to enable (`sp_configure` — one line, requires sysadmin)
- The NTLM coercion primitive via UNC paths in `CREATE EXTERNAL MODEL` applies immediately upon upgrade; no additional enablement required
- Any foothold on a sysadmin SQL account — common in environments with legacy web apps or misconfigured service accounts — is sufficient to weaponize all three features
- The 100MB exfiltration payload limit and HTTPS transport make this an attractive post-exploitation channel that bypasses most DLP tools focused on volume or protocol
- OT jump hosts or internal management servers running SQL Server for plant historian or SCADA-adjacent data should be included in version audit scope

**Immediate action:** Audit SQL Server versions across the estate. If SQL Server 2025 is present, validate that `external rest endpoint enabled` is off and that CLR is either disabled or `clr strict security` is set to 1.

---

## Detection Notes

`detection_candidate: true`

> **Note:** All three detection approaches require SQL Server Audit or Extended Events with SQL text logging configured. Native SQL Server error logs do not reliably capture statement-level telemetry for these features. Queries below are written for environments where SQL audit data flows into Sentinel via a Log Analytics agent or Microsoft Defender for SQL.

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound HTTPS connections from sqlservr.exe to non-corporate destinations — primary exfil/C2 channel for sp_invoke_external_rest_endpoint abuse
// MITRE: T1048.003, T1071.001

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
// Exclude RFC1918 — adjust to include any known internal model/AI infrastructure IPs
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

> ⚠️ **Schema note:** Validate `RemoteUrl` availability. If SQL Server 2025 AI features are legitimately in use pointing to internal model infrastructure, add those IPs/hostnames to the exclusion list.

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound SMB (TCP/445) from sqlservr.exe — NTLM coercion via UNC path in CREATE EXTERNAL MODEL
// MITRE: T1557.001

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by Timestamp desc
```

> This covers the NTLM coercion primitive. Any SMB connection originating from `sqlservr.exe` to an external host is suspicious — the ONNX Runtime path resolution that drives this does not need to reach across the network in normal operation.

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect xp_cmdshell or cmd.exe spawned by sqlservr.exe — execution primitive used in simple C2 variant
// MITRE: T1059

DeviceProcessEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    ProcessIntegrityLevel
| order by Timestamp desc
```

---

### Validated Columns

- [ ] `InitiatingProcessFileName` — `DeviceNetworkEvents` / `DeviceProcessEvents` — standard, confirmed
- [ ] `RemotePort` — `DeviceNetworkEvents` — standard, confirmed
- [ ] `RemoteUrl` — `DeviceNetworkEvents` — validate sensor version availability
- [ ] `ProcessIntegrityLevel` — `DeviceProcessEvents` — validate in tenant schema

---

## Hardening Actions

- [ ] **Audit SQL Server version inventory** — identify any instances at version 2025; prioritise external-facing or management-plane servers
- [ ] **Verify `external rest endpoint enabled = 0`** on all SQL Server 2025 instances — this is off by default but a single `sp_configure` call enables it
- [ ] **Set `clr strict security = 1`** on all SQL Server instances — prevents unsigned CLR assemblies; blocks in-memory CLR C2 agent loading
- [ ] **Disable `clr enabled`** on any SQL Server instance that does not require CLR
- [ ] **Audit sysadmin role membership** — all three attack chains require sysadmin; remove from web app connection strings and service accounts where not needed
- [ ] **Block outbound HTTPS from SQL Server service account** at perimeter/host firewall — if AI features are not in use, `sqlservr.exe` should not be making outbound HTTPS connections
- [ ] **Block outbound SMB from SQL Server hosts** at perimeter — closes the NTLM coercion via UNC path primitive
- [ ] **Watchlist `sys.external_models` DDL events** in SQL Server Audit — alert on `CREATE EXTERNAL MODEL` DDL statements if Extended Events or SQL Audit is configured

---

## Related Notes

- [[KQL-MSSQL2025-AI-Outbound-HTTPS-C2-Device]]
- [[KQL-MSSQL2025-NTLM-Coerce-SMB-Device]]
- [[KQL-MSSQL2025-xp-cmdshell-Spawn-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — SpecterOps research by Justin Kalnasy, published 2026-06-10 |
