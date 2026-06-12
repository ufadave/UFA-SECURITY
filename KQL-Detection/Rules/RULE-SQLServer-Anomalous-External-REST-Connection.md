---
date: 2026-06-12
title: SQL Server Anomalous External REST Connection
table: "DeviceNetworkEvents"
schema: "Advanced Hunting"
mitre: "T1071.001"
tactic: "Command and Control, Exfiltration"
technique: "Application Layer Protocol: Web Protocols"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - SQL Server Anomalous External REST Connection"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#network"
  - "#cloud"
---

# RULE -- SQL Server Anomalous External REST Connection

---

**Table:** DeviceNetworkEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1071.001 | **Tactic:** Command and Control, Exfiltration | **Technique:** Application Layer Protocol: Web Protocols
**Created:** 2026-06-12 | **Status:** Validated

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-12 |
| **Deployed To** | MDE Custom Detection |
| **Rule Name** | Custom - SQL Server Anomalous External REST Connection |
| **Rule ID** | <!-- Populate mde_rule_name in frontmatter when deployed in portal --> |

---

## Purpose

Detects `sqlservr.exe` initiating outbound HTTPS/HTTP connections to destinations outside
known Microsoft/Azure infrastructure. SQL Server has no legitimate reason to make arbitrary
outbound web requests under normal operation -- any such connection is anomalous and
warrants investigation.

**Origin:** Sparked by SpecterOps research (`[[INTEL-SpecterOps-SQL-Server-2025-AI-Features-Weaponization]]`)
on SQL Server 2025's `CREATE EXTERNAL MODEL` / `sp_invoke_external_rest_endpoint` AI features
being abusable as a C2/exfiltration channel. **The environment does not run SQL Server 2025**
(confirmed 2026-06-12) -- however the underlying behavioural pattern (database engine making
outbound REST calls to non-Microsoft infrastructure) is a recognised anomaly class regardless
of version, and corresponds to Microsoft Defender for Cloud's built-in alert
`SQL.VM_ShellExternalSourceAnomaly` ("SQL Server potentially spawned a Windows command shell
and accessed an abnormal external source").

**Other relevant scenarios this also covers:**
- Misconfigured or malicious linked server pointing at external infrastructure
- `xp_cmdshell`-based exfiltration (if enabled) spawning a process that reaches out externally
- A future SQL Server 2025 upgrade where AI features are abused per the SpecterOps pattern
- Compromised SQL service account credentials used to stage outbound C2 from a DB host



---

## Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort in (443, 80)
// Exclude Azure Instance Metadata Service (benign, IMDS link-local address)
| where RemoteIP != "169.254.169.254"
| where not (RemoteUrl has_any
    "openai.azure.com", "azure.com", "microsoft.com",
    "windows.net", "core.windows.net"
))
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Validated Columns

- [x] `InitiatingProcessFileName =~ "sqlservr.exe"` -- confirmed populated, 4 SQL hosts identified (ufadb206-a, ufadb506-a/b/c, erp-bld7-1)
- [x] `RemoteIP` -- confirmed populated
- [x] `RemoteUrl` -- confirmed empty for IMDS (raw-IP) connections; populated for URL-based connections
- [x] `RemotePort` -- confirmed populated

---

## Test Results

**7-day validation -- 2026-06-05 to 2026-06-12**

| Result | Detail |
|--------|--------|
| Total events (pre-tuning) | 25 |
| Disposition | All 25 events were Azure IMDS (169.254.169.254) from svc-ufadb506-mssql, svc-ufadb206-mssql, and network service -- benign, expected Azure VM managed identity/metadata queries |
| Post-tuning | IMDS exclusion added (`RemoteIP != "169.254.169.254"`) -- expect 0 events on next run unless genuinely anomalous |
| SQL Server 2025 confirmed absent | Confirmed via sysadmin 2026-06-12; `DeviceTvmSoftwareInventory` query also returned no SQL Server 2025 instances |

**SQL hosts identified during validation:** ufadb206-a, ufadb506-a, ufadb506-b, ufadb506-c
(all `.ad.corp.local`), erp-bld7-1.

---

## Deployment

<!-- INACTIVE: Sentinel Analytics Rule -- DeviceNetworkEvents is Advanced Hunting only -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - SQL Server Anomalous External REST Connection`
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** Medium
- **Actions:** Collect investigation package
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

**Response action rationale:** Collect investigation package -- consistent with the recently
adopted approach for newly-deployed, broad-pattern detections (see
`[[RULE-Encoded-PowerShell-Commands-With-Web-Request-Tuned]]`). Gathers forensic context
without disrupting a production database server. Revisit toward isolation only if repeated
true positives are confirmed -- isolating a production SQL Server has significant
availability impact and should not be an automatic first response.

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-SpecterOps-SQL-Server-2025-AI-Features-Weaponization]] -- source INTEL note
- [[RULE-Encoded-PowerShell-Commands-With-Web-Request-Tuned]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-12 | Created -- promoted from SpecterOps SQL Server 2025 AI abuse research. SQL Server 2025 confirmed not in use, but underlying anomaly pattern (sqlservr.exe -> external REST) retained as general-purpose detection. IMDS exclusion added after 7-day validation showed 25 benign IMDS events. Aligns with Defender for Cloud's SQL.VM_ShellExternalSourceAnomaly alert class. |
