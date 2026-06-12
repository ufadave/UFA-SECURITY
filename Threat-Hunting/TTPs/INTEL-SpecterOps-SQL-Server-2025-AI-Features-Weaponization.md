---
title: INTEL-SpecterOps-SQL-Server-2025-AI-Features-Weaponization
date: 2026-06-12
source: "https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/"
author: "SpecterOps"
mitre:
  - "T1505.001"
  - "T1071.001"
  - "T1567"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#network"
  - "#cloud"
---

# INTEL -- SpecterOps: Abusing AI Features in SQL Server 2025

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/ |
| **Author** | SpecterOps |
| **Date Observed** | 2026-06-12 |
| **Date Published** | 2026-06-10 |
| **Affects** | SQL Server 2025 (17.x) and Azure SQL Database / Managed Instance with SQL Server 2025 AI features enabled |
| **Patch Available** | N/A -- design-level abuse of legitimate features, not a CVE |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1505.001 | Server Software Component: SQL Stored Procedures |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1567 | Exfiltration Over Web Service |

---

## Summary

SpecterOps demonstrates that the native AI features introduced in SQL Server 2025 -- vector
data types, embedding generation, and especially the ability to register and call external
AI model endpoints directly from T-SQL -- create a built-in channel for data exfiltration
and command-and-control (C2) that operates entirely within the database engine.

**The enabling primitives:**

- **`CREATE EXTERNAL MODEL`** -- registers an external AI model object containing the
  location, authentication method, and purpose of an AI model inference endpoint. This
  endpoint can be ANY REST API, not just Azure OpenAI -- attacker-controlled infrastructure
  can be registered as a "model."
- **`sp_invoke_external_rest_endpoint`** -- a new system stored procedure enabling native
  REST API calls from T-SQL. This is the core abuse primitive: any T-SQL caller with
  sufficient privilege can make outbound HTTPS calls to arbitrary endpoints directly from
  the database server.
- **`AI_GENERATE_EMBEDDINGS`** and related embedding functions -- legitimately send data to
  external endpoints for vectorization. The same code path can be repurposed to package
  and transmit arbitrary database content to an attacker endpoint disguised as an
  "embedding generation" request.

**Why this matters operationally:**

1. **Traffic blends in.** Outbound calls from a SQL Server to an HTTPS endpoint for "AI
   model inference" is now a legitimate, expected pattern in SQL Server 2025 environments.
   A C2 channel disguised as embedding generation traffic would not stand out to network
   monitoring that has been tuned to expect AI-related egress.
2. **No new binary, no new process.** The abuse happens entirely through `sqlservr.exe`
   making outbound network connections -- no dropped files, no child process spawning that
   traditional endpoint detection would flag.
3. **Privilege requirement is the gate.** `CREATE EXTERNAL MODEL` and
   `sp_invoke_external_rest_endpoint` require elevated database permissions (typically
   `CONTROL DATABASE` or higher, or specific server-level permissions depending on
   configuration). This makes it primarily a post-compromise persistence/exfiltration
   technique for an attacker who has already achieved DBA-level access, or an insider
   threat scenario -- not a remote unauthenticated attack vector.
4. **Credential/endpoint storage.** `CREATE EXTERNAL MODEL` stores authentication details
   for the external endpoint -- if an attacker can read these definitions, registered
   credentials for legitimate AI services could also be harvested.

---

## Relevance to Environment

**Currently low-to-no direct exposure** -- the environment's SQL Server estate (if any)
would need to be on SQL Server 2025 (17.x) with AI features enabled and
`PREVIEW_FEATURES` database scoped configuration turned on for the full vector/embedding
feature set, or have `sp_invoke_external_rest_endpoint` available (general availability
timing for this proc specifically should be confirmed).

**Worth assessing:**
1. Is any SQL Server instance in the environment running version 2025 (17.x)?
2. If so, are AI features (`CREATE EXTERNAL MODEL`, `sp_invoke_external_rest_endpoint`,
   vector functions) enabled?
3. Who holds `CONTROL DATABASE` or equivalent elevated permissions on those instances?

**Forward-looking relevance:** Given the active AI Acceptable Use Policy work and the
broader pattern of AI features being embedded directly into core infrastructure (M365
Copilot, ChatGPT connectors, Codex, now SQL Server), this represents a new category of
attack surface that will recur as more platforms add native AI/agentic capabilities. The
general principle -- AI feature integrations create new outbound network paths that blend
with legitimate traffic -- applies beyond SQL Server specifically.

---

## Detection Notes

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Surface outbound HTTPS connections initiated by sqlservr.exe to
// non-Microsoft/non-Azure destinations -- potential abuse of sp_invoke_external_rest_endpoint
// or CREATE EXTERNAL MODEL pointing at attacker infrastructure.
// NOTE: Legitimate use (Azure OpenAI, Microsoft Foundry) will generate baseline noise --
// exclusion list for known-good AI endpoint domains required before deployment.

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where RemotePort in (443, 80)
| where RemoteUrl !has_any (
    "openai.azure.com", "azure.com", "microsoft.com",
    "windows.net", "core.windows.net"
)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```sql
-- Run directly against SQL Server -- audit registered external models
-- Purpose: Enumerate any CREATE EXTERNAL MODEL definitions and their endpoints
SELECT
    name,
    create_date,
    modify_date,
    location -- endpoint URL
FROM sys.external_models
ORDER BY create_date DESC;

-- Audit who has permission to invoke external REST endpoints
SELECT
    pr.name AS principal_name,
    pr.type_desc,
    perm.permission_name,
    perm.state_desc
FROM sys.database_permissions perm
JOIN sys.database_principals pr ON perm.grantee_principal_id = pr.principal_id
WHERE perm.permission_name LIKE '%EXTERNAL%'
   OR perm.permission_name LIKE '%CONTROL%';
```

### Validated Columns
- [ ] `InitiatingProcessFileName =~ "sqlservr.exe"` -- confirm DeviceNetworkEvents captures SQL Server process network activity in this environment
- [ ] Confirm whether any SQL Server 2025 instances exist in the environment before deploying

---

## Hardening Actions

- [ ] **Inventory SQL Server versions** -- identify any instances running SQL Server 2025 (17.x)
- [ ] **If SQL Server 2025 present:** audit `sys.external_models` for unexpected registrations
- [ ] **Restrict `CREATE EXTERNAL MODEL` and `sp_invoke_external_rest_endpoint` permissions** to a minimal set of DBA accounts -- treat as a privileged capability equivalent to `xp_cmdshell`
- [ ] **Network egress filtering for SQL Server hosts** -- if SQL Server 2025 AI features are in use, restrict outbound HTTPS to known Azure OpenAI / Microsoft Foundry endpoints only
- [ ] Consider this pattern when evaluating future platform AI feature rollouts (Copilot, agentic integrations) -- "AI features create new outbound network paths" is a recurring theme

---

## Related Notes
- [[INFO-MDE-RPC-Activity-Monitoring-InboundRemoteRpcCall-2026-06]]
- [[RESEARCH-AI-Coding-Tools-and-M365-Integration-Security-Summary]]
- [[INFO-NSA-MCP-Security-Design-Considerations-May-2026]]
- [[RULE-SQLServer-Anomalous-External-REST-Connection]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-12 | Created -- SpecterOps SQL Server 2025 AI feature abuse; 1 network detection stub + SQL audit queries; assess for SQL Server 2025 presence in environment |
