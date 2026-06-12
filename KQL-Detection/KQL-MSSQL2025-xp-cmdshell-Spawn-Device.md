---
date: 2026-06-11
title: "MSSQL2025 xp_cmdshell Shell Spawn from sqlservr"
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1059"
tactic: "Execution"
technique: "Command and Scripting Interpreter"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#endpoint"
---

# KQL — MSSQL2025 xp_cmdshell Shell Spawn from sqlservr

---

## Purpose

Detects `cmd.exe` or PowerShell spawned by `sqlservr.exe` — the execution primitive used in the simple C2 variant of the SQL Server 2025 AI feature abuse chain. While `xp_cmdshell` is the most common driver (requires explicit enablement), any shell child process of `sqlservr.exe` is anomalous and warrants investigation regardless of whether SQL Server 2025 AI features are involved. This is a broadly applicable detection that covers `xp_cmdshell` abuse across all SQL Server versions.

---

## Query

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessIntegrityLevel
| order by Timestamp desc
```

---

## Validated Columns

- [ ] `InitiatingProcessFileName` — `DeviceProcessEvents` — standard, confirmed
- [ ] `FileName` — `DeviceProcessEvents` — standard, confirmed
- [ ] `ProcessCommandLine` — `DeviceProcessEvents` — standard, confirmed
- [ ] `InitiatingProcessCommandLine` — `DeviceProcessEvents` — standard, confirmed
- [ ] `ProcessIntegrityLevel` — `DeviceProcessEvents` — validate in tenant schema

---

## Test Results

<!-- Paste CSV results here after running in Advanced Hunting -->

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - sqlservr.exe Spawning Shell Process (xp_cmdshell / C2)` |
| **Table** | `DeviceProcessEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **MITRE** | T1059 — Command and Scripting Interpreter |
| **Actions** | Alert SOC; isolate if combined with outbound HTTPS or SMB alert on same device |
| **False Positive Risk** | Low — SQL Server does not legitimately spawn interactive shells; any hit warrants investigation |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceProcessEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- Disable `xp_cmdshell` via `sp_configure` if not required (most environments do not need it)
- Set `clr strict security = 1` to block unsigned CLR assemblies (the more advanced CLR C2 agent variant)

---

## Related Notes

- [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]]
- [[KQL-MSSQL2025-AI-Outbound-HTTPS-C2-Device]]
- [[KQL-MSSQL2025-NTLM-Coerce-SMB-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-MSSQL2025-AI-Features-Data-Exfil-C2]] |
