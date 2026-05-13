---
title: FIND-Mini-Shai-Hulud-TanStack-Exposure-Assessment-2026-05-12
date: 2026-05-12
case_id:
alert_id:
severity: High
status: open
tags:
  - "#ir"
  - "#finding"
  - "#status/active"
  - "#supply-chain"
  - "#endpoint"
  - "#cloud"
---

# FIND — Mini Shai-Hulud TanStack Exposure Assessment (2026-05-12)

**Date:** 2026-05-12
**Analyst:** Dave
**Severity:** High
**Status:** Open

---

## Source

| Field | Value |
|-------|-------|
| **Alert / Signal** | Threat intel — INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321 |
| **Platform** | MDE / Advanced Hunting — proactive hunt |
| **Affected Asset(s)** | TBD — pending query results |
| **Affected User(s)** | TBD — pending query results |
| **Detection Time** | 2026-05-12 |
| **Triage Time** | 2026-05-12 |

---

## Observation

On 2026-05-11 between 19:20–19:26 UTC, TeamPCP published 84 malicious versions across 42 @tanstack/* npm packages as part of the Mini Shai-Hulud supply chain worm campaign (CVE-2026-45321, CVSS 9.6). The malicious packages install a credential-stealing payload (`router_init.js`, SHA256: `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`) via the npm prepare lifecycle hook at install time, stealing GitHub tokens, cloud credentials, npm tokens, and SSH keys. The worm self-propagates by using stolen OIDC tokens to publish compromised versions of victim packages.

This finding documents a proactive exposure assessment to determine whether any host in the environment installed an affected @tanstack/* package version during the compromise window (2026-05-11T19:20Z onwards).

---

## Investigation Notes

### Hypothesis

The primary endpoint estate is Windows-based with no known Node.js development workloads. Direct exposure is assessed as low. However, any developer machines running the ChatGPT/Codex M365 POC, Azure DevOps/GitHub Actions CI/CD pipelines, or Linux-based tooling hosts (OT assessment boxes) may have npm in the dependency chain.

### KQL Pivots

**Hunt 1 — router_init.js payload on disk**

```kql
// SHA256: ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
DeviceFileEvents
| where FileName =~ "router_init.js"
    or SHA256 == "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
    SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

**Hunt 2 — C2 connectivity to Mini Shai-Hulud infrastructure**

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2026-05-11T19:00:00Z)
| where RemoteUrl has_any (
    "filev2.getsession.org",
    "api.masscan.cloud",
    "git-tanstack.com"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

**Hunt 3 — npm install execution in the compromise window**

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-05-11T19:00:00Z)
| where FileName in ("npm", "node", "npx", "pnpm", "yarn")
| where ProcessCommandLine has_any ("install", "add", "ci")
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

**Hunt 4 — npm lifecycle hook spawning suspicious child processes**

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-05-11T19:00:00Z)
| where InitiatingProcessFileName in ("node", "npm", "npx")
    and InitiatingProcessCommandLine has_any ("prepare", "postinstall", "install")
| where FileName in ("curl", "wget", "bash", "sh", "python3", "python", "cmd", "powershell")
    or ProcessCommandLine has_any ("getsession", "masscan", "git-tanstack")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

**Hunt 5 — C2 beacon string in repo commits (manual)**

Search internal GitHub/Azure DevOps repos for commits containing:
- `thebeautifulmarchoftime`
- `thebeautifulsandsoftime`

A hit confirms worm execution and C2 callback.

### Results

| Hunt | Query | Result | Date Run |
|------|-------|--------|----------|
| 1 | router_init.js / SHA256 on disk | | |
| 2 | C2 connectivity | | |
| 3 | npm install in window | | |
| 4 | Lifecycle hook child process | | |
| 5 | C2 beacon strings in repos (manual) | | |

---

## Assessment

**Verdict:** Undetermined — pending query results

Preliminary assessment is low exposure based on estate profile (Windows-primary, no known Node.js development workloads). Formal verdict pending execution of all five hunts above.

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | Initial Access / Credential Access |
| Technique | T1195.001 — Supply Chain Compromise |
| Sub-technique | T1552.001 — Credentials in Files |

---

## Actions Taken

- [x] Threat intel note created: [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]]
- [ ] Run Hunt 1 — router_init.js / SHA256
- [ ] Run Hunt 2 — C2 connectivity
- [ ] Run Hunt 3 — npm install in window
- [ ] Run Hunt 4 — lifecycle hook child process
- [ ] Run Hunt 5 — beacon strings in repos (manual)
- [ ] Confirm no Azure DevOps / GitHub Actions pipelines consume @tanstack/* packages
- [ ] Confirm no developer machines running Codex POC have npm in dependency chain
- [ ] Update Results table above with findings
- [ ] Escalate to IR case if any hunt returns a positive result

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[IR-Mini-Shai-Hulud-TanStack-Compromise-2026-05-12]]
- [x] No — close as benign if all five hunts return no results

---

## Related Notes

- [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]]
- [[RESEARCH-ChatGPT-Codex-M365-Connector-POC-Setup-and-Security]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created — proactive exposure assessment, all hunts pending |
