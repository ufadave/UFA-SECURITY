---
title: "Nextron THOR at Locked Shields + Axios/LiteLLM Supply Chain YARA Rules"
date: 2026-04-23
source: https://www.nextron-systems.com/2026/04/22/nextron-locked-shields-thor-apt-scanner/
author: "Nextron Research"
mitre:
  - T1195.001
  - T1195.002
tactic:
  - "Supply Chain Compromise"
detection_candidate: true
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#intel"
  - "#status/active"
  - "#endpoint"
  - "#supply-chain"
  - "#action-required"
---

# INTEL — Nextron THOR at Locked Shields + Axios/LiteLLM Supply Chain YARA Rules

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.nextron-systems.com/2026/04/22/nextron-locked-shields-thor-apt-scanner/ |
| **Author** | Nextron Research |
| **Tweet** | https://x.com/nextronresearch/status/2046666197412839578 |
| **Date Observed** | 2026-04-23 |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain |

---

## Summary

Nextron published two items around this date. First, their involvement in Locked Shields 2026 using THOR APT Scanner for compromise assessment — highlighting THOR's value in detecting attacker artifacts missed by EDR at rest. Second, Valhalla YARA rules now cover two active supply chain attacks: the Axios NPM compromise (March 30, 2026 — malicious versions 1.14.1 and 0.30.4 delivering a cross-platform RAT via `plain-crypto-js@4.2.1`) and the LiteLLM PyPI attack (March 2026 — versions 1.82.7/1.82.8 exfiltrating credentials and installing a persistent C2 backdoor attributed to TeamPCP).

---

## Relevance to Environment

If any developer systems or build pipelines use npm or Python packages, the Axios and LiteLLM supply chain compromises are directly relevant. LiteLLM in particular is a dependency that could appear in AI tooling being evaluated across the fleet. THOR scanner is worth evaluating for periodic compromise assessment across the Windows fleet.

---

## Detection Notes

### KQL Stubs

**1. Suspicious child process from package manager (npm/pip)**

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect suspicious process spawning from npm or pip installs — potential supply chain execution

DeviceProcessEvents
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "python.exe", "pip.exe", "pip3")
| where ProcessCommandLine has_any ("cscript", "curl", "powershell", "cmd /c", "wget", "certutil")
| where InitiatingProcessCommandLine has_any ("install", "pip install", "npm install")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

**2. Axios malicious version detection (file hash / version)**

```kql
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect presence of known-malicious Axios npm versions by path pattern

DeviceFileEvents
| where FolderPath has "node_modules"
| where FolderPath has "axios"
| where FileName == "package.json"
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Validated Columns

- [ ] `DeviceProcessEvents.InitiatingProcessFileName` — confirm case sensitivity behaviour
- [ ] `DeviceProcessEvents.InitiatingProcessCommandLine` — confirm field populated for npm/pip on Windows
- [ ] `DeviceFileEvents.FolderPath` — confirm npm node_modules path format in your environment

---

## IOCs

| Type | Value | Campaign |
|------|-------|----------|
| npm package | `axios` v1.14.1 | Axios supply chain |
| npm package | `axios` v0.30.4 | Axios supply chain |
| npm package | `plain-crypto-js` v4.2.1 | Axios supply chain (dropper) |
| PyPI package | `litellm` v1.82.7 | TeamPCP / LiteLLM |
| PyPI package | `litellm` v1.82.8 | TeamPCP / LiteLLM |

---

## Hardening Actions

- [x] Check developer endpoints for Axios npm versions 1.14.1 or 0.30.4
- [ ] Check for LiteLLM versions 1.82.7 or 1.82.8 in Python environments
- [ ] Evaluate THOR Lite for periodic compromise assessment on key servers
- [ ] Review Valhalla free YARA rules for supply chain signatures

---

## Related Notes

- [[INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience]] — TeamPCP actor detail
- [[ACTOR-TeamPCP]] — threat actor note

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-23 | Created |
| 2026-05-28 | Renamed from Nextron-Research-THOR-Locked-Shields-Supply-Chain.md — added YAML frontmatter, fixed #status/active typo, standardised structure |
