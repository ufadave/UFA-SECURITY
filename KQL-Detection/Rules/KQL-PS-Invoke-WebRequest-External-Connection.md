---
date: 2026-05-14
title: PS Invoke-WebRequest External Connection
table: "DeviceNetworkEvents"
schema: "Advanced Hunting"
mitre: "T1105"
tactic: "Command and Control"
technique: "Ingress Tool Transfer"
status: "Active"
promoted_to_rule: true
mde_rule_name: "Custom - PS connecting to an external site using Invoke-Webrequest"
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
  - "#network"
---

# KQL — PS Invoke-WebRequest External Connection

---

**Table:** `DeviceNetworkEvents` | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1105 | **Tactic:** Command and Control | **Technique:** Ingress Tool Transfer
**Created:** 2026-05-14 | **Status:** `Active`

---

## Purpose

Detects PowerShell using `Invoke-WebRequest` to establish successful connections to public IP addresses or external URLs. This technique is commonly used in post-exploitation for payload staging, C2 beaconing, and data exfiltration. Codex AI is excluded as a known-benign parent process; `developer.globalpayments.com` is excluded as an allowed business domain.

---

## Query

```kql
// Written by Burt-Han
// https://kqlquery.com/posts/detecting-post-exploitation-behaviour/
// Detects PowerShell Invoke-WebRequest connecting to public external endpoints
// Codex AI agent excluded as known-benign parent — note: exclusion covers both binary name variants (see tuning note below)
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let AllowedDomains = dynamic(['developer.globalpayments.com']);
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "Invoke-WebRequest"
// Exclude Codex AI agent — Windows binary ships as codex-x86_64-pc-windows-msvc.exe, not codex.exe
| where not(InitiatingProcessParentFileName has "codex")
| extend CommandLineIpv4 = extract(IPRegex, 0, InitiatingProcessCommandLine)
// Uncomment below to restrict to direct IPv4 connections only (higher fidelity, lower volume)
//| where isnotempty(CommandLineIpv4)
| where not(RemoteUrl in (AllowedDomains))
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| project-reorder Timestamp, InitiatingProcessCommandLine, RemoteUrl, ActionType, CommandLineIpv4
```

---

## Validated Columns

- [x] `InitiatingProcessCommandLine` — present in `DeviceNetworkEvents`
- [x] `InitiatingProcessParentFileName` — present in `DeviceNetworkEvents`
- [x] `RemoteUrl` — present in `DeviceNetworkEvents`
- [x] `ActionType` — present in `DeviceNetworkEvents`
- [x] `RemoteIPType` — present in `DeviceNetworkEvents`; values: `Public`, `Private`, `Loopback`
- [x] `CommandLineIpv4` — calculated via `extract()`, not a native column

---

## Test Results

**Run:** 2026-05-14
**Result:** 2 hits — both false positives on `lt13265.ad.corp.local` (user: `Divya.Madapu@ufa.com`)

| Result | Command Summary | Parent | Verdict |
|--------|----------------|--------|---------|
| 2026-05-14 14:52 | Fetch `ufa.com`, parse CSS/asset refs | `codex-x86_64-pc-windows-msvc.exe` | False Positive — Codex |
| 2026-05-07 20:23 | Fetch Maven Central POM files (JAXWS 4.0.2) | `codex-x86_64-pc-windows-msvc.exe` | False Positive — Codex |

**Root cause:** Original query excluded `codex.exe` but Windows ships the binary as `codex-x86_64-pc-windows-msvc.exe`. Updated exclusion to `has "codex"` to cover all variants.

---

## Tuning Notes

### Codex Exclusion Fix
- **Original:** `| where InitiatingProcessParentFileName != @"codex.exe"`
- **Updated:** `| where not(InitiatingProcessParentFileName has "codex")`
- **Rationale:** The Codex AI Windows binary is named `codex-x86_64-pc-windows-msvc.exe`. The original string match was too narrow and allowed Codex-parented PowerShell through. The `has` operator covers all current and future Codex binary name variants. If a non-Codex process ever contains "codex" in its name, reassess and switch to `!in~` with explicit values.

### AllowedDomains Expansion Candidates
Consider adding the following if they produce noise in your environment:
- `repo1.maven.org` — Maven Central (Java dependency resolution via Codex)
- Any internal proxy or update endpoints that surface as public IPs

### IPv4-Only Variant
The commented-out `| where isnotempty(CommandLineIpv4)` line restricts results to connections where the URL in the command line is a raw IPv4 address. This is the higher-fidelity variant — harder to attribute as benign tooling, more likely to be staging/C2. Enable if alert volume is high.

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - PS connecting to an external site using Invoke-Webrequest
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** Medium
- **Actions:** `Alert only`
- **Deployed:** [x]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is Advanced Hunting only; use MDE Custom Detection
### Sentinel Analytics Rule
- **Rule Name:** Custom - PS connecting to an external site using Invoke-Webrequest
- **Deployed:** [ ]
-->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes

- [[]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-14 | Created — based on Burt-Han query (kqlquery.com); Codex exclusion corrected from `codex.exe` to `has "codex"` following FP analysis on lt13265 |
