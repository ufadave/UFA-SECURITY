---
date: 2026-05-29
title: Network Scanning Detected
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre:
  - "T1046"
  - "T1595.001"
tactic: "Discovery / Reconnaissance"
technique: "T1046 — Network Service Scanning | T1595.001 — Scanning IP Blocks"
status: "Validated"
promoted_to_rule: true
mde_rule_name: "Custom - Network Scanning Detected"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
  - "#network"
---

# RULE — Network Scanning Detected

---

**Table:** `DeviceProcessEvents` | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1046, T1595.001 | **Tactic:** Discovery / Reconnaissance
**Created:** 2026-05-29 | **Status:** `Validated`

---

## Purpose

Detects execution of known network scanning tools — specifically Advanced IP Scanner, Advanced Port Scanner (Famatech), and SoftPerfect Network Scanner — via process version metadata (company name, product name, file description) and characteristic command-line arguments. Catches both GUI-launched and portable/silent invocations. Targets internal use: any execution on an endpoint warrants review, as these tools have no legitimate baseline in the environment.

---

## Query

```kql
let CompanyKeywords = dynamic(["Famatech", "SoftPerfect"]);
let ProductKeywords = dynamic(["Advanced IP Scanner", "Advanced Port Scanner", "Network Scanner"]);
let DescKeywords    = dynamic(["Advanced IP Scanner", "Advanced Port Scanner", "Application for scanning networks"]);
let Exceptions      = dynamic(["Canon IJ Network Scanner Selector EX", "Canon IJ Network Scanner Selector EX2"]);
DeviceProcessEvents
| where not(ProcessVersionInfoFileDescription has_any (Exceptions)) 
| where ProcessVersionInfoCompanyName has_any (CompanyKeywords)
    or ProcessVersionInfoProductName has_any (ProductKeywords)
    or ProcessVersionInfoFileDescription has_any (DescKeywords)
    or ProcessCommandLine has_all ("/portable", "/lng")
    or ProcessCommandLine has_all ("/hide", "/auto")
| project
    Timestamp, ReportId, DeviceName, DeviceId, AccountName, FileName,
    ProcessCommandLine, ProcessVersionInfoCompanyName,
    ProcessVersionInfoProductName, ProcessVersionInfoFileDescription,
    SHA256, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

---

## Validated Columns

- [x] `Timestamp` — standard
- [x] `ReportId` — required for MDE Custom Detection alert linking
- [x] `DeviceName` — standard
- [x] `DeviceId` — standard
- [x] `AccountName` — standard
- [x] `FileName` — process image name
- [x] `ProcessCommandLine` — used in has_all clauses; confirm no truncation on long args
- [x] `ProcessVersionInfoCompanyName` — version info field; populated only when PE metadata is present
- [x] `ProcessVersionInfoProductName` — version info field; same caveat
- [x] `ProcessVersionInfoFileDescription` — version info field; used in Exception exclusion and detection
- [x] `SHA256` — for hash-based correlation
- [x] `InitiatingProcessFileName` — parent process context
- [x] `InitiatingProcessCommandLine` — parent process args
- [x] `InitiatingProcessParentFileName` — grandparent process context

> ⚠️ `ProcessVersionInfoCompanyName`, `ProcessVersionInfoProductName`, `ProcessVersionInfoFileDescription` — these fields rely on PE version metadata embedded in the binary. Unsigned, packed, or renamed copies of scanners will not populate these fields. The `/portable` and `/hide` command-line clauses provide partial coverage for evasion scenarios.

---

## Test Results

- [x] Validated against 30-day live data — confirmed hits on legitimate scanner use prior to rule deployment
- [x] Canon exception confirmed effective — no false positives from Canon IJ network selector
- [x] `/portable /lng` clause validated against Advanced IP Scanner portable invocations
- [ ] `/hide /auto` clause — confirm against SoftPerfect silent scan invocations if observed

---

## Deployment

### MDE Custom Detection Rule

- **Rule Name:** `Custom - Network Scanning Detected`
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** Medium
- **Actions:** Alert only
- **Deployed:** [x]
- **Rule ID:** <!-- Populate mde_rule_name confirmed above; no separate rule ID captured -->

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-29 |
| **Deployed To** | MDE Custom Detection |
| **Rule Name** | `Custom - Network Scanning Detected` |
| **Rule ID** | <!-- Populate from MDE portal if needed --> |

<!-- INACTIVE: Sentinel Analytics Rule -->
<!--
This query runs against DeviceProcessEvents (Advanced Hunting only).
Not applicable for Sentinel Log Analytics deployment.
If ingesting MDE device tables into Sentinel in future, revisit.
-->

---

## Tuning Notes

> Expand `CompanyKeywords`, `ProductKeywords`, or `DescKeywords` lists to cover additional scanner tools as encountered (e.g. Angry IP Scanner, LanSweeper, Nmap GUI wrappers).
>
> Consider adding `InitiatingProcessFileName` exclusions if IT tooling (e.g. RMM agents) is found to invoke scanners legitimately during approved network assessments.
>
> Version metadata detection is bypassable — consider supplementing with a hash-based IOC watchlist for known scanner binaries.

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
| 2026-05-29 | Created — rule already deployed as MDE Custom Detection |
