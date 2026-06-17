---
title: JetBrains Malicious Plugins — IDE Process Outbound HTTP Behavioural Detection
date: 2026-06-17
table: DeviceNetworkEvents
schema: Advanced Hunting
mitre:
  - "T1528"
  - "T1071.001"
  - "T1195.002"
tactic: Credential Access / Command and Control / Supply Chain
technique: Steal Application Access Token / Web Protocols / Compromise Software Supply Chain
status: Validated
promoted_to_rule: true
mde_rule_name: "Custom - JetBrains IDE Java Process Outbound HTTP Port 80"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#supply-chain"
  - "#endpoint"
  - "#status/done"
---

# KQL — JetBrains Malicious Plugins — IDE Process Outbound HTTP Behavioural Detection

---

## Purpose

Behavioural detection for JetBrains IDE processes (`java.exe`) making outbound HTTP connections on port 80 to non-private external IPs, scoped to JetBrains install paths. The malicious plugins exfiltrate over plaintext HTTP to a hardcoded IP — IDE processes running from JetBrains install directories should not be making direct port 80 connections to arbitrary external IPs. Catches future variants that rotate the C2 IP, unlike the IOC-based companion query. Validated against live environment — environment has no JetBrains IDEs on MDE-enrolled endpoints (zero results confirmed).

---

## Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "java")
| where RemotePort == 80
| where RemoteIPType != "Private"
// Scope to JetBrains IDE install paths only — eliminates ServiceNow MID, cloudmanager, Kronos, Site24x7 noise
| where InitiatingProcessFolderPath has_any (
    "JetBrains",
    "IntelliJIdea",
    "PyCharm",
    "WebStorm",
    "GoLand",
    "Rider",
    "CLion",
    "DataGrip"
  )
// Exclude known JetBrains infrastructure
| where not(RemoteUrl has_any (
    "jetbrains.com",
    "plugins.jetbrains.com",
    "downloads.marketplace.jetbrains.com",
    "marketplace.jetbrains.com",
    "statistics.jetbrains.com"
  ))
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## Validated Columns

- [x] `RemoteIPType` — confirmed available in DeviceNetworkEvents
- [x] `RemoteUrl` — confirmed available; may be empty for raw IP connections (acceptable)
- [x] `InitiatingProcessFileName` — confirmed; `java.exe` on Windows
- [x] `InitiatingProcessFolderPath` — confirmed; key tuning field — path scoping eliminates all environment noise

---

## Test Results

Validated 2026-06-17. Pre-tuning query (no folder path filter) returned all legitimate environment Java traffic: ServiceNow MID servers (`ufads206`, Cloudflare IPs), cloud manager processes (`ufancm20x`, AWS IMDS `169.254.169.254`), Kronos/WFC (`ufaap211`), Site24x7 on-prem poller (`pocme501`). Adding `InitiatingProcessFolderPath has_any (JetBrains install paths)` filter reduced results to zero — confirms no JetBrains IDEs present on MDE-enrolled endpoints. Zero results is the expected baseline; any future hit warrants immediate investigation.

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-17 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | `Custom - JetBrains IDE Java Process Outbound HTTP Port 80` |
| **Rule ID** | <!-- Populate mde_rule_name in frontmatter when deployed in MDE portal --> |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics; deploy via MDE Advanced Hunting only -->

---

## Hardening Control Pair

- [[HARD-Chrome-Extension-Policy]] *(create if not exists)*
- [[HARD-JetBrains-Plugin-Allowlist]] *(create if not exists)*

---

## Related Notes

- [[INTEL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026]]
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device]]
- [[RULE-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created — companion to [[INTEL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026]] |
| 2026-06-17 | Query tuned — added InitiatingProcessFolderPath scoping to eliminate ServiceNow MID, cloudmanager, Kronos, Site24x7 noise; validated zero results (no JetBrains IDEs on enrolled endpoints) |
| 2026-06-17 | Promoted to rule — RULE-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural |
