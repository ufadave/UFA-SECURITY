---
title: JetBrains Malicious Plugins — C2 IP IOC Detection
date: 2026-06-17
table: DeviceNetworkEvents
schema: Advanced Hunting
mitre:
  - "T1528"
  - "T1071.001"
tactic: Credential Access / Command and Control
technique: Steal Application Access Token / Web Protocols
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/query"
  - "#supply-chain"
  - "#endpoint"
  - "#status/draft"
---

# KQL — JetBrains Malicious Plugins — C2 IP IOC Detection

---

## Purpose

Direct IOC match against the confirmed C2 IP `39.107.60.51` used by the JetBrains malicious plugin campaign to exfiltrate AI provider API keys (OpenAI, DeepSeek, SiliconFlow). Any hit on this IP is high-confidence — the IP is hardcoded into all 15 malicious plugins with no legitimate use. Deploy as an MDE Custom Detection; convert to scheduled alert if Sentinel ingestion of network events is available.

---

## Query

```kql
DeviceNetworkEvents
| where RemoteIP == "39.107.60.51"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## Validated Columns

- [ ] `RemoteIP` — confirm field name; may be `RemoteIPAddress` in some schema versions
- [ ] `InitiatingProcessAccountName` — correct column name in DeviceNetworkEvents (not `AccountName`)
- [ ] `RemoteUrl` — confirm populated for HTTP connections; may be empty for raw IP connections
- [ ] `InitiatingProcessFileName` — standard AH column, expected: `java.exe` for JetBrains IDE
- [ ] `InitiatingProcessCommandLine` — standard AH column
- [ ] `InitiatingProcessFolderPath` — standard AH column; look for JetBrains install paths

---

## Test Results

> Paste CSV results here after running in Advanced Hunting. Expected: `java.exe` initiating process from a JetBrains install directory. Any hit = confirmed compromise; rotate API keys immediately.

---

## Deployment

### MDE Custom Detection (Advanced Hunting)

| Field | Value |
|-------|-------|
| **Rule Name** | `Custom - JetBrains Plugin C2 IP Contact 39.107.60.51` |
| **Schema** | Advanced Hunting |
| **Table** | DeviceNetworkEvents |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **Actions** | Isolate device, alert SOC |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics; deploy via MDE Advanced Hunting only -->

---

## Hardening Control Pair

- [[HARD-Chrome-Extension-Policy]] *(create if not exists)*

---

## Related Notes

- [[INTEL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026]]
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created — companion to [[INTEL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026]] |
