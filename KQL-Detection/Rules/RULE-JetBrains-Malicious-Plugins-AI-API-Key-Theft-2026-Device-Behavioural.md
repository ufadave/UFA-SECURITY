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

# RULE — JetBrains Malicious Plugins — IDE Process Outbound HTTP Behavioural Detection

---

## Purpose

Behavioural detection for JetBrains IDE processes (`java.exe`) making outbound HTTP connections on port 80 to non-private external IPs, scoped to JetBrains install paths. The malicious plugin campaign (Aikido Security, June 2026) exfiltrates AI API keys over plaintext HTTP to a hardcoded C2 — IDE processes running from JetBrains install directories have no legitimate reason to make direct port 80 connections to arbitrary external IPs. Catching future variants with rotated C2 IPs is the primary value of this rule; the companion IOC rule covers the known C2.

Validated 2026-06-17: environment has no JetBrains IDEs on MDE-enrolled endpoints. Zero results is expected baseline; any hit is high-priority.

---

## Query

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "java")
| where RemotePort == 80
| where RemoteIPType != "Private"
// Scope to JetBrains IDE install paths only
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

## Deployment

### MDE Custom Detection (Advanced Hunting)

| Field | Value |
|-------|-------|
| **Rule Name** | `Custom - JetBrains IDE Java Process Outbound HTTP Port 80` |
| **Schema** | Advanced Hunting |
| **Table** | DeviceNetworkEvents |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | High |
| **Actions** | Generate alert — investigate before isolating; confirm JetBrains IDE is genuinely present before escalating |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics; MDE Advanced Hunting only -->

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-06-17 |
| **Deployed To** | `MDE Custom Detection` |
| **Rule Name** | `Custom - JetBrains IDE Java Process Outbound HTTP Port 80` |
| **Rule ID** | <!-- Populate after creating rule in MDE portal → Advanced Hunting → Custom detections --> |

---

## Triage Notes

If this rule fires:

1. Confirm `InitiatingProcessFolderPath` — is this genuinely a JetBrains IDE install? If not, the path-based filter may need expanding (investigate the path and add to exclusions if legitimate).
2. Check `RemoteIP` against the known IOC `39.107.60.51` — if it matches, treat as confirmed exfiltration and escalate immediately.
3. Identify which user account (`InitiatingProcessAccountName`) and which device. Check whether any AI API keys (OpenAI, DeepSeek, SiliconFlow) are associated with that user.
4. Review `InitiatingProcessCommandLine` — does it reference any of the 15 known malicious plugin IDs (see INTEL note)?
5. If exfiltration confirmed: rotate affected API keys before revoking plugin access — do not revoke tokens before key rotation or the attacker may destroy evidence.

---

## Hardening Control Pair

- [[HARD-Chrome-Extension-Policy]] *(create if not exists)*
- [[HARD-JetBrains-Plugin-Allowlist]] *(create if not exists)*

---

## Related Notes

- [[INTEL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026]]
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device]]
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created — promoted from [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]] |
| 2026-06-17 | Severity elevated to High — zero expected baseline makes any hit immediately significant |
