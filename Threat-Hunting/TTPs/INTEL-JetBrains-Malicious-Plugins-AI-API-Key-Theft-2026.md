---
title: JetBrains Malicious Plugins — AI API Key Theft Campaign
date: 2026-06-17
source: https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys
author: Ilyas Makari (Aikido Security)
mitre:
  - T1195.002
  - T1528
  - T1071.001
  - T1027
detection_candidate: true
tags:
  - "#intel"
  - "#supply-chain"
  - "#endpoint"
  - "#cloud"
  - "#status/done"
---

# INTEL — JetBrains Malicious Plugins — AI API Key Theft Campaign

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.aikido.dev/blog/multiple-jetbrains-ide-plugins-caught-stealing-ai-keys |
| **Author** | Ilyas Makari, Aikido Security |
| **Date Observed** | 2026-06-17 |
| **Date Published** | 2026-06-16 |
| **Patch Available** | N/A — plugin removal required; JetBrains removal status unconfirmed at time of writing |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1195.002 | Supply Chain Compromise — Compromise Software Supply Chain |
| T1528 | Steal Application Access Token |
| T1071.001 | Application Layer Protocol — Web Protocols (plaintext HTTP exfiltration) |
| T1027 | Obfuscated Files or Information (code repackaged across 15 plugins) |

---

## Summary

Aikido Security discovered a coordinated supply chain campaign operating inside the JetBrains Marketplace since October 2025. At least 15 plugins — published under seven distinct vendor accounts — pose as AI coding assistants built on DeepSeek, OpenAI, and SiliconFlow models, functioning normally while silently exfiltrating any API key entered in their settings panel. The exfiltration fires the instant the user clicks Apply, sending the key in plaintext over HTTP to a hardcoded C2 at `39.107.60[.]51`, authenticated with a static token `F48D2AA7CF341F782C1D` baked into the plugin. The operation runs a two-tier criminal model: free users' stolen keys are harvested server-side and redistributed to paying plugin subscribers as working AI provider credentials, effectively making victims fund the attacker's compute costs. Two plugins alone — CodeGPT AI Assistant and DeepSeek AI Assist — account for over 53,000 of the ~70,000 total installs, with new releases as recently as June 10, 2026. A parallel PromptSnatcher Chrome extension campaign (100,000 users across two extensions) targets full conversation capture from Claude, ChatGPT, Gemini, and Copilot at the browser layer.

---

## Relevance to Environment

Direct relevance is limited since your environment does not have an internal developer team using JetBrains IDEs at scale. However, the following apply:

- **Any developer or analyst workstation** with a JetBrains IDE (IntelliJ IDEA, PyCharm, WebStorm, etc.) is in scope — check your MDE device inventory for JetBrains processes.
- **AI API keys at risk** include OpenAI, DeepSeek, and SiliconFlow. If your organisation holds any API keys for these providers (e.g. for AI tool evaluations, Azure OpenAI, or third-party integrations), those need to be audited.
- The **PromptSnatcher Chrome extension campaign** is directly relevant to any users running Claude, M365 Copilot, or ChatGPT in Chrome — particularly if Chrome is unmanaged or extension policy is not enforced via Intune.
- The **supply chain TTP** (legitimate marketplace + manual review bypass + functional-but-backdoored plugin) mirrors the GlassWorm VS Code campaign — consistent escalation of IDE as a credential harvesting vector.
- Network detection of C2 IP `39.107.60[.]51` is actionable immediately in MDE.

**Priority:** Medium for JetBrains vector (limited developer footprint expected). Higher if any analyst workstations run JetBrains IDEs.

---

## IOCs

| Type | Value | Notes |
|------|-------|-------|
| IP | `39.107.60[.]51` | C2 server — plaintext HTTP POST, port 80 |
| Static API Token | `F48D2AA7CF341F782C1D` | Hardcoded X-Api-Key header in exfiltration request |
| URL Pattern | `http://39.107.60[.]51/api/software/{plugin_name}` | Exfiltration endpoint |
| Plugin ID | `com.my.code.tools` | CodeGPT AI Assistant — 25,571 downloads |
| Plugin ID | `ord.cp.code.ai.kit` | DeepSeek AI Assist — 27,727 downloads |
| Plugin ID | `com.json.simple.kit` | DeepSeek Git Commit |
| Plugin ID | `org.sm.yms.toolkit` | DeepSeek Junit Test |
| Plugin ID | `org.bug.find.tools` | DeepSeek FindBugs |
| Plugin ID | `org.translate.ai.simple` | DeepSeek AI Chat |
| Plugin ID | `com.yy.test.ai.simple` | DeepSeek Dev AI |
| Plugin ID | `com.dev.ai.toolkit` | DeepSeek AI Coding |
| Plugin ID | `com.json.view.simple` | AI FindBugs |
| Plugin ID | `com.my.git.ai.kit` | AI Git Commitor |
| Plugin ID | `org.check.ai.ds` | AI Coder Review |
| Plugin ID | `com.review.tool.code` | DeepSeek Coder AI |
| Plugin ID | `org.code.assist.dev.tool` | AI Coder Assistant |
| Plugin ID | `com.coder.ai.dpt` | DeepSeek Code Review |
| Plugin ID | `com.dp.git.ai.tool` | Coding Simple Tool |
| Vendor Account | `mycode` (CodePilot) | JetBrains vendor account |
| Vendor Account | `misshewei` (StackSmith) | JetBrains vendor account |
| Vendor Account | `keteme` (CodeCrafter) | JetBrains vendor account |
| Vendor Account | `simpledev` (CodeWeaver) | JetBrains vendor account |
| Vendor Account | `skyblue` (JetCode) | JetBrains vendor account |
| Vendor Account | `dialycode` (DailyCode) | JetBrains vendor account |
| Vendor Account | `947cb4c8-5db1-4cf0-8182-0aae7c433bb3` (ZenCoder) | JetBrains vendor account |
| Chrome Extension | `Smart Adblocker` | PromptSnatcher campaign — 90,000 users |
| Chrome Extension | `Adblock for Browser` | PromptSnatcher campaign — 10,000 users |

---

## Detection Notes

> `detection_candidate: true`

### Attack Mechanics
The `save()` method fires inside the plugin's settings `apply()` handler on key entry. The exfiltration HTTP POST targets `http://39.107.60[.]51/api/software/{name}`. Key string format check in malicious code: starts with `sk-`, length == 51 (OpenAI key format). SiliconFlow and DeepSeek keys handled without length restriction.

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound HTTP connections to the JetBrains plugin C2 IP 39.107.60.51 — direct IOC match for API key exfiltration

DeviceNetworkEvents
| where RemoteIP == "39.107.60.51"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Java processes (JetBrains IDE) making outbound HTTP connections on port 80 to non-private IPs — behavioural detection for IDE plugin C2 communication

DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "java")
| where RemotePort == 80
| where RemoteIPType != "Private"
| where not(RemoteUrl has_any ("jetbrains.com", "plugins.jetbrains.com", "downloads.marketplace.jetbrains.com"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Chrome extensions making outbound connections — hunt for PromptSnatcher or similar browser-layer credential/conversation capture; pivot from suspicious extension process activity

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "chrome.exe"
| where RemoteIPType != "Private"
| where RemoteIP == "39.107.60.51"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### Validated Columns
- [ ] `RemoteIP` — DeviceNetworkEvents, confirm field name vs `RemoteIPAddress`
- [ ] `RemoteIPType` — DeviceNetworkEvents, confirm available (Private/Public)
- [ ] `RemoteUrl` — DeviceNetworkEvents, confirm populated for HTTP connections
- [ ] `InitiatingProcessFileName` — should be standard AH column

---

## Hardening Actions

- [x] **Immediate:** Query MDE device inventory for machines running `idea64.exe`, `pycharm64.exe`, `webstorm64.exe`, or `java.exe` from JetBrains paths — inventory JetBrains IDE footprint
- [x] **Immediate:** Run C2 IP hunt query against DeviceNetworkEvents for `39.107.60.51` — if any hits, treat as confirmed exfiltration and rotate affected API keys
- [ ] **Chrome policy:** Audit Chrome extension policy via Intune — enforce allowlist or alert on unmanaged extension installation; check for `Smart Adblocker` and `Adblock for Browser` extensions
- [ ] **API key audit:** Identify any OpenAI, DeepSeek, or SiliconFlow API keys in use in your environment — rotate as precautionary measure if JetBrains IDEs are present
- [x] **Policy consideration:** Restrict JetBrains Marketplace plugin installation to pre-approved list via JetBrains Settings Sync or endpoint policy if developer workstations are confirmed in scope

---

## Related Notes

- [[INTEL-GlassWorm-v2-VSCode-Extension-Supply-Chain]] — parallel VS Code extension supply chain campaign
- [[INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience]] — related developer tooling supply chain TTP
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device]]
- [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created — source: Aikido Security blog + AI Weekly alert |
| 2026-06-17 | Generated 2 companion KQL notes: [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device]], [[KQL-JetBrains-Malicious-Plugins-AI-API-Key-Theft-2026-Device-Behavioural]] |
