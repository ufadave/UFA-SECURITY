---
title: GlassWorm v2 — 73 Fake VS Code Extensions Supply Chain Campaign
date: 2026-04-28
source: https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html
author: Ravie Lakshmanan
mitre:
  - T1195
  - T1195.002
  - T1555.003
  - T1552.001
  - T1546
  - T1071
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#supply-chain"
  - "#infostealer"
  - "#endpoint"
  - "#cloud"
---

# GlassWorm v2 — 73 Fake VS Code Extensions Supply Chain Campaign

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html |
| **Author** | Ravie Lakshmanan — The Hacker News |
| **Date Observed** | 2026-04-28 |
| **Date Published** | 2026-04-27 |
| **Additional Sources** | https://www.infoworld.com/article/4164656/ — InfoWorld deep-dive |
| **Research Firm** | Socket (Philipp Burckhardt, Head of Threat Intelligence) |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1195 | Supply Chain Compromise |
| T1195.002 | Compromise Software Supply Chain |
| T1555.003 | Credentials from Password Stores: Web Browsers |
| T1552.001 | Unsecured Credentials: Credentials in Files |
| T1546 | Event Triggered Execution (extension persistence) |
| T1071 | Application Layer Protocol (Solana blockchain C2) |
| T1027 | Obfuscated Files or Information (Unicode variation selectors) |

---

## Summary

GlassWorm v2 is the latest iteration of a persistent supply chain infostealer campaign first observed in October 2025, targeting developer environments via the Open VSX marketplace. The April 2026 wave saw 73 cloned VS Code extensions published — six confirmed malicious at the time of discovery, the remaining operating as sleeper packages that appear benign until a subsequent update delivers the GlassWorm loader. The extensions typosquat legitimate tool names to maximise download rates. The campaign uses blockchain-based C2 via Solana transaction memos, allowing payload URLs to be updated dynamically without modifying the original malicious package, complicating takedown and detection. Over 320 malicious artifacts have been identified since December 2025 across VS Code, Open VSX, npm, and GitHub repositories.

The infection chain is staged: the extension acts as a thin loader, connects to a newly created GitHub or public account, and downloads the GlassWorm payload as an "update." The ZOMBI payload module performs extensive credential harvesting — npm tokens, GitHub tokens, OpenVSX credentials, Git credentials, browser-stored credentials, crypto wallet data, macOS Keychain databases, Apple Notes, Safari cookies, and VPN configurations. Stolen credentials are then abused to compromise additional developer accounts and spread the worm further, creating an automated self-sustaining propagation cycle. The ForceMemo subvariant uses stolen GitHub tokens to force-push malicious code into Python repositories while preserving original commit metadata.

---

## Relevance to Environment

Moderate-to-high relevance. Developers and IT staff in your environment who use VS Code with Open VSX extensions are at risk. The credential theft targets GitHub tokens, npm, Git credentials, and browser-stored passwords — any developer account compromise could feed into a wider supply chain impact. macOS Keychain targeting is directly relevant given the Mac transition. The campaign has now expanded into MCP-style packages, which warrants monitoring given current Claude/MCP tooling use. There is no confirmed direct targeting of E5 enterprise environments, but stolen developer credentials could pivot into organisational systems.

---

## Detection Notes

### KQL Stubs

```kql
// Detect VS Code extension process spawning unusual child processes
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Identify VS Code extension host spawning suspicious network or credential-access processes

DeviceProcessEvents
| where InitiatingProcessFileName =~ "extensionHost.exe"
    or InitiatingProcessParentFileName =~ "code.exe"
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "curl.exe", "wget.exe")
| where ProcessCommandLine has_any ("solana", "github.com/releases", "vsix", "http", "base64")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```kql
// Detect outbound connections from VS Code extension host to unusual external IPs
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Identify extension host making unexpected external connections

DeviceNetworkEvents
| where InitiatingProcessFileName =~ "extensionHost.exe"
| where RemotePort in (80, 443, 8080)
| where not(RemoteUrl has_any ("marketplace.visualstudio.com", "open-vsx.org", "github.com", "microsoft.com"))
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```

```kql
// Detect persistence via LaunchAgents on macOS endpoints (MDE)
// Table: DeviceFileEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Flag new .plist files in LaunchAgents paths — GlassWorm macOS persistence mechanism

DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any ("/Library/LaunchAgents", "/Library/LaunchDaemons", "~/Library/LaunchAgents")
| where FileName endswith ".plist"
| where not(InitiatingProcessFileName in~ ("installer", "softwareupdated", "mdmclient"))
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Validated Columns
- [ ] `RemoteUrl` — DeviceNetworkEvents, confirm availability
- [ ] `extensionHost.exe` process name — confirm in MDE telemetry for macOS endpoints
- [ ] LaunchAgents path format — confirm FolderPath format in MDE for macOS

---

## Hardening Actions

- [ ] Audit VS Code extensions across developer endpoints — remove unrecognised or recently added extensions
- [ ] Disable automatic extension updates in VS Code: `extensions.autoUpdate: false` in settings
- [ ] Enforce extension allowlisting policy via Intune or endpoint management if developer population is defined
- [ ] Monitor for new `.plist` files in `~/Library/LaunchAgents` — GlassWorm macOS persistence path: `com.user.nodestart.plist`
- [ ] Rotate GitHub tokens and npm tokens for any developer who installed extensions from Open VSX since December 2025
- [ ] Add Open VSX to monitored domains — unexpected outbound connections from extension processes should alert

---

## Known Malicious Extension Names (partial)

- `outsidestormcommand.monochromator-theme`
- `lauracode.wrap-selected-code` (sleeper, activated Mar 18 2026)
- `96-studio.json-formatter` (sleeper, activated Mar 18 2026)

> Note: Eclipse Foundation has removed the 73 extensions. However the broader GlassWorm campaign (320+ artifacts) continues. Treat any Open VSX extension installed since Dec 2025 as requiring verification.

---

## Related Notes

- [[INTEL-GlassWorm-VS-Code-Extensions]] — prior note if exists
- [[Hardening/Controls/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created from Gmail [INTEL] triage |
