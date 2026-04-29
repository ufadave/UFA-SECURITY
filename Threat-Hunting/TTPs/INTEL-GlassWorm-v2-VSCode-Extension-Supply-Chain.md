---
title: GlassWorm v2 — 73 Fake VS Code Extensions Supply Chain Attack
date: 2026-04-28
source: https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html
source_secondary: https://www.scworld.com/news/glassworm-attackers-activate-new-sleeper-extensions-on-open-vsx
tags:
  - "#intel"
  - "#endpoint"
  - "#supply-chain"
  - "#infostealer"
  - "#status/review"
  - "#action-required"
detection_candidate: "true"
---

# INTEL — GlassWorm v2: 73 Fake VS Code Extensions Supply Chain Attack

## Source
- **Primary:** The Hacker News — 2026-04-27
- **Secondary:** SC Media, Aikido Security
- **Original email subject:** `[INTEL] Researchers Uncover 73 Fake VS Code Extensions Delivering GlassWorm v2 Malware`

## MITRE ATT&CK
| Tactic | Technique |
|--------|-----------|
| Initial Access | T1195.001 — Compromise Software Supply Chain |
| Execution | T1204.002 — Malicious File |
| Credential Access | T1528 — Steal Application Access Token |
| Persistence | T1505 — Server Software Component (extension dependency abuse) |
| Collection | T1005 — Data from Local System |

## Detection Candidate
> ⚠️ **Yes** — malicious extension execution, credential exfiltration over network, suspicious child process from IDE

## Summary
Socket's threat research team identified 73 cloned VS Code extensions on the Open VSX marketplace linked to the ongoing GlassWorm infostealer campaign, now tracked as v2. Of the 73, six have been confirmed active and malicious; the rest are "sleeper" packages that appear benign at install time and activate malice via subsequent updates. The campaign has been running since at least October 2025, with over 320 total artefacts identified since December 2025. The active malware targets credential stores across VS Code, Cursor, VSCodium, and other IDE variants — exfiltrating Open VSX tokens, GitHub credentials, npm tokens, and cryptocurrency wallet data. The attackers use the stolen credentials to self-propagate by publishing more infected extensions.

## Technical Detail
- Clones use typosquatting on package names and copy legitimate icons/descriptions to build visual trust
- Malicious activation delivered via `extensionPack` and `extensionDependencies` manifest fields added post-install, or via malware hosted on external GitHub repos
- This shifts the malicious logic outside of static code analysis scan coverage — the extension's source code at install is clean
- A Zig-based native dropper was observed in March 2026 wave; April 2026 wave escalated with sleeper pattern
- Six confirmed malicious extensions in this cluster impersonated: Monochromator theme, AutoAntigravity, IronPLC, VS Code Pets, HTML-validate, Version Lens
- As of 2026-04-28 the confirmed malicious extensions have been removed from Open VSX

## Relevance to Environment
- **IronPLC impersonation is directly OT-relevant** — IronPLC is a VS Code extension for IEC 61131-3 PLC programming (Rockwell, Siemens, others). Any engineer with VS Code on an OT-adjacent system who installed a cloned IronPLC should be treated as potentially compromised.
- Developers on endpoints using VS Code/Cursor/VSCodium are exposed — audit extension installs across the estate.
- GitHub and npm credentials stolen could expose internal repos or CI/CD pipelines if devs have those credentials cached.
- Low likelihood of direct org impact (no devs confirmed using Open VSX vs official VS Code Marketplace), but verify.

## Detection Notes

### KQL Stub — Suspicious VS Code Child Process (MDE)
```kql
// Schema: Advanced Hunting — DeviceProcessEvents
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("code.exe", "cursor.exe", "vscodium.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "certutil.exe", "curl.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### KQL Stub — Outbound Network from IDE (MDE)
```kql
// Schema: Advanced Hunting — DeviceNetworkEvents
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("code.exe", "cursor.exe", "vscodium.exe")
| where RemotePort !in (80, 443)
    or RemoteUrl has_any ("github.com", "raw.githubusercontent.com") == false
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

### Schema Validation
- [ ] `InitiatingProcessFileName` — available in DeviceProcessEvents and DeviceNetworkEvents ✓
- [ ] `RemoteUrl` — available in DeviceNetworkEvents ✓
- [ ] `RemoteIP` — use `RemoteIP` not `RemoteIPAddress` in DeviceNetworkEvents ✓

## Hardening Actions
- Audit all VS Code/Cursor/VSCodium extension installs across the estate — focus on extensions from Open VSX vs official Marketplace
- **Priority: Any machine that had IronPLC installed from Open VSX** — treat as credential compromise
- Apply MDE custom detection rule for IDE spawning cmd/PS child processes
- Consider WDAC allowlist policy to prevent unsigned extension executables

## Related Notes
- [[WDAC-Deployment]] — extension execution may be a WDAC policy gap
- [[OT-SCADA/Assets]] — IronPLC impersonation is OT-relevant

## Validated Columns
- [ ] `InitiatingProcessFileName` — DeviceProcessEvents
- [ ] `RemoteIP` — DeviceNetworkEvents (not `RemoteIPAddress`)
- [ ] `RemoteUrl` — DeviceNetworkEvents

## Changelog
| Date | Change |
|------|--------|
| 2026-04-28 | Created from inbox triage |
