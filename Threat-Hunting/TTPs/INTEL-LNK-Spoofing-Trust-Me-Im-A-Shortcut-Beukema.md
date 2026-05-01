---
title: Trust Me, I'm a Shortcut — LNK File UI Spoofing & Hidden Execution (Beukema / lnk-it-up)
date: 2026-04-28
source: https://www.wietzebeukema.nl/blog/trust-me-im-a-shortcut
tags:
  - "#intel"
  - "#endpoint"
  - "#detection"
  - "#status/active"
  - "#action-required"
  - "High"
detection_candidate: true
---

# INTEL — LNK File UI Spoofing: Five Techniques to Spoof Target & Hide Arguments

## Source
- **URL:** https://www.wietzebeukema.nl/blog/trust-me-im-a-shortcut
- **Author:** Wietze Beukema (author of HijackLibs, ArgFuscator — trusted researcher)
- **Published:** February 2026
- **Date received:** 2026-04-28
- **Tool:** lnk-it-up (lnk-generator + lnk-tester) — https://github.com/wietzebeukema/lnk-it-up
- **Original email subject:** `[Info] Trust Me, I'm a Shortcut`

## MITRE ATT&CK
| Tactic | Technique |
|--------|-----------|
| Initial Access | T1566.001 — Phishing: Spearphishing Attachment |
| Execution | T1204.002 — User Execution: Malicious File |
| Defense Evasion | T1027.012 — Obfuscated Files: LNK Icon Smuggling |
| Defense Evasion | T1218 — System Binary Proxy Execution (LOLBIN via hidden args) |
| Lateral Movement / Credential Access | T1187 — Forced Authentication (LNK → UNC path → NTLM hash leak) |

## Detection Candidate
> ⚠️ **Yes** — process launch mismatch, hidden argument length, suspicious LNK characteristics detectable in MDE DeviceFileEvents and DeviceProcessEvents

## Summary
Wietze Beukema (author of HijackLibs.net and ArgFuscator) has documented five previously undisclosed techniques for crafting Windows LNK shortcut files that deceive users and bypass tooling inspection. The core problem: Windows Explorer reads multiple optional structures in the LNK binary format and applies inconsistent fallback logic — what Explorer *displays* in the Properties dialog and what it *executes* when you open the shortcut can be completely different. The five techniques allow fully spoofing the displayed target path, hiding command-line arguments beyond the 260-character display limit, and blanking the Properties dialog entirely while still executing payloads. One technique received CVE assignment (CVE-2025-9491); Microsoft has declined to patch most of the others as "UI bugs not meeting the security bar." The `lnk-it-up` toolkit (lnk-generator + lnk-tester) is now publicly available — meaning weaponisation is commodity.

## Five Techniques (Summary)
| # | Technique | What's Spoofed | Detection Challenge |
|---|-----------|---------------|-------------------|
| 1 | LinkTargetIDList vs ExpString mismatch | Displayed target vs executed target | Requires binary LNK parsing |
| 2 | Argument truncation at 260 chars | Arguments beyond char 260 hidden in UI | Process cmdline captures full args |
| 3 | HasExpString flag + null EnvironmentVariableDataBlock | Target AND arguments blanked in Properties | FileCreated event + binary inspection |
| 4 | LinkInfo fallback abuse | Target shown as legitimate path, alternate executed | LNK parser required (not Windows Explorer) |
| 5 | Icon/target path spoofing via relative path manipulation | Icon path ≠ execution path | MDE FileCreated + launch tracking |

## Relevance to Environment
- **Direct relevance** — LNK-based initial access is a primary delivery vehicle for the Iranian APT threat actors targeting your environment (Handala/CL-STA-1128). This research expands the LNK attack surface significantly.
- POS terminals and remote plant workstations are high-value targets: USB-delivered LNKs bypass email gateway inspection entirely.
- The hidden argument technique (Variant 2, 65,536-char cmdline) is trivially detectable in MDE `ProcessCommandLine` — process execution logs capture the full argument string even when Explorer won't display it. This is a hunt target.
- NTLM hash leak via UNC-pointing LNK remains a risk in the NTLMv2-only environment — LNK icon paths can still force SMB auth to attacker-controlled servers.
- `lnk-it-up` is now public — expect threat actors to operationalise these variants rapidly.

## Detection Notes

### KQL — Oversized LNK Command-Line Arguments (MDE)
```kql
// Schema: Advanced Hunting — DeviceProcessEvents
// Detects processes launched with unusually long cmdlines (hidden args technique)
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where strlen(ProcessCommandLine) > 500
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, FolderPath
| order by strlen(ProcessCommandLine) desc
```

### KQL — LNK File Creation Events (MDE)
```kql
// Schema: Advanced Hunting — DeviceFileEvents
// Hunt for recently created LNK files in user-writable paths (suspicious staging locations)
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where FolderPath has_any (
    "\\Downloads\\", "\\AppData\\Temp\\", "\\Desktop\\",
    "\\Users\\Public\\", "\\Startup\\"
)
| where InitiatingProcessFileName !in~ ("explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

### KQL — LOLBin Execution via LNK (MDE)
```kql
// Schema: Advanced Hunting — DeviceProcessEvents
// LOLBIN child processes from Explorer (indicating LNK-launched payloads)
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "certutil.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "bitsadmin.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### KQL — UNC Path in Process Creation (NTLM Hash Leak via LNK icon)
```kql
// Schema: Advanced Hunting — DeviceNetworkEvents
// Outbound SMB to non-internal destinations — may indicate LNK icon UNC coercion
DeviceNetworkEvents
| where RemotePort == 445
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName
```

### Schema Validation
- [ ] `InitiatingProcessFileName` — DeviceProcessEvents ✓
- [ ] `ProcessCommandLine` — DeviceProcessEvents ✓ (captures full cmdline including truncated portions)
- [ ] `FolderPath` — DeviceFileEvents ✓
- [ ] `RemoteIPType` — DeviceNetworkEvents — confirm field availability; may need to filter by IP range instead

## Hardening Actions
- [ ] **Hunt:** Run oversized cmdline query — look for ProcessCommandLine > 500 chars from Explorer-spawned processes
- [ ] **Hunt:** Run LOLBin-from-Explorer query for past 30 days
- [ ] Create MDE custom detection rule for LNK creation in Downloads/Temp/Desktop by non-browser processes
- [ ] Review `lnk-tester` tool — deploy to DFIR/IR workflow for LNK inspection during investigations
- [ ] Consider ASR rule: "Block Office applications from creating executable content" and "Block execution of potentially obfuscated scripts" — won't block LNKs directly but covers common follow-on payloads
- [ ] Add LNK inspection step to IR playbooks — use lnk-tester or LECmd for binary inspection rather than relying on Explorer Properties dialog
- [ ] For OT/SCADA plant: USB policy review — LNK delivery via removable media is a primary OT initial access vector

## Sentinel Analytics Rule Recommendation
- **Rule:** LOLBin child process from explorer.exe
- **Frequency:** Every 5 minutes
- **Lookback:** 5 minutes
- **Severity:** Medium (high with process injection follow-on)

## Related Notes
- [[IR-DFIR/Playbooks]] — add LNK inspection to initial triage procedure
- [[OT-SCADA/Assets]] — USB-delivered LNK is a primary OT threat vector
- [[Hardening/Controls]] — ASR rules, USB policy
- [[Threat-Hunting/TTPs]] — Iranian APT initial access patterns

## Validated Columns
- [ ] `ProcessCommandLine` — DeviceProcessEvents ✓
- [ ] `InitiatingProcessFileName` — DeviceProcessEvents ✓
- [ ] `RemoteIPType` — DeviceNetworkEvents — **validate in your environment**; may not be available in all schemas
- [ ] `FolderPath` — DeviceFileEvents ✓

## Changelog
| Date | Change |
|------|--------|
| 2026-04-28 | Created from inbox triage — high-priority detection candidate, lnk-it-up now public |
