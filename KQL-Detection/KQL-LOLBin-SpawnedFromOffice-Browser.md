---
title: "LOLBin Spawned from Office or Browser with Suspicious Command Line"
date: 2026-04-26
schema: Advanced Hunting (MDE)
table: DeviceProcessEvents
mitre:
  - T1218 — System Binary Proxy Execution
  - T1059.001 — PowerShell
  - T1059.005 — Visual Basic
  - T1140 — Deobfuscate/Decode Files or Information
  - T1566 — Phishing (Initial Access)
tags:
  - "#detection/hunting"
  - "#endpoint"
  - "#hunt"
  - "#status/active"
status: active
---

# LOLBin Spawned from Office or Browser with Suspicious Command Line

## Purpose

Detects known Living-off-the-Land Binaries (LOLBins) spawned directly by Microsoft Office applications or browsers when the process command line contains high-confidence indicators of malicious activity — encoded commands, download cradles, or in-memory execution strings. This pattern is consistent with phishing-delivered macro execution, browser-based drive-by downloads, or HTML Application (HTA) abuse.

Particularly relevant for your environment given the active Iranian APT (Handala/CL-STA-1128) threat targeting endpoints via spear-phishing and LOLBin proxy execution.

---

## Schema Validated Columns

- [x] `Timestamp` — present in `DeviceProcessEvents`
- [x] `DeviceName` — present
- [x] `DeviceId` — present
- [x] `ReportId` — present
- [x] `AccountName` — present
- [x] `InitiatingProcessFileName` — present (parent process name)
- [x] `InitiatingProcessCommandLine` — present (parent process full cmdline)
- [x] `FileName` — present (child process binary name)
- [x] `ProcessCommandLine` — present (child process cmdline)

> **Schema Note:** All columns are native to `DeviceProcessEvents` in Advanced Hunting. No `parse_json()` or `AdditionalFields` expansion required for this query. Validated against MDE Advanced Hunting schema — no known availability issues.

---

## Query

```kql
let known_lolbins = dynamic([
    "rundll32.exe","regsvr32.exe","wscript.exe",
    "cscript.exe","mshta.exe","certutil.exe"
]);
let office_browsers = dynamic([
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
    "onenote.exe","msaccess.exe","mspub.exe",
    "msedge.exe","firefox.exe","chrome.exe"
]);
let high_confidence_indicators = dynamic([
    "encodedcommand","-enc","-bypass",
    "downloadstring","downloadfile",
    "iex","invoke-expression",
    "frombase64string"
]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ (known_lolbins)
| where InitiatingProcessFileName in~ (office_browsers)
| where not(
    InitiatingProcessCommandLine has "--no-startup-window"
    and InitiatingProcessFileName =~ "msedge.exe")
| where ProcessCommandLine has_any (high_confidence_indicators)
| project
    Timestamp, DeviceName, DeviceId, ReportId, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine
```

---

## Query Notes

### LOLBin List Rationale
| Binary | Common Abuse |
|--------|-------------|
| `rundll32.exe` | DLL sideloading, shellcode execution |
| `regsvr32.exe` | Squiblydoo (COM scriptlet via URL) |
| `wscript.exe` | VBScript/JScript macro payloads |
| `cscript.exe` | Console scriptlet execution |
| `mshta.exe` | HTA files, inline VBScript |
| `certutil.exe` | Base64 decode, file download cradle |

### High-Confidence Indicator Rationale
| Indicator | Why High Confidence |
|-----------|-------------------|
| `encodedcommand` / `-enc` | PowerShell Base64-encoded command — rarely legitimate from Office |
| `-bypass` | Execution policy bypass — almost always malicious in this context |
| `downloadstring` / `downloadfile` | In-memory download cradle |
| `iex` / `invoke-expression` | In-memory execution — classic cradle pattern |
| `frombase64string` | Encoded payload decoding |

### False Positive Suppression
The exclusion for `msedge.exe` with `--no-startup-window` covers the Edge background service manager process, which is a known benign spawn pattern. Adjust if your environment has additional Edge enterprise launch arguments that trigger noise.

### Lookback Note
Query uses `ago(1h)` — suitable for hunting/live investigation. Adjust to `ago(7d)` for broader retrospective hunts. See Analytics Rule settings below for scheduled detection.

---

## Test Results

```
Date tested:
Environment:
Devices tested against:
True positives found:
False positives observed:
FP suppression applied:
Notes:
```

---

## Sentinel Analytics Rule Settings

| Setting | Value |
|---------|-------|
| **Rule Name** | LOLBin Spawned from Office or Browser with Malicious Indicators |
| **Severity** | High |
| **Query Frequency** | Every 15 minutes |
| **Query Lookback** | Last 1 hour |
| **Alert Threshold** | > 0 results |
| **Event Grouping** | Group all events into a single alert |
| **MITRE ATT&CK** | T1218, T1059.001, T1059.005, T1140, T1566 |
| **Suppression** | None recommended — each hit is high confidence |
| **Incident Creation** | Enabled |
| **Custom Details to Map** | `DeviceName`, `AccountName`, `InitiatingProcessFileName`, `FileName`, `ProcessCommandLine` |

> **Note:** If this fires frequently in your environment due to legitimate tooling, consider adding a `DeviceId`-based or `AccountName`-based allowlist using a `let` exclusion block before promoting to analytics rule.

---

## Tuning Suggestions

- Add `| summarize count() by DeviceName, FileName, InitiatingProcessFileName` to identify noisy devices during initial hunting
- Extend `known_lolbins` with `msiexec.exe`, `odbcconf.exe`, `ieexec.exe` for broader coverage
- Pair with `DeviceNetworkEvents` to correlate network connections immediately following these process events (pivoting on `DeviceId` and `Timestamp`)
- Consider adding `InitiatingProcessParentFileName` to spot grandparent chains (e.g., `explorer.exe` → `winword.exe` → `rundll32.exe`)

---

## Hardening Control Pairs

- [[HARD-Disable-Macros-Office]] — Block VBA macros from internet-delivered documents
- [[HARD-ASR-Block-Office-Child-Processes]] — ASR Rule: Block Office applications from creating child processes (GUID: `d4f940ab-401b-4efc-aadc-ad5f3c50688a`)
- [[HARD-ASR-Block-Win32-from-Macro]] — ASR Rule: Block Win32 API calls from Office macros

---

## Related Notes

- [[INTEL-Handala-APT-LOLBin-TTPs]]
- [[KQL-CertUtil-Download-Cradle]]
- [[KQL-MSHTA-Execution-Detection]]
- [[HUNT-LOLBin-Abuse-Campaign]]

---

## Changelog

| Date | Change | Author |
|------|--------|--------|
| 2026-04-26 | Initial creation — sourced from KQL exercise | Dave |
