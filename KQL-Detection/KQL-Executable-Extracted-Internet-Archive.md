---
title: Executable Extracted from Internet-Sourced Archive
date: 2026-04-28
table: DeviceFileEvents, DeviceFileCertificateInfo
schema: Advanced Hunting (MDE)
mitre:
  - T1566.001 — Phishing: Spearphishing Attachment
  - T1204.002 — User Execution: Malicious File
  - T1027.002 — Obfuscated Files or Information: Software Packing
  - T1105 — Ingress Tool Transfer
tags:
  - "#detection/query"
  - "#detection"
  - "#endpoint"
  - "#email"
  - "#status/review"
status: review
---

# Executable Extracted from Internet-Sourced Archive

## Purpose

Detects high-risk file types written to disk following extraction from an archive (`.zip`, `.7z`, `.rar`) that originated from the internet. Covers browser-download extraction via Mark of the Web signals and direct extraction via known archive tool processes.

This is a high-signal detection for the initial access / execution phase — a user receiving a phishing attachment or downloading a malicious archive and extracting an executable is one of the most common initial access patterns.

---

## Schema

| Field | Source | Notes |
|---|---|---|
| `ActionType` | DeviceFileEvents | Filter to `FileCreated` — excludes renames and attribute changes |
| `FileName` | DeviceFileEvents | Filename only, no path |
| `FolderPath` | DeviceFileEvents | Full destination path |
| `FileOriginUrl` | DeviceFileEvents | URL the file was downloaded from; `about:internet` = MoTW zone 3 |
| `FileOriginReferrerUrl` | DeviceFileEvents | Referrer URL — populated when file extracted from a browser-downloaded archive |
| `InitiatingProcessFileName` | DeviceFileEvents | Process that wrote the file — archive tool name |
| `InitiatingProcessVersionInfoOriginalFileName` | DeviceFileEvents | Original filename from PE version info — more reliable than process name for renamed binaries |
| `SHA1` | DeviceFileEvents | Used for hash-based exclusions |
| `SHA256` | DeviceFileEvents | Projected for downstream enrichment / VirusTotal lookup |
| `IsTrusted` | DeviceFileCertificateInfo | 1 = trusted certificate chain |
| `Signer` | DeviceFileCertificateInfo | Signing entity name |

---

## Validated Columns

- [x] `ActionType` — confirmed values include `FileCreated`, `FileModified`, `FileRenamed`
- [x] `FileName` — filename only, no path component
- [x] `FolderPath` — full path to destination folder
- [x] `FileOriginUrl` — populated for browser downloads; `about:internet` is a valid MoTW signal
- [x] `FileOriginReferrerUrl` — populated when browser download referrer contains archive URL; may be empty for direct downloads
- [x] `InitiatingProcessFileName` — process name; can be spoofed — use alongside `VersionInfoOriginalFileName`
- [x] `InitiatingProcessVersionInfoOriginalFileName` — PE version info original name; more reliable for identifying renamed archive tools
- [x] `SHA1` — always populated on `FileCreated` events in MDE
- [x] `SHA256` — always populated; preferred for VirusTotal lookups
- [x] `IsTrusted` — boolean in `DeviceFileCertificateInfo`; not all files have certificate records — `leftanti` join handles this correctly
- [ ] `FileOriginReferrerUrl` for `.rar` archives — confirm this populates correctly in your environment; `.rar` referrer behaviour may differ by browser

> ⚠️ **`FileOriginReferrerUrl` is not always populated.** When a user downloads a zip directly (no referrer) and extracts with Explorer, neither `FileOriginReferrerUrl` nor an archive initiating process may be present. The `FileOriginUrl == "about:internet"` condition is your catch-all for this scenario — but see tuning notes on the noise trade-off.

---

## Query

```kql
// Executable Extracted from Internet-Sourced Archive
// Detects high-risk file types written to disk following extraction from a
// zip/archive that originated from the internet.
// Schema: DeviceFileEvents + DeviceFileCertificateInfo (Advanced Hunting / MDE)
// MITRE: T1566.001 Phishing: Spearphishing Attachment, T1204.002 User Execution: Malicious File

// --- Tunable parameters ---

let HighRiskExtensions = dynamic([
    ".exe", ".dll", ".ps1", ".cmd", ".bat",
    ".vbs", ".wsf", ".hta", ".lnk",
    ".iso", ".img", ".vhdx"
]);

// MDEClientAnalyzer tool — excluded by SHA1 (no hash available for FileOriginReferrerUrl)
// ⚠️ Review these hashes after any MDEClientAnalyzer tool update — hashes will change
let KnownMDEAnalyzerHashes = dynamic([
    "7cc17e965be903847a78830f15ea7cdbac21d4e9",  // MDELiveAnalyzerAppCompat.ps1
    "fd53c636108916fa67d3f60343c122c4616dace0",  // MDELiveAnalyzer.ps1
    "12c9463ac325bb0b265b77a795395d7ca06b2585",  // MDELiveAnalyzerNet.ps1
    "d6f6b8a5efbd9aa17c0c3a7a6487641707606ee6",  // MDELiveAnalyzerAV.ps1
    "6ba5bb5486d9b3679863d2c56dfb59b908767952",  // MDELiveAnalyzerVerbose.ps1
    "6800d81356adfd35e7b8c2bf740463d41cc9fe2d",  // MDEClientAnalyzer.cmd
    "3e94284d7157eaed1c42d327794777ebb2dee3a1",  // MDEClientAnalyzer.ps1
    "69d6505a444316b695ce4ef8f795de962c29bf75",  // DLPDiagnose.ps1
    "1a9fa41096756596ee8d59d237b4a2db81dc415b",  // RemoteMDEClientAnalyzer.cmd
    "a7da0e4365c1a94834a0a189f17ea0cf6abe1919",  // EULA.ps1
    "e0503fa3158bbad2e948e730bb775b08e74c0144",  // MDELiveAnalyzerPerf.ps1
    "898567396086be3f089c15926d941e7fa47b58f6",  // SysprepPreSteps(1).bat
    "1d0ca953c656fde51bd2f9c0bcceef587b3ec37d",  // Prepare-D365DevelopmentMachine.ps1
    "f0cd8253b7e64157d39a8dc5feb8cf7bda7e8dae"   // ScintillaNET.dll
]);

// Known-noisy filenames — prefer SHA1 or signer exclusions over filename exclusions
// Filename exclusions are fragile — a different version of the same tool has the same name
let ExcludedFileNames = dynamic([
    "chromedriver.exe",
    "RR.HardwareStation.Installer.exe",
    "RR.StoreCommerce.Installer.exe",
    "RR.ModernPos.Installer.exe",
    "RR.ScaleUnit.Installer.exe"
]);

// Archive extraction initiating processes
let ArchiveProcesses = dynamic([
    "7zg.exe",    // 7-Zip GUI
    "7z.exe",     // 7-Zip CLI
    "winrar.exe"  // WinRAR — remove if not used in environment
]);

// Trusted signers — files signed by these vendors are excluded via leftanti join
// Extend as needed; use exact signer strings from DeviceFileCertificateInfo
let TrustedSigners = dynamic([
    "Varonis Systems, Inc."
    // "Microsoft Corporation"
    // "Google LLC"
]);

// --- Main query ---

DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has_any (HighRiskExtensions)
| where FileName !in~ (ExcludedFileNames)
| where SHA1 !in (KnownMDEAnalyzerHashes)
| where (
    FileOriginReferrerUrl has_any (".zip", ".7z", ".rar")
    or FileOriginUrl == "about:internet"
    or InitiatingProcessVersionInfoOriginalFileName has_any (ArchiveProcesses)
    or InitiatingProcessFileName has_any (ArchiveProcesses)
)
| where FolderPath !startswith @"C:\$Recycle.Bin"
| where FolderPath !contains "LEAPWORK"
| where FolderPath !contains "Mobile_App.app"
| join kind=leftanti (
    DeviceFileCertificateInfo
    | where IsTrusted == 1
    | where Signer in (TrustedSigners)
) on SHA1
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    FileName,
    FolderPath,
    FileOriginUrl,
    FileOriginReferrerUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain,
    SHA1,
    SHA256,
    ActionType
| sort by TimeGenerated desc
```

---

## Refactoring Notes (from original query)

| Change | Reason |
|---|---|
| `let` blocks for all lists | Single place to add/remove entries — inline lists scattered through the query become unmaintainable |
| `ActionType == "FileCreated"` added | Original query matched all action types including renames and attribute changes — scope to new files only |
| `ArchiveProcesses` list extended | Original only caught `7zg.exe` (7-Zip GUI) — `7z.exe` CLI and `winrar.exe` were missed |
| `InitiatingProcessFileName` added alongside `VersionInfoOriginalFileName` | Some processes don't populate PE version info — matching both catches renamed binaries and processes with missing version data |
| `leftanti` join corrected | Original join logic was inverted — `leftanti` on `Signer !in (...)` returned files with no certificate record among non-Varonis signers, not files that are unsigned or untrusted. Corrected to exclude files that ARE signed by trusted signers |
| `TrustedSigners` as named `let` list | Extend signer exclusions without modifying join logic |
| `has_any` for extension matching | Replaces 11 `or FileName endswith` clauses — same logic, readable and maintainable |
| `project` added | Raw `DeviceFileEvents` returns ~40 columns — triage-relevant columns only in output |
| SHA1 exclusion list annotated | Each hash now has its corresponding filename as an inline comment |

---

## Tuning Notes

### `FileOriginUrl == "about:internet"` noise trade-off

This condition catches the MoTW (Mark of the Web) zone 3 signal — any file downloaded via a browser where no specific referrer is recorded. It is the correct signal for Explorer-extracted zips where no archive process name is present in `InitiatingProcessFileName`.

However, it will also match legitimate vendor software downloaded directly from a vendor site if the download had no referrer. If this generates noise, consider tightening the condition:

```kql
// Stricter: require archive process OR referrer-based signal; MoTW as secondary only
| where (
    FileOriginReferrerUrl has_any (".zip", ".7z", ".rar")
    or InitiatingProcessVersionInfoOriginalFileName has_any (ArchiveProcesses)
    or InitiatingProcessFileName has_any (ArchiveProcesses)
    or (FileOriginUrl == "about:internet" and InitiatingProcessFileName == "explorer.exe")
)
```

The last condition scopes MoTW hits to Explorer-initiated extractions only, reducing noise from direct browser downloads of executables.

### Extending `TrustedSigners`

Add signer strings exactly as they appear in `DeviceFileCertificateInfo`. To find the correct string for a known-noisy file:

```kql
DeviceFileCertificateInfo
| where FileName == "example.exe"
| project Signer, SignerHash, IsTrusted, IsRootSignerMicrosoft
```

### Filename exclusions are fragile

The `ExcludedFileNames` list excludes by name only — a malicious file named `chromedriver.exe` would be suppressed. Where possible, replace filename exclusions with SHA1 exclusions (version-specific) or signer exclusions (vendor-wide). Filename exclusions should be a last resort.

### `.lnk` files

`.lnk` (shortcut) files in archives are a known delivery mechanism (T1204.002). Keep in `HighRiskExtensions` — LNK-based phishing is active and relevant to your environment.

---

## Test Results

- [ ] Executed against production workspace — date: ___
- [ ] Baseline noise level confirmed acceptable
- [ ] `leftanti` join confirmed working — Varonis-signed files absent from results
- [ ] `7z.exe` CLI extraction confirmed detected
- [ ] `about:internet` condition reviewed for noise
- [ ] ExcludedFileNames list reviewed — SHA1/signer alternatives identified where possible

---

## Sentinel Analytics Rule

> ⚠️ This query runs against `DeviceFileEvents` (Advanced Hunting / MDE schema). To use as a Sentinel scheduled rule, the workspace must have the `DeviceFileEvents` and `DeviceFileCertificateInfo` tables available via the MDE connector.

| Setting | Value |
|---|---|
| **Rule name** | Executable Extracted from Internet-Sourced Archive |
| **Severity** | High |
| **Frequency** | Every 1 hour |
| **Lookback** | 1 hour |
| **Suppression** | None — each unique file+device combination should alert |
| **Entity mapping** | Account → `InitiatingProcessAccountName`; Host → `DeviceName`; File → `FileName`; FileHash → `SHA256` |
| **Custom detail** | `FileName`, `FolderPath`, `FileOriginUrl`, `FileOriginReferrerUrl`, `InitiatingProcessFileName`, `SHA256` |
| **Alert threshold** | > 0 results |

---

## Triage Steps

1. **Check SHA256 against VirusTotal** — first and fastest signal; known-bad hash closes the investigation quickly
2. **Check `FileOriginUrl` and `FileOriginReferrerUrl`** — identifies where the archive came from; correlate with MDO email delivery if the URL looks like a file host
3. **Check `InitiatingProcessFileName`** — confirms extraction method; `explorer.exe` = user double-clicked; `7z.exe` in a script context is higher risk
4. **Check `InitiatingProcessAccountName`** — service account extracting an archive from the internet is immediately suspicious
5. **Check `FolderPath`** — extraction to `%TEMP%`, `%APPDATA%`, or a user's Downloads folder is normal; extraction to `C:\Windows\`, `C:\ProgramData\`, or a system path is a strong IOC
6. **Correlate process execution** — pivot to `DeviceProcessEvents` on `DeviceName` + `TimeGenerated` to see if the extracted file was subsequently executed

---

## Related Notes

- [[KQL-Keepass-Archive-File-Access]] — file access detection
- [[KQL-Anomalous-Process-Execution-4688]] — downstream execution detection

---

## Tags

`#detection/query` `#detection` `#endpoint` `#email` `#status/review`

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2026-04-28 | Dave | Initial note. Refactored from original query — corrected leftanti join logic, extended archive process list, added ActionType filter, moved all lists to let blocks, added project. Documented refactoring changes, tuning notes, and triage steps. |
