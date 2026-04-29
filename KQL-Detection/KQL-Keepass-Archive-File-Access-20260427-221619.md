---
title: KeePass Archive — Sensitive File Access Detection
date: 2026-04-27
table: SecurityEvent
schema: Log Analytics (Sentinel)
mitre:
  - T1555.005 — Credentials from Password Stores: Password Managers
  - T1083 — File and Directory Discovery
  - T1070.004 — Indicator Removal: File Deletion
tags:
  - "#detection/query"
  - "#detection"
  - "#endpoint"
  - "#identity"
  - "#status/review"
status: review
---

# KeePass Archive — Sensitive File Access Detection

## Purpose

Detects any access to `.kdbx` (KeePass database) and `.key` (KeePass key file) files stored on the decommissioned KeePass fileshare archive on `cgyfs201`. KeePass has been decommissioned — **no legitimate business access to these files should occur post-decommission.** Any hit should be treated as suspicious until proven otherwise.

Covers read, write, append, delete, attribute write, and metadata operations. Access is bucketed by sensitivity to support fast triage.

---

## Schema

| Field | Source | Notes |
|---|---|---|
| `EventID` | SecurityEvent | 4663 = An attempt was made to access an object |
| `Computer` | SecurityEvent | Hostname of the file server |
| `Account` | SecurityEvent | `DOMAIN\username` format |
| `SubjectDomainName` | SecurityEvent | Domain context for the account |
| `ObjectName` | SecurityEvent | Full path including device volume |
| `AccessMask` | SecurityEvent | Hex bitmask — decoded inline by query |
| `ProcessName` | SecurityEvent | Process making the access — critical for triage |

---

## Validated Columns

- [x] `EventID` — standard SecurityEvent field
- [x] `Computer` — populated on all 4663 events
- [x] `Account` — format is `DOMAIN\user`; use `SubjectDomainName` for domain split
- [x] `ObjectName` — full device path; confirm `HarddiskVolume13` matches current volume assignment on cgyfs201
- [x] `AccessMask` — hex string; decoded via `case()` in query
- [x] `ProcessName` — available on 4663; may be empty for some legacy audit events — flag if blank
- [ ] `SubjectLogonId` — available but not projected; add if correlating to logon session
- [ ] `HandleId` — available; useful for correlating open/close/access event chains

> ⚠️ **Volume number validation required:** Confirm `\Device\HarddiskVolume13` is still the correct volume mapping on `cgyfs201`. Volume numbers can change after reboots or disk changes. Validate with: `fsutil volume diskfree C:` or check via `wmic logicaldisk` on the server.

---

## Query

```kql
// KeePass Archive — Sensitive File Access Detection
// Detects read, write, delete, and attribute operations against .kdbx and .key files
// Schema: SecurityEvent (Log Analytics / Sentinel)
// Tuning: Add known service accounts to ExcludedAccounts below

let SensitiveExtensions = dynamic([".kdbx", ".key"]);
let SensitivePath = @"\Device\HarddiskVolume13\Keepass_Archive";
let ExcludedAccounts = dynamic(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]);
// Add backup/AV service accounts: e.g., "svc-backup", "svc-defender"

SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4663
| where Computer contains "cgyfs201"
| where ObjectName startswith SensitivePath
| where ObjectName has_any (SensitiveExtensions)
| where Account !in~ (ExcludedAccounts)
| extend AccessType = case(
    AccessMask == "0x1",      "ReadData",
    AccessMask == "0x2",      "WriteData",
    AccessMask == "0x4",      "AppendData",
    AccessMask == "0x20",     "Execute",
    AccessMask == "0x40",     "WriteAttributes",
    AccessMask == "0x80",     "ReadAttributes",
    AccessMask == "0x100000", "Synchronize",
    AccessMask == "0x10000",  "DELETE",
    AccessMask == "0x20000",  "ReadControl",
    AccessMask == "0x40000",  "WriteDAC",
    AccessMask == "0x80000",  "WriteOwner",
    strcat("UnknownMask:", AccessMask)
    )
| extend Sensitivity = case(
    AccessMask in ("0x10000"),              "HIGH — Deletion",
    AccessMask in ("0x2", "0x4", "0x40"),  "HIGH — Write/Modify",
    AccessMask in ("0x1", "0x80"),          "MEDIUM — Read",
    "LOW — Metadata"
    )
| extend FileType = case(
    ObjectName endswith ".kdbx", "KeePass Database",
    ObjectName endswith ".key",  "KeePass Key File",
    "Unknown"
    )
| project
    TimeGenerated,
    Computer,
    Account,
    SubjectDomainName,
    ObjectName,
    FileType,
    AccessType,
    AccessMask,
    Sensitivity,
    ProcessName
| sort by TimeGenerated desc
```

---

## AccessMask Reference

| Mask | Operation | Sensitivity |
|------|-----------|-------------|
| `0x1` | ReadData | MEDIUM |
| `0x2` | WriteData | HIGH |
| `0x4` | AppendData | HIGH |
| `0x20` | Execute | HIGH |
| `0x40` | WriteAttributes | HIGH |
| `0x80` | ReadAttributes | MEDIUM |
| `0x10000` | DELETE | HIGH |
| `0x20000` | ReadControl | LOW |
| `0x40000` | WriteDAC | HIGH |
| `0x80000` | WriteOwner | HIGH |
| `0x100000` | Synchronize | LOW |

> Note: AccessMask values can be combined (bitwise OR). The `case()` above handles single-mask values. If you see compound masks (e.g., `0x120089`), consider adding a `binary_and()` decode or a secondary lookup table.

---

## Test Results

- [ ] Executed against production workspace — date: ___
- [ ] Baseline noise level confirmed acceptable
- [ ] ExcludedAccounts list validated against known service accounts on cgyfs201
- [ ] Volume number `HarddiskVolume13` confirmed correct
- [ ] HIGH sensitivity hits reviewed — confirmed no false positives

---

## Sentinel Analytics Rule

| Setting | Value |
|---|---|
| **Rule name** | KeePass Archive — Sensitive File Access |
| **Severity** | High |
| **Frequency** | Every 5 minutes |
| **Lookback** | 1 hour |
| **Suppression** | None — all hits should alert |
| **Entity mapping** | Account → Account; Computer → Host; ObjectName → File |
| **Custom detail** | `AccessType`, `Sensitivity`, `ProcessName`, `FileType` |
| **Alert threshold** | > 0 results |

> **Recommended:** Consider splitting into two rules:
> - **Rule A — Write/Delete** (AccessMask in write/delete set): Severity High, alert immediately, no aggregation
> - **Rule B — Read** (AccessMask `0x1`, `0x80`): Severity Medium, aggregate over 15 min window, alert if > 3 unique files or > 1 unique account

---

## Triage Notes

When this fires:

1. **Identify the account** — Is it a service account, admin, or user account? Check `SubjectDomainName`.
2. **Check ProcessName** — `explorer.exe` or `cmd.exe` is human-driven. A backup agent or AV process is likely benign. An unexpected process (e.g., `powershell.exe`, `robocopy.exe`, `7z.exe`) is a strong IOC.
3. **Check timing** — After-hours access from a user account to a decommissioned share is immediately suspicious.
4. **Correlate logon** — Use `SubjectLogonId` to pull the associated logon event (4624) and confirm source IP / logon type.
5. **HIGH — Deletion hits** — Treat as potential evidence destruction. Preserve snapshot of fileshare immediately.

---

## Hardening Control Pair

- [ ] Confirm NTFS auditing is correctly configured on `\Keepass_Archive` folder (Object Access auditing enabled, Success + Failure)
- [ ] Confirm SMB share permissions restrict access — ideally no accounts should have active permissions post-decommission
- [ ] Consider moving `.kdbx` and `.key` files to an offline cold archive if they must be retained for compliance
- [ ] Review who currently has share-level read access to the KeePass fileshare

---

## Related Notes

- [[HARD-SMB-Signing]] — SMB hardening controls
- [[HARD-NTLM-Enforcement]] — NTLMv2 enforcement
- [[KQL-FileShare-Sensitive-Access]] — Generic fileshare access detection (if exists)

---

## Tags

`#detection/query` `#detection` `#endpoint` `#identity` `#status/review`

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2026-04-27 | Dave | Initial note — improved from original query. Added write/delete/attribute masks, AccessType decode, Sensitivity bucketing, FileType column, service account exclusion list, ProcessName projection. |
