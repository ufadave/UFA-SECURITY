---
title: "Gap Analysis Hunt — T1078 / T1569 / T1105"
date: 2026-04-26
analyst: Dave
status: active
schema: Advanced Hunting (MDE)
mitre:
  - T1078 — Valid Accounts
  - T1569 — System Services
  - T1105 — Ingress Tool Transfer
tags:
  - #hunt
  - #detection
  - #endpoint
  - #identity
  - #status/active
---

# Hunt — Gap Analysis: T1078 / T1569 / T1105

**Date:** 2026-04-26
**Analyst:** Dave
**Schema:** Advanced Hunting (MDE)
**Scope:** All onboarded endpoints — Alberta, BC, Saskatchewan fleet (~150 devices) + POS terminals. OT/SCADA assets excluded pending onboarding confirmation.

---

## Gap Analysis Framework

Repeatable workflow applied to each technique below:

```
1. VALIDATE    → Does the telemetry exist? (table, ActionType, fields present)
2. BASELINE    → What does normal look like? (volume, top processes, top devices)
3. SIGNAL TEST → Run detection query, assess raw hit count
4. TUNE        → Suppress known-good, tighten scope
5. PROMOTE?    → Custom Detection Rule / Hunting Query / Backlog
```

---

## T1078 — Valid Accounts (Suspicious Sign-In Patterns)

**Tactic:** Credential Access, Persistence, Privilege Escalation, Defence Evasion
**Table:** `IdentityLogonEvents`
**Relevance:** Entra Connect SyncJacking exposure, service principal abuse (CVE patched Apr 9 2026), infostealer credential leak risk, Iranian APT targeting identity layer.

### Step 1 — Validate telemetry

```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| summarize EventCount = count() by ActionType
| sort by EventCount desc
```

**Telemetry validation:**
- [ ] `IdentityLogonEvents` returns rows — DfI sensors on domain controllers confirmed
- [ ] `LogonSuccess` ActionType present
- [ ] `IPAddress` field populated (not null/empty)
- [ ] `AccountUpn` field populated
- [ ] `DeviceName` field populated

> **Schema note:** If this returns zero rows, check Defender for Identity sensor coverage on all domain controllers. No DfI sensor = no `IdentityLogonEvents` data.

---

### Step 2 — Baseline: normal logon behaviour

```kql
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| summarize
    TotalLogons      = count(),
    UniqueSources    = dcount(IPAddress),
    UniqueDevices    = dcount(DeviceName),
    UniqueAccounts   = dcount(AccountName)
    by bin(Timestamp, 1d)
| sort by Timestamp desc
```

**Baseline notes (populate after running):**
- Daily logon volume avg: `___`
- Spike threshold (>X% day-over-day): `___`
- Top noise sources identified: `___`

---

### Step 3 — Detection: logon from new/rare source IP

```kql
// Baseline: 30-day known source IPs per account
let BaselinePeriod = 30d;
let DetectionWindow = 1d;

let KnownSourceIPs = IdentityLogonEvents
| where Timestamp between (ago(BaselinePeriod) .. ago(DetectionWindow))
| where ActionType == "LogonSuccess"
| summarize KnownIPs = make_set(IPAddress) by AccountUpn;

// Detection: logons from IPs not seen in baseline
IdentityLogonEvents
| where Timestamp > ago(DetectionWindow)
| where ActionType == "LogonSuccess"
| where isnotempty(AccountUpn)
| join kind=leftanti KnownSourceIPs on AccountUpn, $left.IPAddress == $right.KnownIPs
| project
    Timestamp,
    AccountUpn,
    AccountDomain,
    DeviceName,
    IPAddress,
    LogonType,
    Protocol,
    ReportId
| sort by Timestamp desc
```

> `leftanti` join surfaces accounts authenticating from an IP not seen in the prior 30 days. Self-tuning as baseline grows — no hardcoded IP lists required.

---

### Step 4 — Noise reduction

Add inside the detection window block before the join if hit count is high:

```kql
| where IPAddress !startswith "10."
| where IPAddress !startswith "192.168."
| where IPAddress !startswith "172.16."
| where LogonType != "Network"
| where AccountUpn !endswith "svc@yourdomain.ca"  // suppress known service accounts
```

---

### Gap Analysis Verdict — T1078

| Dimension | Assessment |
|---|---|
| **Telemetry present?** | Confirm with Step 1 — requires DfI sensors on all DCs |
| **Signal volume** | Medium-high raw; `leftanti` join self-tunes as baseline matures |
| **Primary noise source** | VPN IP rotation, travel, cloud service logons, service accounts |
| **Promotable as-is?** | ⚠️ Tune first — needs service account exclusions + RFC1918 suppression |
| **Recommended action** | Run Step 2 for 7 days. Capture top 10 noise sources. Suppress. Then promote. |
| **Sentinel rule recommendation** | Frequency: 1h \| Lookback: 1d \| Severity: Medium |

**Sentinel Analytics Rule Settings:**
- Query frequency: `1h`
- Query period: `1d`
- Alert threshold: `> 0`
- Severity: `Medium`
- Tactics: `CredentialAccess`, `Persistence`

---

---

## T1569 — System Services (Malicious Service Installation)

**Tactic:** Execution, Persistence
**Table:** `DeviceEvents`
**Relevance:** Classic persistence mechanism. High signal value on a locked-down fleet — unexpected service installs outside Intune/SCCM deployment windows are immediately suspicious. Relevant to ransomware pre-staging and Iranian APT tooling.

### Step 1 — Validate telemetry

```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("ServiceInstalled", "DriverLoad")
| summarize EventCount = count() by ActionType
```

**Telemetry validation:**
- [ ] `DeviceEvents` returns rows for `ServiceInstalled`
- [ ] `AdditionalFields` is populated (not empty JSON)
- [ ] `AdditionalFields.ServiceName` parseable via `tostring()`
- [ ] `AdditionalFields.ServiceImagePath` parseable
- [ ] `AdditionalFields.ServiceAccount` parseable
- [ ] `AdditionalFields.ServiceStartType` parseable
- [ ] `InitiatingProcessFileName` populated

> **Schema note:** `ServiceInstalled` is generated by the MDE sensor directly — not via ETW. Zero rows = device not fully onboarded or sensor gap. Check onboarding status for POS terminals specifically.

---

### Step 2 — Baseline: who installs services normally?

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ServiceInstalled"
| extend ServiceName      = tostring(AdditionalFields.ServiceName)
| extend ServiceImagePath = tostring(AdditionalFields.ServiceImagePath)
| extend ServiceType      = tostring(AdditionalFields.ServiceType)
| extend ServiceAccount   = tostring(AdditionalFields.ServiceAccount)
| summarize
    InstallCount  = count(),
    UniqueDevices = dcount(DeviceId)
    by ServiceName, ServiceImagePath, InitiatingProcessFileName
| sort by InstallCount desc
| take 30
```

**Baseline notes (populate after running):**
- Top installers in environment: `___`
- Legitimate Intune/SCCM service names to allowlist: `___`
- Unexpected entries at Step 2: `___`

---

### Step 3 — Detection: service installed from suspicious path or unexpected process

```kql
let AllowedInstallers = dynamic([
    "msiexec.exe",
    "trustedinstaller.exe",
    "svchost.exe",
    "ccmexec.exe",                        // SCCM
    "intunemanagementextension.exe"        // Intune MDM
]);

let SuspiciousPaths = dynamic([
    "\\temp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "\\windows\\tasks\\", "\\recycle"
]);

DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ServiceInstalled"
| extend ServiceName      = tostring(AdditionalFields.ServiceName)
| extend ServiceImagePath = tolower(tostring(AdditionalFields.ServiceImagePath))
| extend ServiceAccount   = tostring(AdditionalFields.ServiceAccount)
| extend ServiceStartType = tostring(AdditionalFields.ServiceStartType)
| where InitiatingProcessFileName !in~ (AllowedInstallers)
    or ServiceImagePath has_any (SuspiciousPaths)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ServiceName,
    ServiceImagePath,
    ServiceAccount,
    ServiceStartType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| sort by Timestamp desc
```

---

### Step 4 — Pivot: correlate with process creation post-install

Run this after a hit to answer "did the service binary execute and what did it spawn?":

```kql
let TargetDevice = "<DeviceId from above>";
let ServiceInstallTime = datetime(2026-01-01T00:00:00Z); // replace with hit timestamp

DeviceProcessEvents
| where DeviceId == TargetDevice
| where Timestamp between ((ServiceInstallTime - 5m) .. (ServiceInstallTime + 15m))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

---

### Gap Analysis Verdict — T1569

| Dimension | Assessment |
|---|---|
| **Telemetry present?** | High confidence on fully onboarded MDE devices — gaps on POS/legacy |
| **Signal volume** | Low-medium — service installs are infrequent events |
| **Primary noise source** | Intune, SCCM, Windows Update, AV/EDR agents |
| **Promotable as-is?** | ✅ Yes — after populating `AllowedInstallers` from Step 2 baseline |
| **Recommended action** | Run Step 2 over 7 days. Build allowlist. Promote with 1h cadence. |
| **Sentinel rule recommendation** | Frequency: 1h \| Lookback: 1d \| Severity: High |

**Sentinel Analytics Rule Settings:**
- Query frequency: `1h`
- Query period: `1d`
- Alert threshold: `> 0`
- Severity: `High`
- Tactics: `Execution`, `Persistence`

---

---

## T1105 — Ingress Tool Transfer (LOLBin File Writes)

**Tactic:** Command and Control
**Tables:** `DeviceFileEvents`, `DeviceNetworkEvents`
**Relevance:** Attacker stages tools using built-in Windows binaries to avoid EDR detection. Highly relevant given infostealer risk, ransomware pre-staging patterns, and Iranian APT tooling methodology. POS terminals are a priority scope.

### Step 1 — Validate telemetry

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has_any (
    "bitsadmin.exe", "certutil.exe", "curl.exe",
    "mshta.exe", "powershell.exe", "pwsh.exe"
)
| summarize EventCount = count() by InitiatingProcessFileName, ActionType
| sort by EventCount desc
```

**Telemetry validation:**
- [ ] `DeviceFileEvents` returns rows for listed LOLBins
- [ ] `ActionType` == `FileCreated` present
- [ ] `FolderPath` populated
- [ ] `FileName` populated
- [ ] `InitiatingProcessFileName` populated
- [ ] `InitiatingProcessCommandLine` populated
- [ ] `InitiatingProcessParentFileName` populated
- [ ] `SHA256` populated
- [ ] `RemoteIPType` in `DeviceNetworkEvents` available for correlation

> **Schema note:** If `powershell.exe` rows are absent entirely, verify Script Block Logging is enabled on endpoints and MDE file creation telemetry is active.

---

### Step 2 — Baseline: legitimate LOLBin file writes

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has_any (
    "bitsadmin.exe", "certutil.exe", "curl.exe",
    "mshta.exe", "powershell.exe", "pwsh.exe", "wscript.exe"
)
| summarize
    WriteCount    = count(),
    UniqueDevices = dcount(DeviceId),
    ExamplePaths  = make_set(FolderPath, 5)
    by InitiatingProcessFileName
| sort by WriteCount desc
```

**Baseline notes (populate after running):**
- PowerShell write volume (expected to dominate): `___`
- Legitimate write paths to exclude: `___`
- certutil.exe / bitsadmin.exe baseline volume: `___`

---

### Step 3 — Detection: LOLBin writes executable to user-writable path

```kql
let LOLBins = dynamic([
    "bitsadmin.exe", "certutil.exe", "curl.exe", "wget.exe",
    "mshta.exe",     "powershell.exe", "pwsh.exe",
    "wscript.exe",   "cscript.exe",   "rundll32.exe"
]);

let SuspiciousExtensions = dynamic([
    ".exe", ".dll", ".ps1", ".bat", ".cmd",
    ".vbs", ".js",  ".hta", ".msi", ".lnk"
]);

let SuspiciousWritePaths = dynamic([
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\programdata\\",
    "\\windows\\tasks\\", "\\recycle.bin\\"
]);

DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has_any (LOLBins)
| extend FileExtension = tolower(tostring(extract(@"(\.[^.\\]+)$", 1, FileName)))
| extend FolderLower   = tolower(FolderPath)
| where FileExtension in (SuspiciousExtensions)
| where FolderLower has_any (SuspiciousWritePaths)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FileName,
    FolderPath,
    FileExtension,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    ReportId
| sort by Timestamp desc
```

---

### Step 4 — Enriched version: correlate file write with network connection (Custom Detection candidate)

```kql
let ToolTransferHits = DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has_any (
    "bitsadmin.exe","certutil.exe","curl.exe",
    "powershell.exe","pwsh.exe"
)
| extend FolderLower = tolower(FolderPath)
| where FolderLower has_any ("\\temp\\","\\appdata\\","\\users\\public\\")
| project DeviceId, FileTimestamp = Timestamp, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId;

ToolTransferHits
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType != "Loopback"
    | project DeviceId, NetTimestamp = Timestamp, RemoteIP, RemotePort, RemoteUrl
) on DeviceId
| where abs(datetime_diff('minute', FileTimestamp, NetTimestamp)) <= 5
| project
    FileTimestamp,
    DeviceId,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    ReportId
| sort by FileTimestamp desc
```

> Multi-signal correlation (file write + network connection within 5 min on same device) is significantly higher confidence than either event alone. This is the Custom Detection Rule candidate.

---

### Gap Analysis Verdict — T1105

| Dimension | Assessment |
|---|---|
| **Telemetry present?** | High on onboarded MDE devices — verify POS terminal coverage |
| **Signal volume** | Medium — PowerShell noise is the primary challenge |
| **Primary noise source** | Legitimate PowerShell writes, software deployment, update tooling |
| **Promotable as-is?** | ✅ Promote the correlated Step 4 version — higher fidelity |
| **Recommended action** | Tighten write paths from Step 2 baseline. Promote network-correlated version. |
| **Sentinel rule recommendation** | Frequency: 1h \| Lookback: 1d \| Severity: High |

**Sentinel Analytics Rule Settings:**
- Query frequency: `1h`
- Query period: `1d`
- Alert threshold: `> 0`
- Severity: `High`
- Tactics: `CommandAndControl`

---

---

## Consolidated Promotion Decision Matrix

| Technique | Table(s) | Telemetry Confidence | Noise Level | Tuning Required | Promote? |
|---|---|---|---|---|---|
| **T1078** Valid Accounts | `IdentityLogonEvents` | Medium — requires DfI sensors on all DCs | High raw, self-tunes with leftanti baseline | Service account suppression, RFC1918 exclusion | ⚠️ Tune first |
| **T1569** System Services | `DeviceEvents` | High on MDE-onboarded devices | Low | Populate installer allowlist from Step 2 | ✅ Ready after allowlist |
| **T1105** Ingress Tool Transfer | `DeviceFileEvents` + `DeviceNetworkEvents` | High | Medium (PowerShell noise) | Tighten write paths, use network-correlated version | ✅ Promote correlated version |

---

## Reusable Gap Analysis Template

Paste as a comment header on any new hunting query:

```kql
// ============================================================
// TECHNIQUE   : T1XXX — Name
// TACTIC      : Execution / Persistence / etc.
// TABLE(S)    : DeviceProcessEvents, DeviceNetworkEvents, etc.
// ============================================================
// TELEMETRY VALIDATED : [ ] Yes  [ ] No  [ ] Partial
// BASELINE RUN        : [ ] Yes  [ ] No  Date: YYYY-MM-DD
// RAW HIT COUNT (1d)  : ___
// PRIMARY NOISE SRC   : ___
// TUNING APPLIED      : ___
// PROMOTION STATUS    : [ ] Custom Detection  [ ] Hunting  [ ] Backlog
// REVIEW DATE         : YYYY-MM-DD
// ============================================================
```

---

## Related Notes

- [[KQL-T1078-ValidAccounts-NewSourceIP]] — standalone query note when promoted
- [[KQL-T1569-ServiceInstalled-SuspiciousPath]] — standalone query note when promoted
- [[KQL-T1105-LOLBin-FileWrite-NetworkCorrelated]] — standalone query note when promoted
- [[PROJ-M365-Hardening]] — Entra Connect SyncJacking and CA policy gaps
- [[INTEL-Handala-CL-STA-1128]] — Iranian APT context

---

## Changelog

| Date | Change |
|---|---|
| 2026-04-26 | Initial note created — gap analysis from Blu Raven workflow exercise |
