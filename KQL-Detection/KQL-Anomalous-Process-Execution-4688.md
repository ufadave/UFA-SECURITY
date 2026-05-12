---
title: Anomalous Process Execution — 4688 Time-Series Anomaly Detection
date: 2026-04-27
table: SecurityEvent
schema: Log Analytics (Sentinel)
source: Microsoft Content Hub (modified — noise reduction)
mitre:
  - T1059 — Command and Scripting Interpreter
  - T1047 — Windows Management Instrumentation
  - T1218.011 — Signed Binary Proxy Execution: Rundll32
  - T1569.002 — System Services: Service Execution (psexec)
tags:
  - "#detection/query"
  - "#detection"
  - "#endpoint"
  - status: promoted
  - promoted_to_rule: true
  - "#status/deployed"
status: deployed
---

# Anomalous Process Execution — 4688 Time-Series Anomaly Detection

## Purpose

Detects statistically anomalous spikes in execution of high-risk process names using time-series decomposition (`series_decompose_anomalies`). Baseline is built over 14 days and deviations above threshold trigger alerts.

Modified from the Microsoft Content Hub version to significantly reduce false positives driven by:
- Windows machine account scheduled tasks (`MACHINE$` accounts running rundll32)
- Known-benign `rundll32.exe` invocation patterns (COM surrogates, UWP app rendering, maintenance tasks)
- AVD pool spin-up and OS maintenance activity

---

## Analyst Assessment

> **Verdict: Low value as a scheduled analytics rule. Retain as a manual hunting query scoped to rare processes only.**

**What this query is actually doing:**

This is a fleet-level macro signal detector. It builds a 14-day hourly baseline of how often each process runs across the estate, then flags hours where the count spikes significantly above normal. The intended scenario is something coordinated running at scale — a worm spreading, a mass RAT deployment, a ransomware precursor running lateral movement scripts simultaneously across many machines.

**Why the approach is flawed for this environment:**

The signal it's chasing is dominated by legitimate IT activity before it's ever explained by an attacker:

- **AVD pools** spin up and down together, generating correlated bursts of `rundll32.exe` across many machines simultaneously — exactly what this query flags
- **Patch Tuesday and Intune deployments** spike `cmd.exe` and `powershell.exe` on a schedule; when cycle timing shifts the baseline breaks
- **Fleet-wide scheduled tasks** running at the same hour will always look anomalous on first run after a change

More fundamentally — a capable attacker will not generate a volume spike. They run one or two instances on a handful of machines, carefully. The scenario where this query fires on a true positive is narrow: something automated, poorly opsec'd, and running at scale simultaneously. That's worm behaviour, not targeted intrusion.

Layering suppressions (machine accounts, CommandLine allowlists, score floors) compensates for the weak core signal but creates a growing maintenance burden that decays as the environment changes. It still won't catch low-and-slow activity.

**Where it does have genuine value:**

Narrowing `ExeList` to processes that should run at near-zero volume in this environment changes the calculus entirely. A spike from 0 to 15 on `psexec.exe` across the estate in one hour is meaningful — the anomaly math works when the expected baseline is flat. The problem is combining those with `powershell.exe`, `cmd.exe`, and `rundll32.exe`, which run constantly and will perpetually generate noise.

**Recommended disposition:**

| Process | Recommended Use |
|---|---|
| `psexec.exe` | Keep in time-series — baseline should be near zero; spikes are meaningful |
| `cacls.exe` | Keep in time-series — rare in normal operation |
| `wmic.exe` | Keep — relatively rare; spikes worth investigating |
| `powershell.exe` | Remove from this query — always noisy; detect via CommandLine content instead |
| `cmd.exe` | Remove — too high volume; detect via parent-child anomalies instead |
| `rundll32.exe` | Remove — OS generates constant legitimate volume; detect via suspicious DLL/export patterns instead |

**Higher-value detection approaches for the same threat space:**

- **Parent-child anomalies** — `rundll32.exe` spawned by `winword.exe`, `powershell.exe` spawned by `msiexec.exe`; malicious regardless of volume
- **CommandLine content** — encoded PowerShell (`-enc`), `IEX`, `DownloadString`, `FromBase64String`; high-fidelity signal regardless of count
- **First-seen LOLBin** — a process executing from a path or with a CommandLine never seen before in the estate
- **User context anomalies** — `wmic.exe` running under a service account that has never run it, or on a machine where it has no history

---

## Noise Analysis (Original Query)

All noise observed in testing originated from `rundll32.exe` with the following characteristics:

| Pattern | Root Cause | Action |
|---|---|---|
| `shell32.dll,SHCreateLocalServerRunDll {GUID} -Embedding` | COM surrogate/shell extension hosting | Excluded |
| `EDGEHTML.dll,#141 <AppPackage>` | Edge/UWP rendering init | Excluded |
| `AppXDeploymentExtensions.OneCore.dll,ShellRefresh` | App deployment refresh | Excluded |
| `-localserver <GUID>` | COM local server activation | Excluded |
| `sysmain.dll,PfSvWsSwapAssessmentTask` | Superfetch scheduled task | Excluded |
| `CapabilityAccessManager.dll,CapabilityAccessManagerDoStoreMaintenance` | Privacy store maintenance | Excluded |
| `Windows.StateRepositoryClient.dll,StateRepositoryDoMaintenanceTasks` | App state maintenance | Excluded |
| `Windows.Storage.ApplicationData.dll,CleanupTemporaryState` | Temp state cleanup | Excluded |
| `Startupscan.dll,SusRunTask` | Startup scan task | Excluded |
| `davclnt.dll,DavSetCookie` | WebDAV/Azure Files cookie auth | Excluded |

**Primary noise driver:** All hits ran under `AccountType == "Machine"` (`MACHINE$` accounts). Legitimate attacker use of these processes almost always runs under a user context. Filtering on AccountType alone eliminates the majority of noise.

---

## Query

```kql
// Anomalous Process Execution — 4688 Time-Series
// Modified from Microsoft Content Hub — added machine account exclusion and CommandLine allowlist
// Schema: SecurityEvent (Log Analytics / Sentinel)

let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 5;
let AnomalyScoreThreshold = 3.0; // Raise to 5+ if still noisy; original was 1.5

// Processes of interest
let ExeList = dynamic([
    "powershell.exe", "cmd.exe", "wmic.exe",
    "psexec.exe", "cacls.exe", "rundll32.exe"
]);

// Known-benign rundll32 CommandLine patterns — extend as needed
let BenignRundll32Patterns = dynamic([
    "SHCreateLocalServerRunDll",           // COM surrogate shell extension hosting
    "EDGEHTML.dll",                        // Edge/UWP rendering component init
    "AppXDeploymentExtensions",            // App deployment refresh
    "PfSvWsSwapAssessmentTask",            // Superfetch/SysMain task
    "CapabilityAccessManagerDoStoreMaintenance", // Privacy store maintenance
    "StateRepositoryDoMaintenanceTasks",   // App state maintenance
    "CleanupTemporaryState",               // Storage temp cleanup
    "SusRunTask",                          // Startup scan task
    "davclnt.dll,DavSetCookie",            // WebDAV / Azure Files cookie auth
    "ShellRefresh"                         // AppX deployment shell refresh
]);

let TimeSeriesData =
SecurityEvent
| where EventID == 4688
| extend Process = tolower(Process)
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where Process in~ (ExeList)
// --- NOISE FILTER 1: Exclude machine accounts (scheduled tasks, OS maintenance) ---
| where AccountType != "Machine"
// --- NOISE FILTER 2: Exclude known-benign rundll32 CommandLine patterns ---
| where not (Process == "rundll32.exe" and CommandLine has_any (BenignRundll32Patterns))
// --- NOISE FILTER 3: Exclude empty CommandLine for rundll32 (often maintenance) ---
// Comment out if you want visibility into rundll32 with no commandline args
| where not (Process == "rundll32.exe" and isempty(CommandLine))
| project TimeGenerated, Computer, AccountType, Account, Process
| make-series Total=count() on TimeGenerated
    from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe
    by Process;

let TimeSeriesAlerts = materialize(TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 1.5, -1, 'linefit')
| mv-expand Total to typeof(double), TimeGenerated to typeof(datetime),
             anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where anomalies > 0
| project Process, TimeGenerated, Total, baseline, anomalies, score
| where Total > TotalEventsThreshold
// --- NOISE FILTER 4: Raise score floor to reduce marginal anomalies ---
| where score > AnomalyScoreThreshold
);

let AnomalyHours = materialize(TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| project TimeGenerated);

TimeSeriesAlerts
| where TimeGenerated > ago(2d)
| join (
    SecurityEvent
    | where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
    | extend DateHour = bin(TimeGenerated, 1h)
    | where DateHour in ((AnomalyHours))
    | where EventID == 4688
    | extend Process = tolower(Process)
    // Re-apply same filters in the join leg for consistency
    | where AccountType != "Machine"
    | where not (Process == "rundll32.exe" and CommandLine has_any (BenignRundll32Patterns))
    | where not (Process == "rundll32.exe" and isempty(CommandLine))
    | summarize CommandlineCount = count()
        by bin(TimeGenerated, 1h), Process, CommandLine, Computer, Account
) on Process, TimeGenerated
| project
    AnomalyHour   = TimeGenerated,
    Computer,
    Account,
    Process,
    CommandLine,
    CommandlineCount,
    Total,
    baseline,
    anomalies,
    score
| extend
    timestamp      = AnomalyHour,
    NTDomain       = split(Account, '\\', 0)[0],
    Name           = split(Account, '\\', 1)[0],
    HostName       = tostring(split(Computer, '.', 0)[0]),
    DnsDomain      = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
| sort by score desc, AnomalyHour desc
```

---

## Validated Columns

- [x] `EventID` — 4688 is Process Creation; requires audit policy enabled
- [x] `Process` — process name only (not full path); use `NewProcessName` if full path needed
- [x] `AccountType` — values: `"User"`, `"Machine"`, `"Well Known Group"` — filter on `"Machine"` to exclude computer accounts
- [x] `CommandLine` — requires **"Include command line in process creation events"** audit policy enabled; may be blank if policy not set
- [x] `Account` — `DOMAIN\user` format
- [ ] `NewProcessName` — full path; not projected here but available if you need parent/child path correlation
- [ ] `ParentProcessName` — available in 4688 but not used; high-value addition for detecting unusual parent-child relationships

> ⚠️ **CommandLine audit policy:** If `CommandLine` is blank for most events, verify Group Policy: `Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled`

---

## Tuning Notes

### If still noisy after these changes:

**Option A — Score floor:** Raise `AnomalyScoreThreshold` from `3.0` to `5.0` or `7.0`. The original query used `1.5` (very sensitive). Your benign AVD spike scored ~5.48 — a floor of `6.0` would have suppressed it while catching genuine outliers.

**Option B — Extend BenignRundll32Patterns:** Review remaining `rundll32.exe` hits and add any recurring benign DLL exports to the list. Common additions:
- `dfshim.dll` — ClickOnce app activation
- `zipfldr.dll` — compressed folder handler
- `url.dll,FileProtocolHandler` — URL file handler

**Option C — Account exclusions:** If specific service accounts generate legitimate hits, add them to a `let ExcludedAccounts` list and filter `Account !in~ (ExcludedAccounts)`.

**Option D — Separate rules per process:** Run individual rules for `powershell.exe`, `cmd.exe`, and `rundll32.exe` with tailored thresholds. `rundll32.exe` legitimately runs at higher volume than `psexec.exe` — combining them in one time-series flattens the signal.

### Important: Re-apply filters in the join leg
The filters must be duplicated in both the `TimeSeriesData` block and the join's inner `SecurityEvent` subquery. If you only filter the time-series training data, the join will still pull noisy rows back into the final results.

---

## Test Results

- [ ] Executed against production workspace — date: ___
- [x] Noise confirmed eliminated
- [ ] BenignRundll32Patterns list validated — no legitimate attack patterns accidentally excluded
- [ ] AnomalyScoreThreshold tuned for environment
- [ ] CommandLine audit policy confirmed enabled on endpoints

---

## Sentinel Analytics Rule

> ⚠️ **Not recommended as a scheduled analytics rule in its current form.** See Analyst Assessment above. If deploying, scope `ExeList` to rare processes only (`psexec.exe`, `cacls.exe`, `wmic.exe`) and remove `powershell.exe`, `cmd.exe`, and `rundll32.exe`.

| Setting | Value |
|---|---|
| **Rule name** | Anomalous Rare Process Execution Spike |
| **Severity** | Medium |
| **Frequency** | Every 1 hour |
| **Lookback** | 3 hours |
| **Suppression** | 1 hour per Process + Computer combination |
| **Entity mapping** | Account → Account; Computer → Host; Process → Process |
| **Custom detail** | `Process`, `CommandLine`, `score`, `Total`, `baseline` |

**Preferred use:** Run manually as a hunting query on a weekly cadence, or trigger ad-hoc following a threat intel report referencing mass lateral movement activity.

---

## Related Notes

- [[KQL-Keepass-Archive-File-Access]] — file access detection on same endpoint tier
- [[HARD-ASR-Policy-Monitoring]] — ASR rules complement this detection

---

## Tags

`#detection/query` `#detection` `#endpoint` `#status/review`

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2026-04-27 | Dave | Modified from MSFT Content Hub version. Added machine account exclusion (primary noise driver), BenignRundll32Patterns allowlist, empty CommandLine filter, score floor parameter. Documented noise analysis from test results. Filters duplicated in join leg for consistency. |
| 2026-04-27 | Dave | Added Analyst Assessment section. Query assessed as low value for scheduled analytics rule use. Documented detection primitive limitations, recommended ExeList scoping to rare processes only, and higher-value alternative detection approaches. Updated Sentinel rule recommendation accordingly. |
