---
date: 2026-05-22
title: Inbound Public Connection Followed By Logon
table: "DeviceNetworkEvents, DeviceLogonEvents"
schema: "Advanced Hunting"
mitre: "T1078, T1133"
tactic: "Initial Access, Persistence"
technique: "T1078 Valid Accounts, T1133 External Remote Services"
status: "Draft"
promoted_to_rule: false
mde_rule_name: "Custom - Inbound Public Connection Followed By Logon"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/query"
  - "#status/draft"
  - "#endpoint"
  - "#network"
---

# KQL — Inbound Public Connection Followed By Logon

---

**Table:** DeviceNetworkEvents, DeviceLogonEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1078, T1133 | **Tactic:** Initial Access, Persistence
**Created:** 2026-05-22 | **Status:** `Draft`

---

## Purpose

Detects a successful logon on a device within 150 seconds of an accepted inbound connection
from a public IP on that same device. The hypothesis is that an external actor established
a remote connection (RDP, WinRM, custom C2 implant) and then authenticated successfully
shortly after — consistent with hands-on-keyboard access following initial remote access.

Correlation is on `DeviceId` and time window only — the IP join from the original hunting
query was dropped because logon events do not reliably record a matching `RemoteIP` in all
scenarios (NAT, RDP gateway, proxied connections). The broader correlation catches more true
positives at the cost of requiring tighter exclusion tuning post-deployment.

> **Detection scope:** Fleet-wide — all enrolled MDE devices.
> **Time window:** 150 seconds between inbound connection accepted and logon success.
> **Key exclusion:** Azure IMDS/WireServer `168.63.129.16` excluded from network events.
> **FP risk:** Legitimate admin RDP sessions on servers with frequent inbound connections
> are the primary noise source. Tune `ExcludedDevices` and `ExcludedAccounts` after
> first deployment.

---

## Query

```kql
// ─────────────────────────────────────────────────────────────────────────────
// DETECTION: Inbound Public Connection Followed By Logon
// Tables: DeviceNetworkEvents + DeviceLogonEvents (Advanced Hunting)
// Correlation: DeviceId + 150s time window (IP join removed — unreliable match)
// Scope: Fleet-wide
// Last validated: 2026-05-22
// ─────────────────────────────────────────────────────────────────────────────

// Tune these after first deployment to suppress known-good admin sources
let ExcludedDevices  = dynamic([]);  // e.g. "jumphost01.ad.corp.local"
let ExcludedAccounts = dynamic([]);  // e.g. "svc-monitoring"
let ExcludedIPs      = dynamic([
    "168.63.129.16"  // Azure IMDS / WireServer — always exclude
    // Add known admin jump IPs or VPN exit nodes here after baseline review
]);
let SearchWindow = 1d;
let CorrelationWindow = 150;  // seconds
//
// Step 1 — Inbound accepted connections from public IPs
let InboundConnections =
    DeviceNetworkEvents
    | where Timestamp > ago(SearchWindow)
    | where ActionType == "InboundConnectionAccepted"
    | where RemoteIPType == "Public"
    | where RemoteIP !in (ExcludedIPs)
    | where DeviceName !in (ExcludedDevices)
    | project
        ConnectionTime = Timestamp,
        DeviceId,
        DeviceName,
        RemoteIP,
        RemotePort,
        LocalIP,
        LocalPort,
        InitiatingProcessFileName,
        ReportId;
//
// Step 2 — Successful logons in the same window
let Logons =
    DeviceLogonEvents
    | where Timestamp > ago(SearchWindow)
    | where ActionType == "LogonSuccess"
    | where AccountName !in (ExcludedAccounts)
    | where DeviceName !in (ExcludedDevices)
    | project
        LogonTime = Timestamp,
        DeviceId,
        LogonType,
        AccountDomain,
        AccountName,
        LogonInitiatingProcess = InitiatingProcessFileName,
        ReportId;
//
// Step 3 — Correlate on DeviceId within 150s window
InboundConnections
| join kind=inner (Logons) on DeviceId
| extend TimeDifferenceSec = datetime_diff('second', LogonTime, ConnectionTime)
| where TimeDifferenceSec between (0 .. CorrelationWindow)
| project
    ConnectionTime,
    LogonTime,
    TimeDifferenceSec,
    DeviceName,
    DeviceId,
    RemoteIP,
    RemotePort,
    LocalPort,
    InitiatingProcessFileName,
    LogonType,
    AccountDomain,
    AccountName,
    LogonInitiatingProcess,
    ReportId
| order by ConnectionTime desc
```

---

## Validated Columns

- [ ] `ActionType == "InboundConnectionAccepted"` — confirm this value exists in your tenant's `DeviceNetworkEvents`
- [ ] `RemoteIPType` — confirm field exists in `DeviceNetworkEvents`; present in most MDE schema versions
- [ ] `ActionType == "LogonSuccess"` — confirm this value exists in your tenant's `DeviceLogonEvents`
- [ ] `InitiatingProcessFileName` — present in both tables; verify column name hasn't changed in your schema version
- [ ] `LogonType` — confirm values returned match expected types (e.g. `RemoteInteractive` for RDP, `Network` for SMB/WinRM)

> **Schema note:** `RemoteIPType` is not present in all MDE Advanced Hunting schema versions.
> If the query errors, replace `| where RemoteIPType == "Public"` with an IP range exclusion
> using `ipv4_is_private(RemoteIP) == false`.

---

## Test Results

- [ ] Run in Advanced Hunting — confirm no schema errors
- [ ] Baseline result count over 7d — document expected daily volume
- [ ] Review first 20 results — classify as TP / FP / Benign and document below
- [ ] Identify ExcludedDevices and ExcludedAccounts candidates from FP review
- [ ] Confirm `LogonType` values in results — `RemoteInteractive` and `Network` are expected; `Interactive` may indicate local console and warrant separate tuning

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Inbound Public Connection Followed By Logon
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** Medium (upgrade to High if combined with other signals — see tuning note)
- **Actions:** Alert only — do not isolate on first deployment; FP rate unknown
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

> **Tuning note — severity:** Medium is appropriate for first deployment given the broad
> correlation approach (DeviceId + time window, no IP match). Once ExcludedDevices and
> ExcludedAccounts are tuned and FP rate drops, consider upgrading to High — especially
> for results where `LogonType == "RemoteInteractive"` (RDP) or `AccountName` is a
> privileged account.
>
> **Tuning note — FP reduction:** After first deployment, the most effective tuning steps are:
> 1. Add known admin jump IPs to `ExcludedIPs` (VPN exit nodes, IT management subnets)
> 2. Add known service accounts to `ExcludedAccounts`
> 3. If servers with frequent scheduled inbound connections are noisy, add to `ExcludedDevices`
>    and create a separate higher-threshold rule for those devices

<!-- INACTIVE — Sentinel Analytics Rule
This detection uses DeviceNetworkEvents and DeviceLogonEvents — Advanced Hunting tables only.
Not available in Sentinel Log Analytics. Deploy via MDE Custom Detection only.
-->

---

## Hardening Control Pair
- **Control:** [[HARD-MDE-ExternalRDP-Conditional-Access]]
- **Linked:** [ ]

---

## Related Notes
- Origin hunting query — converted to detection 2026-05-22
- [[PLAYBOOK-Graph-API-Broad-Permission-Grant]] — unrelated but same session context
- [[KQL-DeviceLogonEvents-RemoteInteractive-Logon-Anomaly]] — companion: RDP logon anomaly detection

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-22 | Created — converted from hunting query |
| 2026-05-22 | IP join removed — correlation changed to DeviceId + 150s time window only; RemoteIP join dropped due to unreliable matching across NAT/RDP gateway scenarios |
| 2026-05-22 | ExcludedDevices and ExcludedAccounts exclusion lists added for post-deployment tuning |
| 2026-05-22 | ActionType1 renamed to LogonInitiatingProcess for clarity |
