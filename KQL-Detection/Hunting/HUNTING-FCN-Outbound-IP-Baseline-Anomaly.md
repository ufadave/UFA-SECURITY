---
date: 2026-06-26
title: FCN Outbound IP Baseline Anomaly
table: "CommonSecurityLog"
schema: "Sentinel / Log Analytics"
mitre: "T1571"
tactic: "Command and Control"
technique: "T1571 — Non-Standard Port / T1048 — Exfiltration Over Alternative Protocol"
type: hunting
status: "Draft"
saved_in: ""
query_name: ""
tags:
  - "#detection"
  - "#detection/hunting"
  - "#hunt"
  - "#status/draft"
  - "#ot-scada"
  - "#network"
---

# HUNTING — FCN Outbound IP Baseline Anomaly

---

**Table:** `CommonSecurityLog` | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1571, T1048 | **Tactic:** Command and Control / Exfiltration | **Technique:** Non-Standard Port / Exfiltration Over Alternative Protocol
**Created:** 2026-06-26 | **Status:** `Draft`

---

## Hypothesis

Fuel Control Network (FCN) endpoints at petro station locations have a narrow, predictable set of external IP destinations. Any deviation from that baseline — particularly a novel public IP not observed in the prior 30 days — may indicate C2 channel establishment, data exfiltration, or remote access tooling following OT compromise. Iranian APT actors (Handala/CL-STA-1128) are actively targeting Rockwell/Allen-Bradley OT infrastructure; FCN anomalies should be treated as high-priority until ruled out.

---

## Purpose

Detects FCN endpoints communicating with external destination IPs not observed during a 30-day baseline window. Each device maintains its own baseline — a new destination IP for one station does not suppress an alert for another.

RFC1918 destinations are excluded upstream by the Palo Alto log filter (`DeviceCustomString4 == "FCN"`) before ingestion into CommonSecurityLog. This query operates on public IPs only.

**Scope:** ~150 petro station locations. FCN endpoints identified by:
- `SourceIP` matching `^10\.\d{1,3}\.\d{1,3}\.50$`
- `DeviceName` matching `^[A-Za-z]{4}-PET-L7-01$`
- `DeviceCustomString4 == "FCN"`
- Excluding known noisy devices: `ALLP-PET-L7-01`, `BWRD-PET-L7-01`

---

## Query

```kql
// ============================================================
// TECHNIQUE   : T1571 / T1048
// TACTIC      : Command and Control / Exfiltration
// TABLE       : CommonSecurityLog
// SCHEMA      : Sentinel / Log Analytics
// ============================================================
// BASELINE    : 30 days prior to detection window
// DETECTION   : 1 day (last 24h)
// SCOPE       : FCN endpoints at petro station sites only
// EXCLUSIONS  : RFC1918 excluded upstream by PA firewall filter
// ============================================================

let BaselineDays   = 30d;
let DetectionDays  = 1d;
let ExcludedDevices = dynamic(["ALLP-PET-L7-01", "BWRD-PET-L7-01"]);

// Step 1 — FCN device filter (reusable)
let FCNFilter = (lookback: timespan) {
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where Activity == "TRAFFIC"
    | where DeviceAction =~ "allow"
    | where SourceIP matches regex @"^10\.\d{1,3}\.\d{1,3}\.50$"
    | where DeviceName matches regex @"^[A-Za-z]{4}-PET-L7-01$"
    | where DeviceCustomString4 == "FCN"
    | where DeviceName !in(ExcludedDevices)
    | where isnotempty(DestinationIP)
};

// Step 2 — Build per-device baseline: known good destination IPs over 30 days
let Baseline = FCNFilter(BaselineDays + DetectionDays)
    | where TimeGenerated < ago(DetectionDays)
    | summarize KnownDestinations = make_set(DestinationIP) by DeviceName;

// Step 3 — Detection window: last 24 hours
let RecentTraffic = FCNFilter(DetectionDays)
    | project
        TimeGenerated,
        DeviceName,
        SourceIP,
        DestinationIP,
        DestinationPort,
        Protocol,
        DeviceAction,
        ApplicationProtocol,
        RequestURL,
        AdditionalExtensions;

// Step 4 — Surface IPs not seen in baseline for each device
RecentTraffic
| join kind=leftouter Baseline on DeviceName
| where not(set_has_element(KnownDestinations, DestinationIP))
| project
    TimeGenerated,
    DeviceName,
    SourceIP,
    DestinationIP,
    DestinationPort,
    Protocol,
    DeviceAction,
    ApplicationProtocol,
    RequestURL,
    AdditionalExtensions
| order by TimeGenerated desc
```

---

## Saved Query

- **Saved In:** <!-- Sentinel / MDE / Log Analytics -->
- **Query Name:** <!-- Populate query_name in frontmatter when saved -->

---

## Validated Columns

- [x] `Activity` — confirmed; filter on `"TRAFFIC"`
- [x] `SourceIP` — confirmed
- [x] `DeviceName` — confirmed
- [x] `DeviceCustomString4` — confirmed (`"FCN"`)
- [ ] `DestinationIP` — confirmed correct field; verify consistently populated across all PA log types
- [ ] `DestinationPort` — Palo Alto CSL typically populates this; confirm
- [ ] `Protocol` — confirm field name; PA may use `Protocol` or `TransportProtocol`
- [ ] `ApplicationProtocol` — PA-specific; may surface app-layer protocol (e.g. `ssl`, `web-browsing`); confirm availability
- [ ] `RequestURL` — confirm availability; not always populated for non-HTTP traffic
- [ ] `AdditionalExtensions` — Palo Alto-specific extension fields; confirm schema
- [ ] `DeviceAction` — confirm populated (`allow`, `deny`); consider filtering on `allow` only

---

## Tuning Notes

**Filter on allowed traffic only** — add to `FCNFilter` to detect only successful connections:
```kql
| where DeviceAction =~ "allow"
```

**First-run noise** — on first execution this will surface all external IPs seen in the last 24h not present in the 30-day baseline. Review output before promoting to a scheduled rule. Expect legitimate churn from:
- Vendor update CDNs (fuel card processors, payment networks)
- NTP servers
- Telemetry endpoints for fuel control software vendors

**Allowlist known-good new IPs** — once identified, add a static exclusion:
```kql
let KnownGoodNewIPs = dynamic(["x.x.x.x", "y.y.y.y"]);
| where DestinationIP !in(KnownGoodNewIPs)
```

**Summarise first on high volume** — swap the final `project` for a `summarize` to understand scope:
```kql
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated),
    HitCount  = count(),
    Ports     = make_set(DestinationPort),
    Protocols = make_set(ApplicationProtocol)
    by DeviceName, DestinationIP
| order by HitCount desc
```

**Baseline maturity** — confirm `CommonSecurityLog` retention covers ≥30 days before treating output as high-fidelity.

---

## Findings

<!-- Populate after each hunt run -->

| Date | DeviceName | DestinationIP | Port | Protocol | Disposition |
|------|------------|---------------|------|----------|-------------|
| | | | | | |

---

## Promote to Detection?

Retain as hunting query until baseline noise is characterised and known-good IPs are allowlisted. Once first-run IP churn is understood and the query produces consistent, low-volume, high-signal output, promote to a Sentinel Analytics Rule via `promote rule HUNTING-FCN-Outbound-IP-Baseline-Anomaly`.

Suggested rule settings when ready: Frequency 1h | Lookback 1d | Severity High.

---

## Hardening Control Pair
- **Control:** [[HARD-OT-FCN-Outbound-Firewall-Allowlist]] ← create if not exists
- **Linked:** [ ]

---

## Related Notes
- [[PROJ-OT-SCADA-Assessment]]
- [[INTEL-Stryker-Breach-Handala-Intune-Wipe]]
- [[ACTOR-Handala]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-26 | Created — FCN outbound IP baseline anomaly detection for petro station Fuel Control Network |
| 2026-06-26 | Promoted to hunting query via promote hunt command |
