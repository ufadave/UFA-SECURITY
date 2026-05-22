---
date: 2026-05-20
title: Custom - OneDrive Bulk File Download Detection
table: "CloudAppEvents"
schema: "Advanced Hunting"
mitre: "T1567.002"
tactic: "Exfiltration"
technique: "Exfiltration Over Web Service: Exfiltration to Cloud Storage"
status: "Active"
promoted_to_rule: true
mde_rule_name: "Custom - OneDrive Bulk File Download Detection"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#cloud"
  - "#identity"
---

# KQL -- OneDrive Bulk File Download Detection

---

**Table:** CloudAppEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1567.002 | **Tactic:** Exfiltration | **Technique:** Exfiltration Over Web Service: Exfiltration to Cloud Storage
**Created:** 2026-05-20 | **Status:** Done

---

## Purpose

Detects bulk OneDrive file download operations -- large clusters of `FileDownloaded` events from a single account within a short window at high velocity. Targets post-compromise data exfiltration consistent with Storm-2949 TTPs, where compromised accounts downloaded thousands of files from OneDrive in single operations.

Specifically flags high-velocity downloads (25+ files in under 2 minutes) to distinguish scripted/automated exfiltration from legitimate SharePoint sync client activity, which typically trickles files over a longer window.

**Known false positive pattern -- cross-account delegated access:**
During role transitions (e.g. departing employee handover), a successor may bulk-download files from the predecessor's OneDrive under a delegated access grant. Before escalating, verify:
1. Is the downloading account known to have delegated access to the source account's drive?
2. Does the source IP match a known corporate egress IP, VPN endpoint, or the user's registered device?
3. Is there an active HR/IT change request for the relevant role transition?

If all three check out, document and close as benign. If the IP is unrecognized, treat as suspicious regardless of access explanation.

**Prerequisite:** Microsoft Defender for Cloud Apps connector must be enabled and OneDrive activity policies configured for `CloudAppEvents` to populate in Advanced Hunting.

---

## Query

```kql
let LookbackWindow = 15m;
let DownloadThreshold = 25;
let MaxDurationSeconds = 120;    // flag high-velocity: 25+ files in under 2 minutes
CloudAppEvents
| where ActionType == "FileDownloaded"
| where Application == "Microsoft OneDrive for Business"
| summarize
    DownloadCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    FileList = make_set(ObjectName, 20),
    IPAddresses = make_set(IPAddress, 5)
    by AccountObjectId, AccountDisplayName, bin(Timestamp, LookbackWindow)
| where DownloadCount >= DownloadThreshold
| extend DurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| where DurationSeconds <= MaxDurationSeconds
| project
    FirstSeen,
    LastSeen,
    DurationSeconds,
    AccountDisplayName,
    AccountObjectId,
    DownloadCount,
    FileList,
    IPAddresses
| order by DownloadCount desc
```

---

## Validated Columns

- [x] `ActionType` -- `FileDownloaded` confirmed in CloudAppEvents for OneDrive activity
- [x] `Application` -- confirmed as `Microsoft OneDrive for Business` (not `Microsoft OneDrive` -- note the difference)
- [x] `AccountObjectId` -- confirmed populated; used as grouping key for accuracy over display name
- [x] `AccountDisplayName` -- confirmed populated
- [x] `ObjectName` -- confirmed populated with full SharePoint URL of downloaded file
- [x] `IPAddress` -- confirmed populated with client IP at time of download
- [x] `datetime_diff` -- confirmed functional for DurationSeconds calculation

---

## Test Results

**30-day validation -- 2026-04-20 to 2026-05-20**
**Threshold tested:** 10 downloads / 15 minutes (broad), then 25 downloads / 15 minutes / 120 seconds (final)

| Date | Account | DownloadCount | DurationSeconds | Source IP | Disposition |
|------|---------|---------------|-----------------|-----------|-------------|
| 2026-05-19 21:33 | Michelle Johnson | 30 | 51s | 206.75.203.2 | Benign -- delegated access, role transition (Les Wolowski). IP confirmed corporate. |

Post-threshold result: **1 result in 30 days** across estate. Noise floor acceptable for scheduled rule deployment.

**Tuning notes:**
- Initial threshold of 10 returned same single result -- estate has low baseline OneDrive bulk download activity
- `MaxDurationSeconds = 120` retains the Michelle Johnson event (51s) as intended -- high-velocity pattern warrants review even when access is delegated
- SharePoint sync client activity excluded by design: sync clients trickle files over longer windows and would not satisfy the 120-second velocity filter
- Application name must be `Microsoft OneDrive for Business` -- `Microsoft OneDrive` returns no results

---

## Deployment

> CloudAppEvents is an Advanced Hunting table (Defender for Cloud Apps connector). Deploy as MDE Custom Detection or Sentinel Analytics Rule -- both schemas support CloudAppEvents.
> Confirm Defender for Cloud Apps connector is active and OneDrive activity is being ingested before deploying.

### MDE Custom Detection Rule
- **Rule Name:** Custom - OneDrive Bulk File Download Detection
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Actions:** Alert only
- **Deployed:** [Y ]
- **Rule Name:** Custom - OneDrive Bulk File Download Detection
### Sentinel Analytics Rule
- **Rule Name:** OneDrive Bulk File Download Detection
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** High
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18]]
- [[KQL-Linux-SUID-SGID-chmod-Detection]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-20 | Created -- promoted from Storm-2949 intel note detection opportunity; 30-day validated, 1 benign result |
| 2026-05-20 | Application name corrected to "Microsoft OneDrive for Business"; MaxDurationSeconds velocity filter added |
