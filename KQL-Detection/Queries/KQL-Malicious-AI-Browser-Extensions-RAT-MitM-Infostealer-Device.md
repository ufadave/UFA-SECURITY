---
date: 2026-05-28
title: Malicious AI Browser Extensions RAT MitM Infostealer Device
table: DeviceNetworkEvents, DeviceProcessEvents
schema: Advanced Hunting
mitre:
  - T1176
  - T1539
  - T1185
  - T1557
tactic: "Collection, Credential Access, Command and Control"
technique: "T1176 — Browser Extensions; T1185 — Browser Session Hijacking; T1557 — Adversary-in-the-Middle"
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#endpoint"
  - "#identity"
  - "#infostealer"
---

# KQL — Malicious AI Browser Extensions RAT MitM Infostealer Device

**Table:** DeviceNetworkEvents, DeviceProcessEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1176, T1185, T1557 | **Tactic:** Collection, Credential Access
**Created:** 2026-05-28 | **Status:** `Draft`

---

## Purpose

Two detection stubs targeting malicious browser extension activity — adversary-in-the-browser (AitB) techniques where a rogue extension intercepts sessions, steals credentials, and beacons to C2:

- **Stub 1 (DeviceNetworkEvents):** Browser process making repeated outbound connections to external hosts not on the known-good domain list — proxy for C2 beaconing from an AitB extension. High connection count threshold (`> 10`) reduces noise but may miss low-and-slow beaconing.
- **Stub 2 (DeviceProcessEvents):** Browser process spawning unusual child processes — indicates RAT-class extension activity. Browsers do not normally spawn arbitrary child processes outside their own renderer/helper binaries.

> **Note:** A companion note `KQL-Browser-Extension-C2-Beaconing` is already linked from the source INTEL note. Confirm what that note covers before deploying this one — this note contains both stubs from the original INTEL source. Merge or deduplicate as appropriate.

---

## Query

```kql
// Stub 1 — Browser C2 beaconing from AitB extension
// High repeated connection count to external hosts not in known-good list
// Adjust the allowlist and threshold to your environment's baseline
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe")
| where RemotePort in (80, 443, 8080, 8443)
| where not(RemoteUrl has_any (
    "microsoft.com", "google.com", "bing.com", "office.com",
    "windowsupdate.com", "azure.com", "akamai.com", "cloudflare.com"
))
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
| where ConnectionCount > 10
| order by ConnectionCount desc
```

```kql
// Stub 2 — Browser spawning unexpected child processes (RAT indicator)
// Browsers should not spawn arbitrary binaries outside their own helper processes
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe")
| where FileName !in~ ("msedge.exe", "chrome.exe", "crashpad_handler.exe", "elevation_service.exe")
| where FileName !endswith ".tmp"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `RemoteUrl` — DeviceNetworkEvents — **validate in your environment**; field may not be populated for all connection types; `RemoteIP` is more reliable as a fallback
- [ ] `RemotePort` — DeviceNetworkEvents ✓ confirm column name vs `RemoteIPPort`
- [ ] `InitiatingProcessFileName` — DeviceNetworkEvents, DeviceProcessEvents ✓ standard column
- [ ] `InitiatingProcessAccountName` — DeviceNetworkEvents — confirm field name (vs `AccountName`)
- [ ] `FileName` — DeviceProcessEvents ✓ standard column

---

## Test Results

- [ ] Tested in environment
- [ ] Stub 1: expand allowlist significantly — browser makes connections to hundreds of CDN/ad/analytics domains in normal use; threshold and allowlist require tuning before this is useful
- [ ] Stub 2: baseline — browser child process spawning is rare; low FP expected; check for known Edge/Chrome helper binaries in results and add to exclusion list
- [ ] FP rate acceptable

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Malicious Browser Extension C2 or RAT Activity
- **Frequency:** every 1h
- **Lookback:** 1h
- **Severity:** Medium (Stub 1 — requires allowlist tuning to be useful); High (Stub 2 — browser child process spawn)
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

> Stub 1 should be treated as a hunting query until the allowlist is built out. Stub 2 is the better candidate for immediate promotion.

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceNetworkEvents and DeviceProcessEvents are Advanced Hunting only -->
<!-- Deploy via MDE Custom Detection -->

---

## Hardening Control Pair
- **Control:** [[HARD-Edge-Extension-Installation-Policy]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-Malicious-AI-Browser-Extensions-RAT-MitM-Infostealer]]
- [[KQL-Browser-Extension-C2-Beaconing]] — check for overlap before deploying both

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-28 | Created — backfill companion to [[INTEL-Malicious-AI-Browser-Extensions-RAT-MitM-Infostealer]] via backfill stubs command; [[KQL-Browser-Extension-C2-Beaconing]] already linked — confirm scope before deploying |
