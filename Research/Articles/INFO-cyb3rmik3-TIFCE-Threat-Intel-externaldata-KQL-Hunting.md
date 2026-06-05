---
title: INFO-cyb3rmik3-TIFCE-Threat-Intel-externaldata-KQL-Hunting
date: 2026-06-03
source: "https://github.com/cyb3rmik3/KQL-threat-hunting-queries/tree/main/TIFCE"
tags:
  - "#resource"
  - "#status/draft"
  - "#detection"
---

# INFO -- cyb3rmik3 TIFCE: Threat Intelligence Feeds via externaldata (KQL)

**Source:** https://github.com/cyb3rmik3/KQL-threat-hunting-queries/tree/main/TIFCE
**Reference blog:** https://www.michalos.net/2024/01/22/harnessing-threat-intelligence-using-externaldata-operator/
**Date:** 2026-06-03
**Author:** Michalis Michalos (cyb3rmik3)

---

## What It Is

TIFCE (Threat Intelligence Feeds via Custom externaldata) is a folder within cyb3rmik3's
KQL-threat-hunting-queries repository demonstrating how to harness external threat
intelligence feeds directly inside KQL hunting queries using the `externaldata` operator
-- without requiring a dedicated Threat Intelligence Platform (TIP) such as MISP. The
technique pulls IOC lists (RMM software names, malicious IPs, domains, hashes) from
hosted CSV files at query time and joins them against Defender XDR / Sentinel telemetry.

The pattern: `externaldata` reads a remote CSV (e.g. from a GitHub raw URL or threat feed),
materialises it as a table inside the query, and filters device/sign-in/network telemetry
against it. This brings threat-feed-driven hunting to environments that don't have a TIP
integrated into Sentinel.

**Example pattern (from the reference blog):**
```kql
let RMMSoftware = externaldata(RMMSoftware: string)
    [@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/rmm-software.csv"]
    with (format="csv", ignoreFirstRecord=True);
let ExclDevices = datatable(excludeddev: string)["DeviceName1", "DeviceName2"];
let Timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(Timeframe)
| where ProcessVersionInfoCompanyName has_any (RMMSoftware)
| where not(DeviceName in (ExclDevices))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    ProcessVersionInfoCompanyName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

---

## Relevance

High -- directly applicable and immediately useful. The `externaldata` technique solves a
real gap: bringing external threat feeds into hunting queries without a TIP. Several
current workflows would benefit:

- **RMM software hunting** -- the RMM CSV feed approach is directly relevant to the
  unapproved-agent discovery work (Site24x7 finding) and the broader unmanaged-tooling
  detection surface. A scheduled query against the RMM list would catch new RMM tooling
  appearing in the estate.
- **IOC-driven hunting** -- pulling IP/domain/hash feeds at query time complements the
  existing detection rules without requiring ingestion into Sentinel watchlists.
- **TeamPCP / supply-chain IOCs** -- the FIRESCALE C2 IPs, npm package hashes, and
  beacon strings tracked in ACTOR-TeamPCP could be hosted as a CSV and joined against
  DeviceNetworkEvents via this pattern.

**Author context:** cyb3rmik3 (Michalis Michalos) is a respected KQL community contributor
whose threat hunting template is widely referenced. This pairs with the Blu Raven Academy
(cyb3rmonk) KQL training already in progress.

**Caveat:** `externaldata` fetches the remote file on every query execution. For scheduled
analytics rules this means a dependency on the external URL being available at runtime --
if the feed host is down, the rule fails. For ad-hoc hunting this is fine; for deployed
detections, consider whether a Sentinel watchlist (ingested copy) is more robust than a
live `externaldata` pull.

---

## Actions

- [ ] Review the TIFCE folder queries for patterns applicable to current hunting workflows
- [ ] Evaluate the RMM software feed approach against the unapproved-agent detection surface
- [ ] Consider hosting TeamPCP / supply-chain IOCs as a CSV for externaldata-driven hunting
- [ ] Assess externaldata vs Sentinel watchlist tradeoff for any feed used in a deployed rule

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-03 | Created -- forwarded INFO email; cyb3rmik3 TIFCE externaldata technique |
