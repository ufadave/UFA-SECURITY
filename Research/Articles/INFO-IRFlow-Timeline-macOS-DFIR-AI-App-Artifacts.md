---
title: INFO-IRFlow-Timeline-macOS-DFIR-AI-App-Artifacts
date: 2026-06-05
source: "https://r3nzsec.github.io/irflow-timeline/dfir-tips/ai-query-history"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- IRFlow Timeline: macOS DFIR Tool + AI App Artifacts Guidance

**Source:** https://r3nzsec.github.io/irflow-timeline/dfir-tips/ai-query-history
**Repo:** https://github.com/r3nzsec/irflow-timeline
**Date:** 2026-06-05
**Author:** Renzon Cruz (r3nzsec)

---

## What It Is

IRFlow Timeline is a free, native macOS DFIR timeline analysis tool -- a SQLite-backed viewer
for CSV, TSV, XLSX, EVTX, Plaso, $MFT, and $UsnJrnl ($J) files. Built specifically for DFIR
analysts who use macOS as their daily driver. The emailed page specifically covers the
**AI Query History and AI App Artifacts** DFIR tip -- forensic artifacts left by AI applications
on endpoints.

**Core features:**
- **Process Inspector** -- parent-child process tree analysis with 340+ MITRE ATT&CK detection rules
- **Lateral Movement Tracker** -- network logon and RDP session visualization as force-directed graphs
- **Persistence Analyzer** -- 30+ persistence techniques, account chain detection, cross-technique
  correlation, and PowerShell 4104 script block reassembly
- **Raw NTFS Artifact Import** -- direct $MFT and $UsnJrnl ingestion with full path reconstruction,
  SI/FN timestamps, change reason mapping
- **Ransomware Analytics** -- bulk rename detection, entropy-based extension analysis, ransom note
  identification, temporal clustering from $MFT data
- **VirusTotal Enrichment** -- bulk IOC lookups, malware family extraction, verdict badges
- **IOC Matching** -- 17+ indicator categories with auto-defanging, CSV/HTML export

Handles 30GB+ forensic timelines. Free and open source (JavaScript/Electron). KAPE profile
auto-detection with optimized column layouts; multi-tab and merge-tab super-timeline views.

---

## Relevance

Medium -- useful DFIR tooling, with one caveat for this environment. The environment includes
a Mac (iCloud/Git vault sync), so a native macOS DFIR tool is directly usable. The AI App
Artifacts DFIR tip is particularly timely given the focus on AI tool governance -- understanding
what forensic traces AI applications leave (query history, cached data, local artifacts) is
relevant to investigating any future incident involving AI tool misuse.

**Note on fit:** The environment is primarily Windows/MDE for endpoint forensics, where
Advanced Hunting and Live Response are the native tools. IRFlow Timeline is most valuable for
offline analysis of collected artifacts (KAPE output, $MFT, EVTX) on a Mac analysis workstation
rather than as a live-response tool. Complements rather than replaces the MDE workflow.

The PowerShell 4104 script block reassembly and 340+ ATT&CK process rules could be useful for
offline analysis of triage collections from incidents like the lt13069 case.

---

## Actions

- [ ] Evaluate for offline artifact analysis on the Mac workstation (KAPE/$MFT/EVTX collections)
- [ ] Review the AI App Artifacts DFIR tip for relevance to AI tool incident investigation
- [ ] Consider for the lt13069 case if offline triage-collection analysis is needed

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-05 | Created -- macOS DFIR timeline tool; emailed page was the AI App Artifacts DFIR tip |
