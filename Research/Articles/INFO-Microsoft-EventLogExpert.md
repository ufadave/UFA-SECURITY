---
title: Microsoft EventLogExpert — Modern Windows Event Viewer
date: 2026-04-28
source: https://github.com/microsoft/EventLogExpert
tags:
  - "#resource"
  - "#status/draft"
---

# Microsoft EventLogExpert — Modern Windows Event Viewer

**Source:** https://github.com/microsoft/EventLogExpert
**Date:** 2026-04-28

---

## What It Is
Microsoft-published open-source replacement for Windows Event Viewer — loads multiple `.evtx` files concurrently with an interleaved combined view, LINQ-based filtering, event description previews inline, and a provider database system for viewing logs from servers without the relevant roles installed (e.g. Exchange logs on a workstation). Latest release v26.4.27.1172.

## Relevance
High — directly useful for DFIR work. The interleaved multi-file view and LINQ filter are significant improvements over native Event Viewer for incident timelines across multiple hosts. Provider database support is valuable for analysing logs from OT/SCADA or specialised systems without needing the product installed locally.

## Actions
- [ ] Download and install on DFIR workstation: https://github.com/microsoft/EventLogExpert/releases/latest
- [ ] Note: Windows Server 2019 requires `Microsoft.WindowsAppRuntime.msix` installed separately

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created — lightweight triage note |
