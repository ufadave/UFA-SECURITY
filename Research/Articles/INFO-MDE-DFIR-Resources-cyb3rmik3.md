---
title: "MDE-DFIR-Resources — Curated KQL, KAPE, Live Response and DFIR Resource List (cyb3rmik3)"
date: 2026-04-28
source: https://github.com/cyb3rmik3/MDE-DFIR-Resources
tags:
  - "#resource"
  - "#detection"
  - "#ir"
  - "#status/review"
---

# INFO — MDE-DFIR-Resources: Curated DFIR Resource List for MDE/Sentinel Environments

## Source
- **URL:** https://github.com/cyb3rmik3/MDE-DFIR-Resources
- **Author:** Michalis Michalos (cyb3rmik3)
- **Type:** GitHub curated reference repository
- **Date received:** 2026-04-28
- **Original email subject:** `[INFO] A curated list of resources for DFIR through Microsoft Defender for Endpoint leveraging kusto queries, powershell scripts, tools such as KAPE and THOR Cloud and more.`

## What It Is
A well-maintained, community-trusted reference repository aggregating the best MDE/Sentinel DFIR resources available. Covers: KQL query collections for IR, Live Response usage guides, KAPE deployment via MDE for remote forensic collection, THOR Cloud for compromise assessment scans (YARA/Sigma/IOC), Velociraptor integration, memory forensics, macOS forensics via Aftermath, and browser forensics (Edge, Chrome incognito). Also references KustoHawk, a triage and response tool purpose-built for Defender XDR and Sentinel. Michalis also maintains a separate KQL hunting queries repo at `cyb3rmik3/KQL-threat-hunting-queries`.

## Key Resources Listed
- Remote collection of Windows forensic artefacts via KAPE + MDE Live Response (DFIRanjith, Krzysztof Miodoński)
- Bert-Jan's three-part IR series: IR on Microsoft Security Incidents (KQL edition), other logs, Live Response
- THOR Cloud via MDE for YARA/Sigma scanning on endpoints
- KustoHawk — incident triage/response tool for Defender XDR and Sentinel
- Selective Isolation with Velociraptor — combines containment + full investigative access
- Ginsu — repackaging tool for large collections (>3GB) to work within MDE Live Response 3GB limit
- macOS forensics via MDE + Aftermath
- Chrome incognito forensics via MDE

## Relevance to Environment
- **High relevance** — MDE is the primary EDR and this is exactly the DFIR workflow stack in use
- KustoHawk is new to me and worth evaluating for incident triage use — automates the "what happened on this device/account" pivot
- THOR Cloud is relevant for OT/SCADA plant machines where deploying full agents may not be feasible — compromise assessment scan without persistent agent
- Bert-Jan's IR series should be reviewed/bookmarked for the IR Playbooks folder
- KAPE deployment via Live Response is directly applicable for future DFIR cases — reduces need to physically access remote prairie/plant locations

## Actions
- [ ] Review KustoHawk — evaluate for SOC triage use
- [ ] Bookmark Bert-Jan IR series — add links to `IR-DFIR/Playbooks`
- [ ] Review THOR Cloud licensing — assess for OT/SCADA compromise assessment use
- [ ] Star the repo on GitHub

## Related Notes
- [[IR-DFIR/Playbooks]]
- [[OT-SCADA/Assets]]
- [[Research/Tools]]

## Changelog
| Date | Change |
|------|--------|
| 2026-04-28 | Created from inbox triage |
