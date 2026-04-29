---
title: Sentinel MITRE ATT&CK Coverage Analyzer
date: 2026-04-27
type: tool
author: Rohit Ashok
source: https://github.com/rohit8096-ag/Sentinel-Assessment-Tool
version: 2.0.0
last_updated: 2026-03-10
platform: PowerShell (cross-platform, macOS compatible)
tags:
  - "#resource"
  - "#detection"
  - "#endpoint"
  - "#cloud"
  - "#identity"
  - "#status/review"
---

# TOOL — Sentinel MITRE ATT&CK Coverage Analyzer

## What It Is

A PowerShell module (`SentinelMITREAnalyzer.psm1`) that queries your Microsoft Sentinel workspace and Defender stack via Azure APIs, then generates a self-contained interactive HTML report mapping your detection coverage against all 211 MITRE ATT&CK techniques across your full Microsoft security stack.

Outputs to `~/Downloads/Sentinel Analytical Analyzer.html`. Requires internet when opening (Chart.js loads from CDN).

---

## Source & Metadata

| Field | Value |
|-------|-------|
| **Repo** | https://github.com/rohit8096-ag/Sentinel-Assessment-Tool |
| **Author** | Rohit Ashok (@rohit8096-ag) |
| **Version** | 2.0.0 |
| **Last Updated** | March 10, 2026 |
| **License** | MIT |
| **Language** | PowerShell 5.1+ |
| **Stars / Forks** | 5 / 1 (minimal community validation — new repo) |

---

## What It Does

Four output tabs in the HTML report:

**Tab 1 — Sentinel Rule Analysis**
- Enabled/disabled rule counts
- Radar chart across all 14 MITRE tactics
- Gap analysis: top 5 tactics with fewest enabled rules
- Disabled rules list with associated MITRE tactics and last-modified date

**Tab 2 — Table Optimization**
- Queries Log Analytics ingestion volumes (last 30 days)
- Flags high-cost tables with zero detection rules — cost/coverage ratio analysis
- Retention policy recommendations

**Tab 3 — Defender Custom Rules** *(requires App Registration)*
- Your custom MDE detection rules mapped to MITRE
- Requires `CustomDetection.Read.All` application permission + admin consent

**Tab 4 — Full MITRE Heatmap**
- 211-technique heatmap combining all sources
- Built-in product counts (hardcoded, not live): MDE (277), MDI (63), MDA (22), MDO (30), Entra ID Protection (21)
- Coverage matrix per tactic per product
- A–F grading scale based on overall coverage %

---

## Prerequisites

- PowerShell 7+ (macOS: `brew install powershell`)
- Azure CLI (macOS: `brew install azure-cli`)
- **Azure Role:** Microsoft Sentinel Reader on the workspace (minimum)
- **Optional (Tab 3):** App Registration with `CustomDetection.Read.All` application permission, admin consent granted

---

## Running on macOS

```bash
# Install prerequisites (one-time)
brew install powershell
brew install azure-cli

# Authenticate
az login
az account set --subscription 'your-subscription-id'

# Clone repo
git clone https://github.com/rohit8096-ag/Sentinel-Assessment-Tool.git
cd Sentinel-Assessment-Tool

# Launch PowerShell and run
pwsh

Import-Module ./SentinelMITREAnalyzer.psm1 -Force

Get-SentinelAnalyticalRulesReport `
    -SubscriptionId (az account show --query id -o tsv) `
    -ResourceGroup 'your-rg' `
    -WorkspaceName 'your-workspace' `
    -WorkspaceId 'your-workspace-guid' `
    -ExportHtml
```

**With Defender Custom Rules (Tab 3):**

```powershell
Get-SentinelAnalyticalRulesReport `
    -SubscriptionId (az account show --query id -o tsv) `
    -ResourceGroup 'your-rg' `
    -WorkspaceName 'your-workspace' `
    -WorkspaceId 'your-workspace-guid' `
    -TenantId 'your-tenant-id' `
    -ClientId 'your-app-client-id' `
    -ClientSecret 'your-app-secret' `
    -ExportHtml
```

---

## Security Posture

- ✅ 100% read-only — no write operations to Azure
- ✅ No credential storage — runtime only
- ✅ No external data transmission — output stays local
- ✅ HTTPS-only API calls
- ✅ Minimum required role: Sentinel Reader

---

## Assessment for This Environment

### High-Value Use Cases

**Gap analysis against active threat priorities**
The tactic-level gap output is directly usable for cross-referencing coverage against current priority threats — Iranian APT (Handala/CL-STA-1128) TTPs targeting Entra ID, Intune, and Rockwell OT. Run it, export the gap list, map to active hunting priorities.

**Disabled rules audit**
The disabled rules list with MITRE mappings provides a fast audit of coverage regression — useful for identifying rules that were disabled without a detection gap analysis.

**Table optimization**
In an E5 environment ingesting MDE, MDO, Entra, and MCAS telemetry, the table analysis will surface expensive tables with zero rules — actionable for either new detections or retention policy review.

### Limitations

| Limitation | Detail |
|-----------|--------|
| **Overall % is inflated** | Built-in MDE/MDI/MDO/MDA counts are hardcoded static numbers, not a live reflection of what's tuned and active |
| **No rule quality signal** | A noisy rule and a well-tuned rule look identical in coverage stats |
| **No OT/ICS scope** | ATT&CK for ICS techniques are not covered — irrelevant for fertilizer plant OT surface |
| **New/unvalidated repo** | 3 commits, 5 stars as of April 2026 — review the `.psm1` source before running in prod |
| **PowerShell required** | Needs `pwsh` installed on Mac — not native |

### Recommendation

Run as a **one-time coverage audit** to baseline current state. The gap analysis and disabled rules outputs are the highest-value deliverables. Do not use the overall MITRE coverage percentage as an operational KPI without accounting for the hardcoded built-in figures.

---

## Related Notes

- [[Detection-KQL/Queries]] — KQL queries to address gaps identified by this tool
- [[Projects/M365-Hardening]] — M365 hardening project; table optimization findings feed here
- [[Threat-Hunting/TTPs]] — Cross-reference gap output against active TTP tracking

---

## Actions

- [ ] Install `pwsh` and `azure-cli` on Mac
- [ ] Review `.psm1` source before running — confirm no unexpected outbound calls
- [ ] Run against Sentinel workspace and export HTML report
- [ ] Cross-reference gap analysis output against Handala/CL-STA-1128 TTP coverage
- [ ] Review disabled rules list for unintentional coverage regressions
- [ ] Action table optimization findings into M365-Hardening project

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-27 | Note created from tool analysis |
