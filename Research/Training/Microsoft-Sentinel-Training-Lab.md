# Resource — Microsoft Sentinel Training Lab

**Source:** https://techcommunity.microsoft.com/blog/microsoftsentinelblog/introducing-the-microsoft-sentinel-training-lab-hands-on-security-operations-in-/4513274
**GitHub:** https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Microsoft-Sentinel-Training-Lab/README.md
**Via:** cyb3rmik3
**Date:** 2026-04-22
**Type:** Training Lab / Hands-on Environment

---

## What It Is
A one-click deployable Microsoft Sentinel training environment with pre-loaded realistic attack telemetry across six data sources. Deploys a fully functional Sentinel workspace with incidents already firing — no agent setup or attack simulation required. Built by the Microsoft Sentinel team, open source under Azure/Azure-Sentinel.

---

## What's Included
- Pre-recorded telemetry from: CrowdStrike, Palo Alto Networks, Okta, AWS CloudTrail, GCP Audit Logs, MailGuard365
- 22 custom detection rules generating correlated XDR incidents
- MITRE ATT&CK coverage across 10 tactics
- 16 guided exercises spanning detection engineering, cost management, data lake, and AI-powered investigation

---

## Exercise Highlights Relevant to Your Stack

| Exercise | Topic | Relevance |
|----------|-------|-----------|
| Ex 1 | Advanced Hunting + first detection rule | Direct KQL practice |
| Ex 5 | Cross-platform device isolation | MDE response workflows |
| Ex 6 | Tune port scan detection thresholds | Reduce Sentinel noise |
| Ex 7 | Detect Okta MFA factor manipulation | Identity detection patterns |
| Ex 8 | Enrich detections with watchlists | Sentinel enrichment |
| Ex 9 | Ingestion cost monitoring | Cost management |
| Ex 14 | 10 AI prompts with Sentinel MCP Server | Copilot/AI-assisted hunting |

---

## Requirements
- Azure subscription (free trial works)
- Owner or Contributor role on the subscription
- Sentinel workspace onboarded to Defender XDR

Deployment takes ~30 minutes.

---

## Actions
- [ ] Deploy lab to personal Azure subscription for hands-on practice
- [ ] Work through Ex 1 (Advanced Hunting) and Ex 6 (tuning thresholds) as priorities
- [ ] Review Ex 14 — Sentinel MCP Server AI prompts — relevant to current Claude/AI tooling work
- [ ] Check if lab detection rules can be adapted for your production Sentinel workspace

---

## Tags
#resource #sentinel #training #kql #advanced-hunting #detection-engineering #mcp

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-24 | Created |
