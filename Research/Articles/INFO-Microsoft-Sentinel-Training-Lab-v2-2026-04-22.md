---
title: INFO-Microsoft-Sentinel-Training-Lab-v2-2026-04-22
date: 2026-05-21
source: "https://techcommunity.microsoft.com/blog/microsoftsentinelblog/introducing-the-microsoft-sentinel-training-lab-hands-on-security-operations-in-/4513274"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- Microsoft Sentinel Training Lab v2 (2026-04-22)

**Source:** https://techcommunity.microsoft.com/blog/microsoftsentinelblog/introducing-the-microsoft-sentinel-training-lab-hands-on-security-operations-in-/4513274
**GitHub:** https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Microsoft-Sentinel-Training-Lab
**Date:** 2026-05-21 (forwarded by David Coombe)
**Author:** Andreas Kapetaniou / Paul Kew, Microsoft

---

## What It Is

Open-source, one-click deploy training environment that stands up a fully functional
Microsoft Sentinel workspace preloaded with realistic attack telemetry. Version 2.0
released April 2026. Deploys pre-recorded data from six security products, custom
detection rules that fire real incidents, workbooks, watchlists, and playbooks -- no
agents, connectors, or attack simulation required. Near-zero cost (~10 MB data, 30-day
Sentinel free trial on new workspaces).

**Requirements:**
- Azure subscription with Owner or Contributor on the target resource group
- Sentinel workspace onboarded to Microsoft Defender XDR (unified SecOps platform)
- User-Assigned Managed Identity with `CustomDetection.ReadWrite.All` Graph permission
  for custom detection rule deployment (optional -- can be skipped)

---

## Relevance

Medium -- training and skills development resource. Directly relevant for building
KQL and Sentinel rule tuning skills against realistic telemetry without risking your
production environment. Useful for:

- Testing new KQL detection logic against realistic multi-stage incident data before
  deploying to production
- Training scenario for incident triage and pivot workflows
- Validating playbook and automation rule behaviour in isolation

Given the current detection engineering workload (Storm-2949 detections, SSPR, RBAC,
OneDrive) this lab provides a safe environment to iterate on query logic without
generating noise in the live Sentinel workspace.

Note: Forwarded by David Coombe on the same day as the Jasper Sleet article -- may
indicate interest in Sentinel skill development or upcoming training initiative.

---

## Actions

- [ ] Deploy to a test Azure subscription and evaluate as a KQL development sandbox
- [ ] Confirm whether the lab includes identity-based attack telemetry (SigninLogs,
  AuditLogs scenarios) relevant to current detection backlog

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-21 | Created -- forwarded by David Coombe |
