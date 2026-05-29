---
title: INFO-KustoHawk-Incident-Triage-Response-Tool-Defender-XDR-Sentinel
date: 2026-05-28
source: "https://github.com/Bert-JanP/KustoHawk"
tags:
  - "#resource"
  - "#status/draft"
---

# INFO -- KustoHawk: Lightweight Incident Triage and Response Tool

**Source:** https://github.com/Bert-JanP/KustoHawk
**Date:** 2026-05-28
**Author:** Bert-Jan Pals (@BertJanCyber) -- launched at KustoCon 2026

---

## What It Is

KustoHawk is a lightweight open-source PowerShell-based incident triage and response
tool for Microsoft Defender XDR and Sentinel environments. Given a device ID or
account, it runs a configurable set of KQL hunting queries via the Graph API and
returns a complete picture of all activities performed by that entity across the unified
XDR workspace. Output is presented in the terminal (verbose mode) or exported to
HTML and CSV files for further investigation. Only results with hits are shown by
default, keeping output actionable.

**Core workflow:** Analyst provides a device ID or account identifier → KustoHawk
connects to the Graph API → runs the query set in the Resources folder against
Advanced Hunting → returns a scoped triage picture.

**Authentication options:** Interactive, Service Principal, Managed Identity, or
Device Code -- flexible for both analyst-run and automated playbook use.

**Query customisation:** The Resources folder contains the KQL query set as JSON.
Custom queries can be added -- the JSON format accepts any valid KQL with
placeholder substitution for device/account and timeframe parameters.

---

## Relevance

High -- directly applicable to the current MDE/Sentinel environment. This fills a
specific gap in the daily workflow: when an alert fires and an analyst needs a rapid
entity-centric triage view (all alerts, process events, network events, logon events
for a given device or account), KustoHawk automates what is currently done manually
via a series of separate Advanced Hunting queries.

**Particularly useful for:**
- Initial triage of MDE Custom Detection alerts -- run KustoHawk on the alerted device
  to get a scoped activity picture before pivoting deeper
- Active incident response -- rapid entity profiling during the FIND-IR-2026-05-07-lt13069
  style investigations where multiple pivots are needed across tables
- Account investigation -- given a suspicious UPN, get all related alerts, sign-ins,
  cloud app events, and audit events in one pass

**Limitation:** PowerShell-based. Given limited PowerShell proficiency, this is best
used as a read-only triage aid rather than a response automation tool. The Graph API
connection requires appropriate app permissions (`ThreatHunting.Read.All` at minimum).

---

## Actions

- [ ] Review query set in Resources folder -- assess coverage against current detection
  backlog and active IR cases
- [ ] Evaluate for use in active FIND-IR-2026-05-07-lt13069 investigation -- run against
  lt13069 device and the net user tcai account for a rapid activity summary
- [ ] Confirm Graph API permissions available for service principal or interactive auth
  in the tenant before running

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-28 | Created |
