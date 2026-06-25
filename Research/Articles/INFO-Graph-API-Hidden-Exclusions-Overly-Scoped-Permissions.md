---
title: INFO-Graph-API-Hidden-Exclusions-Overly-Scoped-Permissions
date: 2026-06-25
source: "https://blog.amberwolf.com/blog/2026/june/microsoft-graph-api---hidden-exclusions-with-overly-scoped-permissions/"
tags:
  - "#resource"
  - "#status/draft"
  - "#identity"
  - "#cloud"
---

# INFO -- Graph API: Hidden Exclusions with Overly Scoped Permissions (Amberwolf, June 2026)

**Source:** https://blog.amberwolf.com/blog/2026/june/microsoft-graph-api---hidden-exclusions-with-overly-scoped-permissions/
**Date:** 2026-06-25
**Author:** Amberwolf

> Note: Article was too recently published to be indexed at triage time. Summary
> is based on the article title, the Microsoft Graph permissions model, and related
> Microsoft documentation. Review the actual article for specific findings and
> technique details.

---

## What It Is

Research article on a class of "hidden exclusions" in Microsoft Graph API permission
behaviour that occurs when overly broad application permissions are granted. The core
issue in the Graph API permissions model: when an app is granted broad application
permissions (e.g., `Mail.Read`, `User.Read.All`, `Files.Read.All`), the permission
applies tenant-wide without restriction by default.

Microsoft does provide scoping mechanisms, but they are not obvious and require
explicit out-of-band configuration:

- **Exchange application access policies** -- restrict `Mail.*` and EWS/IMAP application
  permissions to specific mailboxes via security groups (the same mechanism identified
  in the SAP PO IMAP investigation, June 2026)
- **Sites.Selected permission** -- for SharePoint/OneDrive, `Sites.Selected` is a
  granular alternative to `Sites.ReadWrite.All` that restricts to specific sites
- **Resource-Specific Consent (RSC)** -- for Teams, allows apps to request permissions
  scoped to a specific team or chat rather than all Teams in the tenant
- **Administrative Units** -- can scope directory permissions to a subset of users/groups

The "hidden exclusions" angle likely refers to cases where: (a) these scoping mechanisms
are not applied by default even when the granted permissions appear broad, or (b) there
are behaviours in the Graph API where broadly-granted permissions interact with
exclusion configurations in non-obvious ways that either under-restrict or over-restrict
access compared to what an admin would expect from the permission name alone.

---

## Relevance

Medium-High -- directly relevant to the deployed Graph API Broad Permission Grant rule
and the recent SAP PO IMAP finding. The article's topic is the same scoping gap that
the SAP PO IMAP investigation raised: `IMAP.AccessAsUser.All` granted `OnBehalfOfAll`
is effectively tenant-wide unless an Exchange application access policy is applied.
Understanding where the Graph API permission model has "hidden" scoping behaviours is
important for both detection (knowing what to flag) and hardening (knowing what to fix).

**Fetch and review the actual article** -- the specific "hidden exclusions" technique
or finding may be directly actionable for the Graph permission grant detection rule or
the app registration audit.

---

## Actions

- [ ] **Fetch and read the full article** -- summary is inferred; actual findings may be
  more specific or actionable than described here
- [ ] Cross-reference with the SAP PO IMAP investigation findings and
  [[RULE-Graph-API-Broad-Permission-Grant-Service-Principal]] exclusion logic

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-25 | Created -- article too new to index at triage; summary inferred from title and Graph permissions model; review actual article for specific findings |
