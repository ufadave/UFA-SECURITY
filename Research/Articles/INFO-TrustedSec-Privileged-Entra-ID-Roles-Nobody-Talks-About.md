---
title: INFO-TrustedSec-Privileged-Entra-ID-Roles-Nobody-Talks-About
date: 2026-06-16
source: "https://trustedsec.com/blog/the-privileged-roles-nobody-talks-about"
tags:
  - "#resource"
  - "#status/done"
  - "#identity"
  
---

# INFO -- TrustedSec: The Privileged Entra ID Roles Nobody Talks About

**Source:** https://trustedsec.com/blog/the-privileged-roles-nobody-talks-about
**Date:** 2026-06-16
**Author:** TrustedSec
**Related:** https://trustedsec.com/blog/managing-privileged-roles-in-microsoft-entra-id-a-pragmatic-approach

---

## What It Is

TrustedSec blog series on Microsoft Entra ID privileged role governance, specifically
covering roles that carry significant privilege but are overlooked in most hardening
reviews because they don't appear in Microsoft's formal "privileged" label set or are
underestimated relative to their actual blast radius.

The article builds on TrustedSec's pragmatic Entra role tiering model (Tier 0 / Tier 1 /
Tier 2), which classifies roles more granularly than Microsoft's own labeling. The series
has been building toward this post: earlier instalments covered Tier 0 roles (Global
Administrator, Privileged Role Administrator, Privileged Authentication Administrator,
Application Administrator, Hybrid Identity Administrator) and Tier 1 roles with write
capabilities or known indirect escalation paths.

**The "nobody talks about" roles** -- based on TrustedSec's Hardening Review casework --
are roles that:
- Are frequently over-assigned because they appear read-only or limited in scope
- Have known indirect escalation paths to Tier 0 that aren't documented by Microsoft
- Are excluded from PIM in most environments because they're not on the "privileged" list
- Show up as bulk assignments in Entra audits without triggering any alert

Examples from TrustedSec's framework (per the managing privileged roles post):
- **Application Administrator / Cloud Application Administrator** -- full control over
  application registrations; can assume identity of privileged apps by updating credentials
- **Conditional Access Administrator** -- can modify CA policies, dramatically changing
  tenant security posture including disabling MFA enforcement
- **Authentication Administrator** -- can set/reset authentication methods for non-admins;
  indirect path to assume identities of app owners and escalate to privileged apps
- **Partner Tier2 Support** -- Microsoft states should not be used; historical escalation risk

---

## Relevance

High and directly actionable. The active CA policy refactor with Ben is the exact context
where over-assigned or under-governed Entra roles matter most: if any non-Tier-0 account
has Conditional Access Administrator or Application Administrator, those accounts represent
a parallel path to undermine the refactored CA policy entirely.

**Immediate cross-reference:** The Graph API Broad Permission Grant rule has already surfaced
two real consent events (ChatGPT, SAP PO IMAP). Both were granted by admin accounts with
appropriate roles -- but the TrustedSec framework is a prompt to confirm those role assignments
are governed via PIM with time-limited activation, not permanently active.

**Tie to active threat priority:** The Entra Agent ID Administrator role (formerly without a
service principal hijack fix until April 9, 2026 patch) is exactly the kind of role this
series focuses on -- elevated privilege not clearly documented, frequently overlooked.

---

## Actions

- [ ] Review TrustedSec's full "privileged roles" post for the specific roles listed
- [ ] Cross-reference with current Entra role assignments: which accounts hold
  Conditional Access Administrator, Application Administrator, Authentication Administrator?
- [ ] Confirm those assignments are PIM-governed (just-in-time) rather than permanently active
- [ ] Add any identified over-assigned roles to the Entra app registration audit scope

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-16 | Created -- TrustedSec Entra privileged role series; marked #action-required for role assignment review during CA refactor |
