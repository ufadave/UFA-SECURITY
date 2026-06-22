---
title: INFO-Entra-B2B-SharePoint-OneDrive-Integration-Forced-Rollout
date: 2026-06-19
source: "https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-integration"
tags:
  - "#resource"
  - "#status/done"
  - "#identity"
  - "#cloud"
  -
---

# INFO -- Microsoft Entra B2B Integration for SharePoint & OneDrive: Forced Rollout

**Source:** https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-integration
**Date:** 2026-06-19
**Reference:** https://learn.microsoft.com/en-us/sharepoint/faqs-odspintegrationwithentrab2b

---

## What It Is

Microsoft is forcing all tenants onto Entra B2B-based guest authentication for SharePoint
and OneDrive external sharing, retiring the legacy SharePoint Online one-time-passcode (OTP)
recipient model. This is not optional and not tenant-configurable past the rollout date.

**Critical timeline:**
- **May 2026:** Microsoft began enabling Entra B2B integration for all tenants regardless
  of the `EnableAzureB2BIntegration` setting. Once rolled out, this setting has no effect
  and the ability to disable it is removed.
- **End of April 2026:** Last date tenants could manually enable in advance (now passed).
- **July 2026:** Hard cutoff -- external collaborators WITHOUT a Microsoft Entra B2B guest
  account in the directory will see "access denied" on previously shared content.

**What changes:** External users accessing previously shared links may encounter "This
organization updated its guest access settings." Guests now get an actual Entra B2B guest
account (subject to CA, MFA, access reviews) rather than an ad hoc OTP-verified recipient
with no CA enforcement.

**No resharing required for existing links IF the guest already has a B2B account.** Only
legacy-OTP guests without a B2B account will lose access in July. Previously shared links
do not need to be reshared if a B2B guest account exists.

---

## Security Impact

This is a meaningful security improvement, not just a platform change:

- **CA policy coverage expands to all external collaborators** -- ad hoc OTP recipients
  previously bypassed Conditional Access entirely. After transition, all guests are subject
  to existing CA policies (MFA requirements, device compliance, sign-in risk).
- **Guest lifecycle becomes manageable** -- B2B guest accounts can be subject to access
  reviews, PIM governance, and Entra Identity Protection.
- **Directly relevant to the CA refactor** -- the CA refactor with Ben should include
  reviewing whether existing guest-facing CA policies remain appropriate for the expanded
  guest population created by the B2B rollout.

---

## Relevance

High and time-sensitive. July 2026 cutoff is approximately 2 weeks away. If external
collaborators (vendors, suppliers, auditors, partners) have legacy OTP-based access to
SharePoint or OneDrive content without a B2B guest account, they will lose access.

**To identify at-risk guests:** Use the external sharing report in the SharePoint Admin
Center to get a list of guests invited via SPO OTP who do not yet have a Microsoft Entra
B2B guest account. Look at the "User E-mail" column per Microsoft guidance.

---

## Actions

- [ ] **Pull the external sharing report** from SharePoint Admin Center to identify guests
  with legacy OTP access but no Entra B2B guest account
- [ ] **Proactively create B2B guest accounts** for identified legacy-OTP guests before
  the July 2026 cutoff to avoid access disruption
- [ ] **Confirm CA policies account for the expanded guest population** -- verify no
  unintended blocking of legitimate external collaborators after transition
- [ ] **Communicate to stakeholders** who manage external sharing relationships about
  potential July 2026 access disruption
- [ ] **Add to CA refactor scope** -- review guest-facing CA policy behaviour post-B2B rollout

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-19 | Created -- forced B2B rollout, July 2026 hard cutoff for legacy OTP guests; tagged #action-required |
