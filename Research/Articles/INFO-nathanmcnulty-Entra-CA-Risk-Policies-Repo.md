---
title: INFO-nathanmcnulty-Entra-CA-Risk-Policies-Repo
date: 2026-06-17
source: "https://github.com/nathanmcnulty/nathanmcnulty/tree/main/Entra/conditional-access/risk-policies"
tags:
  - "#resource"
  - "#status/done"
  - "#identity"
  
---

# INFO -- Nathan McNulty: Entra Conditional Access Risk Policies (GitHub)

**Source:** https://github.com/nathanmcnulty/nathanmcnulty/tree/main/Entra/conditional-access/risk-policies
**Date:** 2026-06-17
**Author:** Nathan McNulty (nathanmcnulty)

---

## What It Is

Nathan McNulty's Entra conditional access risk-policies folder in his public GitHub repo.
Contains deployable CA policy templates and scripts specifically for risk-based Conditional
Access -- sign-in risk policies and user risk policies using Microsoft Entra ID Protection
signals, deployable via PowerShell/Graph API rather than manual portal configuration.

McNulty is a recognised practitioner in the Entra/Intune community and previously authored
the ASR rules implementation guide already in the vault
([[INFO-Nathan-McNulty-MDE-ASR-Rules-Implementation-Guide]]).

---

## Why This Is Time-Sensitive

<br>

> ⚠️ **Microsoft is retiring legacy ID Protection risk policies on October 1, 2026.**

The legacy risk policies configured directly in Microsoft Entra ID Protection (the
"User risk policy" and "Sign-in risk policy" configured under ID Protection > Policies)
are being retired October 1, 2026. After that date they will stop enforcing.

**Migration path:** Equivalent policies must be recreated as Conditional Access policies
before October 1, 2026. This is not optional -- legacy policies will be disabled by Microsoft
on the retirement date regardless of configuration state.

Microsoft migration guidance:
https://learn.microsoft.com/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies

Key steps per Microsoft docs:
1. Create equivalent sign-in risk and user risk CA policies in **report-only mode**
2. Validate coverage using report-only data
3. Switch from Report-only to **On**
4. Disable the legacy ID Protection policies

McNulty's repo provides template implementations of these policies that can accelerate
step 1 -- particularly valuable during the active CA refactor with Ben.

---

## Relevance

**High and time-sensitive.** The CA refactor is already underway and the October 2026
deadline is under 4 months away. Risk-based CA policies are a core component of the
current threat mitigation posture:

- The SSPR Post-Reset Sign-In rule (`[[RULE-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device]]`)
  was designed to catch the Storm-2949 attack chain -- risk-based CA covering the same
  surface with automated identity risk signals is a complementary control.
- The AiTM BEC case (now closed) demonstrated that sign-in risk detection is critical for
  catching token theft scenarios -- ensuring sign-in risk CA policies are properly migrated
  and enforcing before October 1 directly addresses this threat class.
- User risk policies catch credential compromise scenarios (infostealers, leaked credentials)
  that are a persistent priority given the Iranian APT and infostealer threat profile.

**Note:** Risk-based CA requires **Microsoft Entra ID P2** -- confirm this is part of the
current E5 licence before building these policies.

---

## Actions

- [x] **Review McNulty's risk-policy templates** in the repo for sign-in risk and user risk
  policy configurations before the October 1, 2026 retirement deadline
- [x] **Confirm whether legacy ID Protection risk policies are currently enabled** in the
  tenant (ID Protection > Policies) -- if yes, migration is mandatory before October 1
- [x] **Add risk policy migration to the CA refactor scope** -- coordinate with Ben to
  ensure sign-in risk and user risk CA policies are included in the refactor workstream
- [x] **Enable report-only mode first** per Microsoft guidance -- validate coverage before
  switching to enforcement
- [x] Confirm Entra ID P2 licence is active (required for risk-based CA conditions)

---

## Related Notes

- [[INFO-Nathan-McNulty-MDE-ASR-Rules-Implementation-Guide]]
- [[RULE-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device]]
- [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- [[INFO-TrustedSec-Privileged-Entra-ID-Roles-Nobody-Talks-About]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created -- legacy ID Protection risk policies retiring October 1, 2026; migration to CA risk policies time-sensitive; McNulty templates directly useful during CA refactor |
