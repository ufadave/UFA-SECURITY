---
title: INFO-Jasper-Sleet-North-Korean-IT-Worker-Infiltration-Detection-2026-04-21
date: 2026-05-21
source: "https://www.microsoft.com/en-us/security/blog/2026/04/21/detection-strategies-cloud-identities-against-infiltrating-it-workers/"
tags:
  - "#resource"
  - "#status/draft"
  - "#action-required"
  - "#identity"
  - "#cloud"
  - "#north-korea"
---

# INFO -- Jasper Sleet: Detection Strategies Against Infiltrating IT Workers (Microsoft, 2026-04-21)

**Source:** https://www.microsoft.com/en-us/security/blog/2026/04/21/detection-strategies-cloud-identities-against-infiltrating-it-workers/
**Date:** 2026-05-21 (forwarded by David Coombe)
**Author:** Microsoft Threat Intelligence

---

## What It Is

Microsoft Threat Intelligence blog covering Jasper Sleet (North Korea-aligned threat actor)
and the broader North Korean remote IT worker infiltration campaign. Jasper Sleet operatives
pose as legitimate remote technical hires using stolen or fabricated identities, AI-generated
personas, and deepfake-assisted video interviews to gain trusted employment and insider
access. Once embedded, they generate revenue for the DPRK regime and in higher-risk cases
enable data theft, extortion, or follow-on compromise of the hiring organization and its
downstream clients.

**Attack chain phases:**
1. Job discovery -- systematic surveying of career sites and hiring portals to identify
   technical roles; GenAI used to tailor applications and extract role-specific language
2. Identity fabrication -- stolen SSNs, AI-generated headshots, deepfake video interviews,
   fabricated employment histories with verifiable LinkedIn presence
3. Device infrastructure -- use of laptop farms in the target country, KVM switches for
   remote control, and residential proxies to mask true location (typically China, Russia,
   or DPRK)
4. Access establishment -- onboarding to M365, Azure, GitHub, internal tooling; immediate
   enumeration of accessible resources
5. Persistence and exfiltration -- data theft from SharePoint/OneDrive, lateral movement to
   client environments, and in some cases ransomware or extortion

---

## Relevance

Medium -- indirect but real. Your organisation is not a large enterprise with high-volume
technical hiring, which reduces the probability of a successful infiltration attempt.
However, the detection strategies are directly actionable for your Microsoft E5 environment
regardless of whether you are actively hiring. The cloud and identity detection opportunities
map to capabilities you already have (SigninLogs, AuditLogs, CloudAppEvents, MDE) and
overlap with detection work already in progress from the Storm-2949 case study.

**Most relevant detection anchors for your environment:**

- **Device compliance and registration anomalies** -- Jasper Sleet operatives use
  unregistered personal or farm devices routed through residential proxies. Devices lacking
  Intune compliance or Entra ID registration during onboarding are a signal. Your existing
  Conditional Access and Intune posture is relevant here.
- **Bulk data access early in tenure** -- OneDrive/SharePoint bulk downloads shortly after
  account creation map directly to the KQL-OneDrive-Bulk-File-Download-Detection rule
  already deployed.
- **Sign-in from residential proxy ASNs** -- Jasper Sleet routes through residential
  proxies (Bright Data, IPRoyal, etc.) to appear local. SigninLogs ASN/ISP fields can
  surface this -- the AADGraphActivityLogs gap is relevant here too.
- **GitHub repository cloning at scale** -- operatives clone entire internal repos
  immediately after access. No detection currently on file for this.
- **KVM/laptop farm indicators** -- multiple concurrent sessions from geographically
  disparate IPs under a single account; impossible travel; sign-in from IPs resolving
  to co-location or residential proxy ASNs within the same session.

**Note from David Coombe:** This article was forwarded directly by the CISO/stakeholder,
suggesting organisational awareness and potential incoming questions about detection
coverage. Worth preparing a brief summary of existing detections that address the
overlapping TTPs.

---

## Key Detection Opportunities (Microsoft-recommended)

| Signal | Table | Current Coverage |
|--------|-------|-----------------|
| Bulk OneDrive download post-hire | CloudAppEvents | ✅ Deployed -- KQL-OneDrive-Bulk-File-Download-Detection |
| Sign-in from new country post-SSPR | SigninLogs + AuditLogs | ✅ At Review -- KQL-SSPR-Followed-By-Sign-In |
| Unregistered device sign-in | SigninLogs | ❌ No detection on file |
| Bulk SharePoint/repo cloning | CloudAppEvents | ❌ No detection on file |
| Concurrent impossible travel sessions | SigninLogs | ❌ No detection on file |
| RBAC role assignment anomalies | AzureActivity | ✅ Deployed -- RULE-Azure-RBAC-Anomalous-Role-Assignment |

---

## Actions

- [ ] **Prepare a detection coverage summary** for David Coombe -- map existing deployed
  rules and in-progress KQL notes to the Jasper Sleet TTPs above. Demonstrates E5 stack
  value and closes the loop on his referral
- [ ] **Build detection for unregistered device sign-in** -- SigninLogs where
  `DeviceDetail.deviceId` is empty and `ResultType == 0`; scope to new accounts or
  accounts with recent SSPR activity
- [ ] **Evaluate bulk SharePoint/GitHub cloning detection** -- CloudAppEvents
  `ActionType == "FileDownloaded"` scoped to SharePoint team sites and GitHub; similar
  threshold approach to the OneDrive rule
- [ ] **Review hiring workflow** -- confirm whether your organisation uses video
  interviews for remote technical roles and whether identity verification steps are in
  place (government ID + liveness check)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-21 | Created -- forwarded by David Coombe; overlaps with Storm-2949 detection work |
