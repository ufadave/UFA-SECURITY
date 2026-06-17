---
title: INFO-Microsoft-Edge-Management-Service-Configuration-Policies
date: 2026-06-17
source: "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-management-service"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
---

# INFO -- Microsoft Edge Management Service: Configuration Policies

**Source:** https://learn.microsoft.com/en-us/deployedge/microsoft-edge-management-service
**Date:** 2026-06-17
**Author:** Microsoft Learn

---

## What It Is

The Microsoft Edge management service is a dedicated browser management experience
in the Microsoft 365 Admin Center that allows IT admins to configure and deploy Edge
browser policies directly to Entra ID-authenticated user profiles -- without requiring
Group Policy Objects (GPO) or a full Intune configuration profile for each setting.

Enabled by default for Edge 115.1935 and later. Any Edge browser signed into a work
account (Entra ID) automatically checks in with the management service for assigned policies.

**Two policy types:**

- **Cloud policies** -- created and managed only in the Edge management service. Support
  policy priority/conflict resolution, extension request management, and org branding.
  Cannot be managed from the Intune portal.

- **Intune policies** -- created via the Edge management service but synced to Intune
  (appear under Devices > Configuration in Intune). Support device-level targeting and
  exclusion filters not available in cloud-only mode. Can be managed from either portal.

**Key capabilities:**
- Policy priority ordering (Cloud policies) -- resolve conflicts by priority number;
  Intune policies do not auto-resolve conflicts
- Extension management -- approve/deny user extension requests; lock extension config
- Organization branding -- custom logo, colour, new tab page customisation
- Enrollment token assignment -- deploy policy without group assignment via
  `EdgeManagementEnrollmentToken` GPO/MDM value

**Important caveat:** Edge management service policies are overridden by conflicting GPOs
or Intune MDM policies on the device. Device-level Intune policies take precedence.

---

## Relevance

Low-Medium -- filed as a reference for future browser hardening work. The Intune-managed
endpoint estate already controls Edge via Intune configuration profiles and potentially GPO.
The Edge management service would be most useful for:

- Rapid deployment of browser policies to cloud-only or Entra-joined devices without GPO
- Extension request governance -- letting users request extensions and admin-approving
  specific ones rather than blanket-allowing or blocking all extensions
- Org branding on Edge for consistent enterprise appearance

**Security-relevant policies worth considering when the time comes:**
- Disable extension install from outside the approved extension list
- Block password saving (covered separately by Credential Guard/password manager policy)
- Configure SmartScreen enforcement
- Block access to `edge://flags` (prevents users disabling security features)
- Restrict InPrivate mode for managed devices

---

## Actions

- [ ] File as reference for future Edge browser hardening work
- [ ] No immediate action required

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-17 | Created -- Microsoft Edge management service reference; filed for future browser hardening work |
