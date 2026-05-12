---
title: INFO-MDE-Controlled-Configuration-Defender-AV
date: 2026-05-12
source: "https://patchmypc.com/blog/controlled-configuration-for-microsoft-defender-antivirus-settings/"
tags:
  - "#resource"
  - "#status/draft"
  - "#endpoint"
---

# INFO — MDE Controlled Configuration for Defender AV Settings

**Source:** https://patchmypc.com/blog/controlled-configuration-for-microsoft-defender-antivirus-settings/
**Date:** 2026-05-12
**Author:** Patch My PC (OSINT/reverse engineering)

---

## What It Is

OSINT investigation into an undocumented Microsoft component called `ControlConfigAdapter` found in the MDE device inventory agent package. The author reverse-engineered the component and identified it as a management bridge with full round-trip behaviour: it imports a configuration payload via `MpImportConfigPayload`, retrieves payload status via `MpGetConfigPayloadStatus`, and continuously checks an "SCC state" (Secure Controlled Configuration) that drives policy reporting. The adapter is registered in the `ROOT\MicrosoftDeviceManagement_Extensibility_ControlConfig` WMI namespace and appears to be the plumbing for a forthcoming "Controlled Configuration" feature for Defender AV settings -- essentially a Microsoft-managed baseline that can enforce Defender settings centrally, similar to how Microsoft manages Exchange Online Protection defaults.

Separately, note that as of platform release 4.18.25110.6 (rolled out March 2026), Defender AV exclusion values are no longer stored in the local registry (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`) for tenants using MDE security settings management. `Get-MpPreference` is now the required method to retrieve antivirus configuration settings.

---

## Relevance

Low-Medium -- awareness item. Controlled Configuration is not yet generally available and no official Microsoft documentation exists. The registry exclusion storage change (4.18.25110.6) is already rolled out and directly relevant if any internal scripts or monitoring tools read exclusions from the registry. Worth checking whether any KQL or monitoring logic relies on the old registry path.

---

## Actions

- [ ] **Verify** no internal scripts or KQL queries rely on `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` for exclusion enumeration -- use `Get-MpPreference` going forward (PowerShell, not KQL)
- [ ] **Monitor** for official Microsoft announcement of Controlled Configuration GA -- may affect how Defender AV baselines are managed in Intune vs MDE security settings management

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created -- awareness of upcoming Controlled Configuration feature and registry exclusion storage change |
