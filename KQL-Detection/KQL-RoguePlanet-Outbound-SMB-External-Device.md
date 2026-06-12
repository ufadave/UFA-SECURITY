---
date: 2026-06-11
title: "RoguePlanet Outbound SMB External Host Detection"
table: "DeviceNetworkEvents"
schema: "Advanced Hunting"
mitre:
  - "T1080"
tactic: "Lateral Movement"
technique: "Taint Shared Content"
status: "done"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/done"
  - "#endpoint"
  - "#network"
---

# KQL — RoguePlanet Outbound SMB External Host Detection

---

## Purpose

Detects outbound SMB connections (TCP/445) from workstations to non-RFC1918 (external/non-corporate) destinations. This closes the remote SMB coercion vector used in the original RoguePlanet RCE path, where a victim is coerced into opening a crafted `.vhd(x)` from an attacker-controlled SMB share, triggering Defender file-handling against remote symlinks. Also a useful general-purpose perimeter hygiene check — outbound 445 from workstations to the internet should never occur.

Secondary-fidelity signal — correlate with the primary MsMpEng shell spawn detection.

---
## Note
We already have a similar detection in place. 
## Query

```kql
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
// Exclude RFC1918 private address space
| where not (RemoteIP startswith "10.")
| where not (RemoteIP startswith "192.168.")
| where not (
    RemoteIP startswith "172.16." or RemoteIP startswith "172.17." or
    RemoteIP startswith "172.18." or RemoteIP startswith "172.19." or
    RemoteIP startswith "172.20." or RemoteIP startswith "172.21." or
    RemoteIP startswith "172.22." or RemoteIP startswith "172.23." or
    RemoteIP startswith "172.24." or RemoteIP startswith "172.25." or
    RemoteIP startswith "172.26." or RemoteIP startswith "172.27." or
    RemoteIP startswith "172.28." or RemoteIP startswith "172.29." or
    RemoteIP startswith "172.30." or RemoteIP startswith "172.31."
)
// Exclude loopback
| where not (RemoteIP startswith "127.")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    ActionType
| order by Timestamp desc
```

> ⚠️ **Schema notes:**
> - `ipv4_is_in_range()` is preferred if available in your tenant schema — replace `startswith` chains with that function for cleaner subnet matching.
> - `RemoteUrl` may not populate for raw SMB connections — include for context where available but don't depend on it.
> - Validate `ActionType` values in your tenant; `ConnectionSuccess` is standard but confirm.

---

## Validated Columns

- [x] `RemotePort` — `DeviceNetworkEvents` — standard, confirmed
- [ ] `ActionType` — `DeviceNetworkEvents` — standard; confirm `"ConnectionSuccess"` is valid in your tenant
- [x] `RemoteIP` — `DeviceNetworkEvents` — standard, confirmed
- [x] `RemoteUrl` — `DeviceNetworkEvents` — validate availability by sensor version
- [x] `InitiatingProcessFileName` — `DeviceNetworkEvents` — standard, confirmed
- [x] `ipv4_is_in_range()` — Advanced Hunting function — validate if you wish to refactor subnet exclusions

---

## Test Results

<!-- Paste CSV results here after running in Advanced Hunting -->

---

## Deployment

### MDE Custom Detection Rule

| Field | Detail |
|-------|--------|
| **Rule Name** | `Custom - Outbound SMB to External Host from Workstation` |
| **Table** | `DeviceNetworkEvents` |
| **Schema** | Advanced Hunting |
| **Frequency** | Every 1h |
| **Lookback** | 1h |
| **Severity** | Medium |
| **MITRE** | T1080 — Taint Shared Content |
| **Actions** | Alert SOC; investigate initiating process and destination |
| **False Positive Risk** | Low — outbound TCP/445 from workstations to internet should not occur if perimeter controls are correct. If FPs surface, they indicate a hardening gap. |

<!-- INACTIVE: Sentinel Analytics Rule — DeviceNetworkEvents is not ingested into Log Analytics. Deploy via MDE Advanced Hunting Custom Detection only. -->

---

## Hardening Control Pair

- Confirm TCP/445 outbound blocked at perimeter firewall for all workstation subnets
- Verify Windows Firewall with Advanced Security (Intune-managed) blocks outbound 445 to non-corporate destinations

---

## Related Notes

- [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]]
- [[KQL-RoguePlanet-MsMpEng-Shell-Spawn-Device]]
- [[KQL-RoguePlanet-VHDX-Mount-Suspicious-Path-Device]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created — companion to [[INTEL-RoguePlanet-Nightmare-Eclipse-Defender-TOCTOU-LPE]] |
