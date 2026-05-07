---
title: RESEARCH-TrustedSec-GPO-UNC-Path-Hijacking-ARP-Spoof
date: 2026-05-05
source: "https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay"
author: "Austin Coontz — TrustedSec"
mitre:
  - "T1557"
  - "T1557.002"
  - "T1021.002"
  - "T1078"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#network"
  - "#identity"
  - "#endpoint"
---

# RESEARCH-TrustedSec-GPO-UNC-Path-Hijacking-ARP-Spoof

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay |
| **Author** | Austin Coontz — TrustedSec |
| **Date Observed** | 2026-05-05 |
| **Date Published** | 2026-04-30 |
| **Patch Available** | No CVE / no patch — AD misconfiguration and network architecture issue |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1557 | Adversary-in-the-Middle |
| T1557.002 | ARP Cache Poisoning |
| T1021.002 | Remote Services: SMB/Windows Admin Shares |
| T1078 | Valid Accounts (WriteGPLink abuse) |

---

## Summary

TrustedSec researcher Austin Coontz documents three distinct attack chains that weaponize GPO UNC path references via ARP spoofing from an authenticated, network-adjacent position. Attack 1 chains `WriteGPLink` on an OU with a pre-existing GPO software deployment — ARP spoofing the referenced UNC server during a target reboot causes a malicious MSI to execute as SYSTEM, with no SYSVOL modification required. Attack 2 exploits drive map GPOs to capture NTLMv2 hashes or force WebDAV fallback (NTLM over HTTP) for relay to LDAP(S)/AD CS/SMB. Attack 3 uses logon/startup script UNC paths to serve replacement script content at execution time. All three require only authenticated domain access, layer-2 adjacency to the target, and the presence of existing GPOs referencing UNC paths by direct hostname (domain-namespace paths are harder to spoof due to DFS referrals). A supporting tool, `parse_sysvol.py`, is released to enumerate vulnerable GPOs from SYSVOL.

---

## Relevance to Environment

**High relevance** given the hybrid AD environment across Alberta, BC, and Saskatchewan locations. GPO-based software deployment and mapped drives are common configurations in distributed environments like yours. The attack requires only standard authenticated domain access and local network adjacency — a compromised endpoint on the same broadcast domain as a DC or file server is sufficient. Key questions to assess: Are any GPO UNC paths using direct hostnames (not DFS/domain-namespaced paths)? Does SYSVOL contain stale software installation GPOs? Are any OUs over-permissioned for `WriteGPLink` for `Authenticated Users` or `Domain Computers`? SMB signing is already deployed in your environment (confirmed hardening control), which mitigates the SMB relay variant of Attack 2, but NTLMv2 capture for offline cracking and WebDAV relay paths remain relevant.

**Note:** SMB signing enforced = Attack 2 SMB relay blocked, but NTLMv2 hash capture + offline cracking still viable. WebDAV relay (HTTP NTLM) to LDAP/AD CS is NOT blocked by SMB signing.

---

## Detection Notes

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound SMB connections from endpoints to unexpected hosts during logon
// Rationale: ARP-spoof attack redirects UNC path connections to attacker — endpoint will initiate
//            SMB to an IP that doesn't normally serve that path

DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 445
| where InitiatingProcessFileName in~ ("svchost.exe", "System")
| where ActionType == "ConnectionSuccess"
// Enrich: flag connections where RemoteIP is not a known DC or file server
// Build a known-good list: let known_smb_servers = dynamic(["x.x.x.x", "x.x.x.x"]);
// | where RemoteIP !in (known_smb_servers)
| summarize count() by DeviceName, RemoteIP, bin(Timestamp, 15m)
| sort by count_ desc
```

```kql
// Table: SecurityEvent
// Schema: Sentinel / Log Analytics
// Purpose: Detect NTLMv2 authentication events to unexpected destinations
// Event ID 4624 with LogonType 3 (network) and NTLM authentication package

SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$" // exclude machine accounts
| summarize count() by TargetUserName, IpAddress, WorkstationName, bin(TimeGenerated, 15m)
| where count_ > 5
| sort by count_ desc
```

```kql
// Table: DeviceEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect WriteGPLink abuse — monitor for gPLink attribute modification events
// Note: This may require DCshadow/LDAP monitoring — validate availability in your environment

DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "LdapSearch" or ActionType contains "LDAP"
| where AdditionalFields has "gPLink"
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

### Validated Columns
- [ ] `RemotePort` in `DeviceNetworkEvents` — confirm column name (may vary)
- [ ] `AuthenticationPackageName` in `SecurityEvent` — confirm column exists and NTLM auth is audited
- [ ] `ActionType contains "LDAP"` in `DeviceEvents` — validate LDAP audit events are present in your MDE schema
- [ ] `IpAddress` in `SecurityEvent` — confirm this reflects the authenticating client IP in your Sentinel setup

---

## Hardening Actions

- [ ] Audit SYSVOL for GPO UNC paths using direct hostnames vs. domain-namespaced DFS paths — direct hostnames are spoof-vulnerable
- [ ] Review `WriteGPLink` permissions in BloodHound — flag any `Authenticated Users` or `Domain Computers` with this edge
- [ ] Verify SMB signing enforcement is consistent across all segments (already deployed, confirm OT/SCADA segment coverage)
- [ ] Review WebDAV service status — disable WebClient service on endpoints where not required to block WebDAV NTLM relay fallback
- [ ] Consider UNC path hardening via GPO: `Computer Configuration > Administrative Templates > MS Security Guide > Extended Protection for NTLM`

---

## Related Notes

- [[Hardening/Controls/HARD-SMB-Signing]]
- [[Hardening/Controls/HARD-NTLMv2-Enforcement]]
- [[Threat-Hunting/TTPs/]]

---

## Tags

#intel #status/draft #network #identity #endpoint

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-05 | Created — TrustedSec GPO UNC path hijacking via ARP spoof |
