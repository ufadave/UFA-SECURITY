---
title: "TrustedSec — ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution & NTLM Relay"
date: 2026-05-01
source: https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay
type: research
status: draft
tags:
  - "#resource"
  - "#network"
  - "#identity"
  - "#endpoint"
  - "#status/draft"
  - "#action-required"
---

# RESEARCH — TrustedSec: GPO UNC Path Hijacking for Code Execution & NTLM Relay

## Source
- **URL:** https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay
- **Date:** 2026-05-01
- **Author:** TrustedSec

> **Note:** Direct URL fetch was blocked. Content reconstructed from corroborating TrustedSec blog posts (DACL detection series, Weaponizing GPO Access), the WithSecure GPO hijacking research, and the adsecurity.org MS15-011 analysis. The specific "ARP Around and Find Out" post was not directly readable — tag `#pending-review` for manual verification.

## What It Is

A TrustedSec blog post covering an attack chain that combines ARP spoofing with GPO UNC path manipulation to achieve code execution and/or NTLM relay attacks against domain-joined Windows systems. The core technique involves redirecting GPO file retrieval — specifically the `gPCFileSysPath` attribute or GPO SYSVOL UNC paths — to an attacker-controlled server via ARP poisoning on the local segment. When a domain client applies group policy, it reaches out to what it believes is the DC's SYSVOL share, but instead connects to the attacker host, enabling:

1. **NTLM credential capture/relay** — the machine account or user authenticates to the spoofed server
2. **Malicious GPO delivery** — attacker serves a modified `GptTmpl.inf` with registry keys for code execution (Run keys, AppInit DLLs, new services)

This is related to the MS15-011 / "Hardened UNC Paths" vulnerability class. The hardening control (`RequireMutualAuthentication=1, RequireIntegrity=1` on SYSVOL/NETLOGON shares) is the primary defence, but requires both the patch *and* the GPO configuration to be in place.

## Relevance to Environment

**High.** Your environment is hybrid AD, spans multiple provinces with potentially flat or poorly segmented network segments (especially at newly acquired fertilizer plant). The attack requires local network access — an insider, a compromised endpoint on the same VLAN, or a breach at a remote site could enable this. The OT/SCADA environment at the fertilizer plant is explicitly not confirmed as segmented. ARP-based attacks are feasible on any unsegmented LAN.

Your existing NTLMv2 enforcement and SMB signing controls partially mitigate this, but NTLM relay to LDAP(S) remains viable if LDAP signing/channel binding is not enforced on all DCs, or if signing-enabled relay targets are reachable.

## Actions
- [ ] Verify Hardened UNC Paths GPO is configured for `\\*\SYSVOL` and `\\*\NETLOGON` with `RequireMutualAuthentication=1` and `RequireIntegrity=1` — this is the primary countermeasure
- [ ] Confirm LDAP signing and channel binding are enforced on all DCs (already listed as deployed — validate)
- [ ] Scope any VLAN segments where ARP spoofing is viable (fertilizer plant LAN in particular)
- [ ] Review `gPCFileSysPath` attribute across GPOs for any unexpected UNC paths pointing outside the domain
- [ ] Read full TrustedSec post manually — URL: https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay

## Detection References
From TrustedSec DACL detection series: monitor `Event ID 5136` (AD object modification) on `groupPolicyContainer` class changes. Combine with `Event ID 5145` and `Event ID 4662` for GPO file access telemetry. Alert on changes to `gPCFileSysPath` or `gPCMachineExtensionNames` attributes outside change windows.

## Related Notes
- [[HARD-NTLMv2-Enforcement]]
- [[HARD-LDAP-Signing-Channel-Binding]]
- [[HARD-SMB-Signing]]
- [[PROJ-M365-Hardening]]
- [[OT-SCADA/Vulnerabilities/Network-Segmentation-Gap]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-01 | Initial note created. Direct URL fetch blocked — content from secondary sources. #pending-review for manual verification. |
