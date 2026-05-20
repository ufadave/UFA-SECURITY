---
title: INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18
date: 2026-05-20
source: "https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/"
tags:
  - "#resource"
  - "#status/draft"
  - "#action-required"
  - "#identity"
  - "#cloud"
---

# INFO -- Storm-2949: Compromised Identity to Cloud-Wide Breach (Microsoft, 2026-05-18)

**Source:** https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/
**Date:** 2026-05-20
**Author:** Microsoft Threat Intelligence

---

## What It Is

Detailed Microsoft Threat Intelligence case study of a Storm-2949 attack that escalated from a single SSPR (Self-Service Password Reset) social engineering call into a full cloud-wide breach spanning M365, Azure App Services, Key Vault, Azure SQL, and storage accounts -- all without traditional malware. The attack unfolded in two phases: targeted identity compromise via SSPR/MFA social engineering, then systematic cloud infrastructure takeover using the legitimate Azure management plane.

**Attack chain summary:**
1. Attacker initiates SSPR for a targeted user, then calls the user impersonating IT support and convinces them to approve what appear to be routine MFA prompts
2. Entra ID credentials captured -- attacker authenticates as the user
3. M365 data exfiltrated immediately: OneDrive (thousands of files in a single operation), shared repositories, mailboxes -- repeated across multiple compromised accounts
4. Azure infrastructure compromise begins: RBAC role assignments enumerated, service principal credentials harvested via Graph API
5. Azure Key Vault raided in under four minutes: dozens of secrets pulled including database connection strings, identity credentials, and app secrets
6. Production application compromised via stolen connection strings -- application password changed to maintain access
7. Azure SQL databases and storage accounts accessed; firewall rules manipulated; SAS tokens and account keys used for bulk exfiltration via custom Python scripts

No traditional malware. No on-premises TTPs. Entirely living off the Azure control plane.

---

## Relevance

High -- this is the exact attack class your environment is exposed to. The SSPR social engineering vector is available in any Entra ID hybrid tenant. Key Vault secrets, Azure RBAC, and Graph API are all present. The case study maps directly to three open action items:

**SSPR abuse:** SSPR is enabled in your tenant. The attack requires the attacker to know the target user's username (easily obtained via LinkedIn, email headers, or OSINT) and then initiate the SSPR flow before calling the user. Mitigation: restrict SSPR registration and use to trusted locations/devices, or require authentication strength (phishing-resistant MFA) for SSPR completion.

**Key Vault access:** The attacker escalated to Key Vault via a compromised account holding the Owner role. Review: which accounts hold Owner or Contributor on Key Vault resources? Can that be scoped to dedicated service principals only?

**Entra app registration audit (open action item):** Storm-2949 used Graph API to enumerate RBAC role assignments and harvest service principal credentials. The open Entra app registration audit directly addresses the exposure surface used in phase 2 of this attack.

**AADGraphActivityLogs (open action item):** This is exactly the log source that would have captured the Graph API enumeration in phase 2. The log is not yet enabled in your tenant.

---

## Key Detection Anchors

From the Microsoft blog -- KQL opportunities for your environment:

- Bulk OneDrive file download operations (large `FileDownloaded` event clusters from a single account in a short window)
- SSPR-initiated sign-ins followed by MFA approval from a new device or location
- Key Vault `SecretGet` events in rapid succession (dozens of secrets in under 4 minutes)
- Azure RBAC role assignment enumeration via Graph API (`RoleAssignmentList` events)
- Azure firewall rule modification on SQL/storage resources
- SAS token generation followed by large data transfer to external IPs

---

## Actions

- [ ] **Review SSPR configuration** -- restrict SSPR completion to trusted locations or require phishing-resistant MFA (FIDO2/certificate-based) for the authentication method used to complete the reset
- [ ] **Audit Key Vault RBAC** -- identify any user accounts (not service principals) holding Owner or Contributor roles on Key Vault resources; scope to managed identities or dedicated service principals
- [ ] **Enable AADGraphActivityLogs** -- would have captured the Graph API RBAC enumeration in phase 2; this is the third time this has come up as directly relevant (still not enabled)
- [ ] **Complete Entra app registration audit** -- Storm-2949 used service principal credentials harvested via Graph API; this is the attack surface that audit addresses

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-20 | Created -- high relevance to open Entra audit and AADGraphActivityLogs action items |
