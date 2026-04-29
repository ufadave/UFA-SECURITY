# Project — M365 Hardening

**Status:** In Progress | **Started:** 2026
**Owner:** Dave

---

## Objective
Systematically harden the Microsoft 365 / E5 environment across Entra ID, Intune, MDE, Sentinel, and Exchange Online.

---

## Control Areas
| Area | Controls | Status |
|------|----------|--------|
| Identity | NTLMv2, LDAP signing, LSA protection | In Progress |
| Endpoint | ASR rules, WDAC, AppLocker | In Progress |
| Network | SMB signing, IPv6 source routing | Deployed |
| Cloud | Entra Connect SyncJacking, CA policies | Planned |
| Email | MDO policies, anti-phishing | In Progress |

---

## Linked Vault Notes
- [[Hardening/Controls/|Hardening Controls]]
- [[Hardening/Policies/|Policies]]
- [[Hardening/Validation/|Validation]]
- [[Threat-Hunting/TTPs/Fabian-Bader-Entra-Connect-SyncJacking|Entra SyncJacking]]
- [[Threat-Hunting/TTPs/Stryker-Breach-Handala-Intune-Wipe|Stryker/Intune Wipe]]

---

## Actions
- [ ] Apply Entra Connect SyncJacking GA hardening
- [ ] Enforce phishing-resistant MFA for admin accounts
- [ ] Restrict Intune admin console to compliant devices via CA

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
