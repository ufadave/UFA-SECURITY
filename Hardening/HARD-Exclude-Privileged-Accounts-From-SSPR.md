---
date: 2026-05-20
title: Exclude Privileged Accounts From SSPR
category: "Identity"
cis_benchmark: "CIS Microsoft 365 Foundations 1.1.3"
mitre: "T1078.004"
priority: "High"
status: "Planned"
deployed: ""
validated: ""
tags:
  - "#hardening"
  - "#status/draft"
  - "#identity"
  - "#action-required"
---

# Hardening Control — Exclude Privileged Accounts From SSPR

---

## Objective

Prevent Self-Service Password Reset (SSPR) from being used as an attack vector against
privileged accounts. SSPR allows any enrolled user to reset their own password using
alternative authentication methods (mobile app notification, SMS, email OTP). For standard
users this is an acceptable IT efficiency measure. For privileged accounts (Global Admin,
Security Admin, Privileged Role Admin, and other Entra ID directory roles), SSPR creates
a social engineering attack surface identical to the Storm-2949 TTP: an attacker who knows
the admin UPN can initiate SSPR and then call the user impersonating IT support, instructing
them to approve what appear to be routine MFA prompts.

Admin credential resets should be handled exclusively through an IT-assisted break-glass
or privileged access workstation (PAW) process, not through SSPR.

---

## Observation That Prompted This Control

During validation of KQL-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device
(2026-05-20), `admin-CJones2@ufa.com` (Support Clinton Jones) successfully completed SSPR
after three failed attempts due to password history policy. The account is a named admin
account (`admin-` prefix convention). SSPR was self-initiated and the event was benign, but
confirmed that SSPR is enabled for privileged accounts -- the same configuration that would
allow an attacker to initiate a Storm-2949-style reset against any admin UPN in the tenant.

---

## Implementation

### Method
`Entra Admin Centre` — SSPR Properties and Groups configuration

### Configuration

**Step 1 — Confirm current SSPR scope**

Navigate to: Entra admin centre > Protection > Password reset > Properties

Check whether SSPR is enabled for "All" or "Selected" users. If "All", SSPR applies to
every account in the tenant including privileged accounts.

**Step 2 — Create an exclusion group for privileged accounts**

Create a security group in Entra ID:
- Name: `SG-SSPR-Excluded`
- Description: `Accounts excluded from Self-Service Password Reset — privileged and break-glass accounts`
- Membership: Add all accounts with the following Entra ID directory roles:
  - Global Administrator
  - Privileged Role Administrator
  - Security Administrator
  - Exchange Administrator
  - SharePoint Administrator
  - Intune Administrator
  - Conditional Access Administrator
  - Authentication Administrator
  - Privileged Authentication Administrator
- Also include: all `admin-*` named accounts, break-glass emergency access accounts

**Step 3 — Apply exclusion group to SSPR policy**

Entra admin centre > Protection > Password reset > Properties:
- If currently set to "All": change to "Selected", create an inclusion group of all
  standard users, and exclude `SG-SSPR-Excluded`
- If currently set to "Selected" with a group: add `SG-SSPR-Excluded` as an exclusion

**Step 4 — Verify with a test account**

Log in as a non-admin account and confirm SSPR is still available. Attempt to initiate
SSPR for an admin account (from the SSPR self-service portal at
https://aka.ms/sspr) and confirm it is blocked or redirected.

**Step 5 — Document the break-glass process**

With SSPR disabled for admins, ensure the IT-assisted reset procedure is documented and
accessible. Minimum viable process:
- Admin contacts IT helpdesk via a pre-agreed out-of-band channel (not Teams -- see
  KongTuke campaign context)
- Identity verified via pre-shared code or in-person
- Password reset performed by a Global Admin or Privileged Authentication Administrator
  from a PAW

---

## KQL Detection Pair

```kql
// Verify no privileged accounts (admin-* prefix or Entra role holders)
// successfully complete SSPR after this control is deployed
// Expected: zero results
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Reset password (self-service)"
| where Result == "success"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| where TargetUPN startswith "admin-"
    or TargetUPN in (
        // Populate with UPNs of known privileged accounts
        "breakglass1@ufa.com",
        "breakglass2@ufa.com"
    )
| project TimeGenerated, TargetUPN, Result
| order by TimeGenerated desc
```

---

## Validation Steps

- [ ] Confirm `SG-SSPR-Excluded` group created and populated with all privileged accounts
- [ ] Confirm SSPR policy updated to exclude `SG-SSPR-Excluded`
- [ ] Confirm standard user SSPR still functional (test with non-admin account)
- [ ] Confirm admin account SSPR blocked (test via https://aka.ms/sspr with admin-* account)
- [ ] Run KQL detection pair -- confirm zero SSPR completions for admin accounts
- [ ] Confirm break-glass reset procedure documented and accessible to IT staff
- [ ] Update `admin-CJones2` / Clinton Jones -- notify that SSPR is no longer available for admin account; direct to IT-assisted process

---

## Rollback Procedure

If SSPR exclusion causes operational issues:
1. Remove the relevant account(s) from `SG-SSPR-Excluded` temporarily
2. Document the exception and the business justification
3. Re-add to exclusion group within 48 hours or after the operational need is resolved

Do not remove the group from the SSPR policy entirely -- remove individual accounts
from the group only.

---

## Related Notes

- [[KQL-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device]]
- [[INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18]]
- [[INTEL-KongTuke-Microsoft-Teams-ModeloRAT-Initial-Access-2026-05-14]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-20 | Created -- prompted by admin-CJones2 SSPR event observed during KQL validation |
