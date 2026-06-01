---
date: 2026-05-29
title: Block Graph Explorer via Conditional Access
category: "Identity / Cloud Access"
cis_benchmark: "CIS M365 v3.0 — 1.1.x (Conditional Access baseline)"
mitre: "T1078.004, T1530, T1069.003"
priority: "Medium"
status: "Planned"
deployed: ""
validated: ""
tags:
  - "#hardening"
  - "#identity"
  - "#cloud"
  - "#status/draft"
  - "#action-required"
---

# Hardening Control — Block Graph Explorer via Conditional Access

---

## Objective

Graph Explorer (`developer.microsoft.com/en-us/graph/graph-explorer`) is a Microsoft-hosted browser tool that allows any authenticated user with a valid Entra ID session to issue live Graph API calls — including directory reads, user enumeration, mail access, group membership queries, and application listing — directly from a browser without any client-side tooling.

This is a meaningful attack surface in a post-compromise scenario: an adversary with a valid session (AiTM token theft, browser session hijack, Entra-registered device) can use Graph Explorer to enumerate the directory, identify privileged accounts, and read accessible mailboxes without deploying any tooling that endpoint controls or MDE would detect.

**This control restricts access to `developer.microsoft.com` via Conditional Access, blocking or scoping Graph Explorer to compliant managed devices only.**

> **Prerequisite check:** Confirm whether any current admin workflows, developer accounts, or approved onboarding processes depend on Graph Explorer access before applying a block. If legitimate use exists, scope the policy to require compliant device rather than outright block.

---

## Scope of Risk

| Risk | Detail |
|------|--------|
| Directory enumeration | Graph Explorer allows `GET /users`, `GET /groups`, `GET /servicePrincipals` — full directory read with `User.Read.All` or `Directory.Read.All` delegated access |
| Mail access | With `Mail.Read` delegated permission, `GET /me/messages` and `GET /users/{id}/messages` accessible from browser session |
| Application/SP enumeration | `GET /applications`, `GET /servicePrincipals` — maps permission grants and attack surface |
| No endpoint footprint | Browser-only — bypasses MDE process-level detection entirely |
| AiTM token theft pivot | A stolen browser token or PRT can be used to access Graph Explorer without MFA re-challenge if CA policy doesn't cover this app |

---

## Implementation

### Method
`Conditional Access Policy` — Entra ID

### Configuration

Graph Explorer authenticates against the Microsoft Graph application (`00000003-0000-0000-c000-000000000002`) with the app ID `de8bc8b5-d9f9-48b1-a8ad-b748da725064` (Graph Explorer registered application).

**Option A — Require compliant device (recommended if any legitimate use exists)**

| Setting | Value |
|---------|-------|
| Policy name | `CA — Require Compliant Device — Graph Explorer` |
| Users / Groups | All users (exclude break-glass accounts) |
| Cloud apps | `Microsoft Graph Explorer` (app ID: `de8bc8b5-d9f9-48b1-a8ad-b748da725064`) |
| Conditions | None required |
| Grant | Require device to be marked as compliant |
| Session | — |
| Policy state | Report-only → then Enabled after validation |

**Option B — Block entirely (if no legitimate use)**

| Setting | Value |
|---------|-------|
| Policy name | `CA — Block — Graph Explorer` |
| Users / Groups | All users (exclude break-glass accounts) |
| Cloud apps | `Microsoft Graph Explorer` (app ID: `de8bc8b5-d9f9-48b1-a8ad-b748da725064`) |
| Grant | Block access |
| Policy state | Report-only → then Enabled after validation |

> **Recommended approach for this environment:** Start with Option A in report-only mode. Validate no legitimate admin workflows are broken. Confirm no enrolled developer accounts require Graph Explorer from unmanaged devices. Promote to enforced after 5–7 day report-only observation window.

### Locating the App in Entra

1. Entra admin centre → Protection → Conditional Access → Policies → New Policy
2. Cloud apps → Select apps → Search `Graph Explorer`
3. If the app does not appear by name, search by app ID: `de8bc8b5-d9f9-48b1-a8ad-b748da725064`

> **Note:** `developer.microsoft.com` itself is not a Conditional Access-targetable endpoint — the control is applied to the **Graph Explorer application registration** in Entra, not the URL. CA intercepts the OAuth authentication event when Graph Explorer requests a token, not the web browsing session.

---

## KQL Detection Pair

Use this to baseline Graph Explorer usage before enforcing the policy, and to monitor for policy bypass attempts or usage by privileged accounts after enforcement.

```kql
// Graph Explorer sign-in activity — baseline and monitoring
// Schema: Sentinel / Log Analytics — SigninLogs
// Run in report-only mode to assess impact before enforcement
SigninLogs
| where TimeGenerated > ago(30d)
| where AppDisplayName =~ "Graph Explorer"
    or AppId =~ "de8bc8b5-d9f9-48b1-a8ad-b748da725064"
| extend IsPrivilegedAccount = UserPrincipalName has_any (
    "admin-", "svc-", "break-glass"   // adjust to your admin UPN pattern
)
| project
    TimeGenerated,
    UserPrincipalName,
    IsPrivilegedAccount,
    IPAddress,
    Location,
    DeviceDetail,
    ConditionalAccessStatus,
    ResultType,
    ResultDescription,
    AuthenticationRequirement
| order by TimeGenerated desc
```

**What to look for:**
- Any `IsPrivilegedAccount = true` rows — privileged account using Graph Explorer warrants immediate review
- `ConditionalAccessStatus == "notApplied"` after policy enforcement — indicates policy gap or exclusion
- Access from unexpected countries or IPs
- `ResultType == 0` (success) after block policy is enforced — indicates a bypass or excluded account

---

## Validation Steps

- [ ] Run KQL baseline — capture current Graph Explorer usage over 30 days before policy creation
- [ ] Identify any users with recurring Graph Explorer sign-ins — confirm whether use is sanctioned
- [ ] Check admin accounts (admin-GKoerhui, admin-CJones2, admin-mrieger, admin-bogle, Admin-gfillo) — any active Graph Explorer sessions?
- [ ] Create policy in report-only mode
- [ ] Monitor `ConditionalAccessStatus` in SigninLogs for 5–7 days — confirm policy is evaluating correctly
- [ ] Confirm no legitimate admin workflows are blocked (Graph Explorer is rarely needed when Entra admin centre and PIM are available)
- [ ] Enable policy
- [ ] Re-run KQL — confirm no `ResultType == 0` events post-enforcement

---

## Rollback Procedure

1. Entra admin centre → Protection → Conditional Access → Policies
2. Locate `CA — Require Compliant Device — Graph Explorer` (or Block variant)
3. Set policy state to **Report-only** or **Off**
4. Document rollback reason in changelog below

Break-glass accounts are excluded from all CA policies by design — they retain Graph Explorer access regardless of policy state.

---

## Related Notes

- [[RESEARCH-Registered-Not-Compliant-CA-Gap-Token-Theft]] — registered ≠ compliant gap context
- [[HUNT-Long-Duration-AiTM-Token-Access-Graph-Recon]] — Graph API recon via stolen session
- [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-29 | Created |
