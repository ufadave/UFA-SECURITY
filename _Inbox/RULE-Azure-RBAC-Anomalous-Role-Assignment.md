---
date: 2026-05-20
title: Azure RBAC Anomalous Role Assignment
table: "AzureActivity"
schema: "Sentinel / Log Analytics"
mitre: "T1078.004"
tactic: "Privilege Escalation"
technique: "Valid Accounts: Cloud Accounts"
status: "Validated"
promoted_to_rule: true
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/active"
  - "#identity"
  - "#cloud"
---

# RULE -- Azure RBAC Anomalous Role Assignment

---

**Table:** AzureActivity | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1078.004 | **Tactic:** Privilege Escalation | **Technique:** Valid Accounts: Cloud Accounts
**Created:** 2026-05-20 | **Status:** `Validated`

---

## Promoted

| Field | Detail |
|-------|--------|
| **Promoted** | 2026-05-20 |
| **Deployed To** | Sentinel Analytics Rule |
| **Rule Name** | Azure RBAC Anomalous Role Assignment |
| **Rule ID** | <!-- Populate sentinel_rule_id in frontmatter when deployed --> |

> **Note:** Tier 2 (burst detection) is a separate query requiring a standalone Sentinel
> Analytics Rule. See Tier 2 query below and deploy as `Azure RBAC Burst Role Assignments`.

---

## Purpose

Detects anomalous Azure RBAC role assignment activity across three tiers:

- **Tier 1 -- Non-admin caller:** Any role assignment write from a caller whose UPN does
  not match the `admin-` naming convention. 30-day baseline confirms all legitimate role
  changes originate exclusively from `admin-*` accounts.
- **Tier 2 -- Burst assignments:** 3+ role assignments from a single caller within 5
  minutes. Targets automated tooling or compromised admin accounts bulk-assigning roles
  post-enumeration. Deployed as a separate Sentinel rule due to summarise/union schema
  incompatibility.
- **Tier 3 -- Subscription-scope or high-privilege role:** Any assignment at subscription
  scope (`/subscriptions/{id}/providers/Microsoft.Authorization`) or using a high-privilege
  role (Owner, Contributor, User Access Administrator, Privileged Role Administrator),
  regardless of caller identity.

Primary threat context: Storm-2949 phase 2 -- post-compromise Azure infrastructure takeover
via RBAC role assignment using service principal credentials harvested from Graph API
enumeration.

**Known false positive pattern -- subscription-scope AVD provisioning:**
Desktop Virtualization User (8e3af657...) assigned at subscription scope by a known
`admin-*` account is a legitimate AVD bulk-provisioning pattern. Before escalating Tier 3
alerts, verify:
1. Is the caller a known `admin-*` UPN from a recognised corporate IP?
2. Is `RoleDefinitionId` a low-privilege role (Desktop Virtualization User, Reader)?
3. Is there an active AVD provisioning or access request for the relevant subscription?

If all three check out, document and close. Escalate immediately if the caller is unknown,
the IP is unrecognised, or the role is Owner/Contributor/User Access Administrator.

**Prerequisite:** Azure Activity Log connector must be enabled in Sentinel.

**Note on RoleDefinitionId resolution:** `Authorization.evidence.roleDefinitionId` is the
correct parse path in this tenant. Fallback to `Authorization.roleDefinitionId` if role
IDs stop populating after a schema change.

---

## Query

### Tier 1 + Tier 3 (primary Sentinel rule)

```kql
let BurstWindow = 5m;
let BurstThreshold = 3;
let AdminPrefix = "admin-";
// High-privilege role definition IDs -- alert on regardless of caller or scope
// Owner, Contributor, User Access Administrator, Privileged Role Administrator
let HighPrivilegeRoles = dynamic([
    "8e44c0a6-d973-4b6e-a6e9-3c6e94a7d31c",  // Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  // Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  // User Access Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814"   // Privileged Role Administrator
]);
let AllAssignments = AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| extend Auth = parse_json(Authorization)
| extend
    RoleDefinitionId = tostring(Auth.evidence.roleDefinitionId),
    Scope = tostring(Auth.scope),
    Entity = tostring(parse_json(Properties).entity)
| extend
    IsAdminCaller = Caller matches regex "(?i)^admin-",
    IsSubscriptionScope = Scope matches regex
        @"^/subscriptions/[^/]+/providers/Microsoft\.Authorization",
    IsHighPrivilegeRole = RoleDefinitionId in (HighPrivilegeRoles)
| project TimeGenerated, Caller, CallerIpAddress,
    RoleDefinitionId, Scope, Entity,
    IsAdminCaller, IsSubscriptionScope, IsHighPrivilegeRole;
let Tier1 = AllAssignments
| where not(IsAdminCaller)
| extend AlertTier = "Tier1 - Non-admin caller",
    AlertReason = strcat("Role assignment by non-admin account: ", Caller);
let Tier3 = AllAssignments
| where IsSubscriptionScope or IsHighPrivilegeRole
| extend AlertTier = case(
    IsHighPrivilegeRole, "Tier3 - High privilege role assigned",
    IsSubscriptionScope, "Tier3 - Subscription-scope assignment",
    "Tier3 - Unknown"
)
| extend AlertReason = strcat(
    iff(IsHighPrivilegeRole, strcat("High privilege role: ", RoleDefinitionId, " "), ""),
    iff(IsSubscriptionScope, "Subscription-scope grant", "")
);
union Tier1, Tier3
| project TimeGenerated, AlertTier, AlertReason, Caller, CallerIpAddress,
    RoleDefinitionId, Scope, Entity,
    IsAdminCaller, IsSubscriptionScope, IsHighPrivilegeRole
| order by TimeGenerated desc
```

### Tier 2 -- Burst detection (deploy as separate Sentinel rule: `Azure RBAC Burst Role Assignments`)

```kql
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| summarize
    AssignmentCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Scopes = make_set(tostring(parse_json(Authorization).scope), 10),
    Roles = make_set(
        tostring(parse_json(Authorization).evidence.roleDefinitionId), 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 5m)
| where AssignmentCount >= 3
| extend DurationSeconds = datetime_diff("second", LastSeen, FirstSeen)
| project FirstSeen, LastSeen, DurationSeconds, Caller, CallerIpAddress,
    AssignmentCount, Scopes, Roles
| order by AssignmentCount desc
```

---

## Validated Columns

- [x] `OperationNameValue` -- `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` confirmed
- [x] `ActivityStatusValue` -- `Success` confirmed; `Start` events excluded by design
- [x] `Caller` -- UPN populated for human admin callers; service principals show object ID
- [x] `CallerIpAddress` -- confirmed populated
- [x] `Authorization` -- JSON field; `Auth.evidence.roleDefinitionId` resolves correctly
- [x] `Authorization.scope` -- confirmed populated with full resource path
- [x] `Properties.entity` -- confirmed populated with full resource path
- [x] `Caller matches regex "(?i)^admin-"` -- case-insensitive; handles both `Admin-` and `admin-` prefix variants
- [x] `Scope matches regex` -- subscription-scope pattern validated against known events

---

## Test Results

**30-day validation -- 2026-04-20 to 2026-05-20**
**Total role assignment events:** 31 | **All callers:** admin-* only | **All roles:** Desktop Virtualization User

| Date | Caller | AlertTier | Disposition |
|------|--------|-----------|-------------|
| 2026-05-20 17:00 | admin-joishi@ufa.com | Tier3 - Subscription-scope | Benign -- AVD provisioning, corporate IP |
| 2026-05-07 16:31-32 | Admin-gfillo@ufa.com | Tier3 - Subscription-scope x3 | Benign -- AVD provisioning, confirmed admin sign-in |
| 2026-05-05 14:23 | admin-joishi@ufa.com | Tier3 - Subscription-scope x2 | Benign -- AVD provisioning, corporate IP |

**Result: 1 alert per run with 30-day lookback. All benign. Noise floor acceptable.**

---

## Deployment

<!-- INACTIVE: MDE Custom Detection -- AzureActivity is Log Analytics only -->

### Sentinel Analytics Rule -- Tier 1 + Tier 3
- **Rule Name:** Azure RBAC Anomalous Role Assignment
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** High
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

### Sentinel Analytics Rule -- Tier 2 (Burst)
- **Rule Name:** Azure RBAC Burst Role Assignments
- **Frequency:** Every 1h
- **Lookback:** 1d
- **Severity:** High
- **Deployed:** [ ]
- **Rule GUID:** <!-- Create companion RULE- note when deployed -->

---

## Hardening Control Pair
- **Control:** [[HARD-Exclude-Privileged-Accounts-From-SSPR]]
- **Linked:** [ ]

---

## Related Notes
- [[INFO-Storm-2949-Identity-to-Cloud-Breach-Microsoft-2026-05-18]]
- [[KQL-Azure-RBAC-Anomalous-Role-Assignment]] -- source KQL note
- [[KQL-SSPR-Followed-By-Sign-In-From-New-Country-Or-Unregistered-Device]]
- [[KQL-OneDrive-Bulk-File-Download-Detection]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-20 | Created -- promoted from KQL-Azure-RBAC-Anomalous-Role-Assignment via promote rule command |
| 2026-05-20 | Authorization parse path confirmed as Auth.evidence.roleDefinitionId |
| 2026-05-20 | Tier 2 burst query retained as separate deployment item -- schema incompatibility with Tier 1+3 union |
| 2026-05-20 | Subscription-scope AVD provisioning documented as known false positive |
