---
title: "App-Only Bulk Mailbox Access via Microsoft Graph (MailItemsAccessed)"
date: 2026-05-03
source_intel: "[[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]"
schema: CloudAppEvents
context: Sentinel (Log Analytics) / Defender XDR Advanced Hunting
mitre_tactics:
  - Collection
  - Exfiltration
mitre_techniques:
  - T1114.002 (Email Collection: Remote Email Collection)
  - T1528 (Steal Application Access Token)
status: candidate
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection/analytics-rule"
  - "#cloud"
  - "#identity"
  - "#status/draft"
  - "#action-required"
---

# KQL — App-Only Bulk Mailbox Access via Microsoft Graph

## Purpose

Detects a service principal or OAuth application accessing mailboxes across multiple distinct user accounts using application-level permissions (`Mail.Read`) via the Microsoft Graph API — the core collection mechanism of M365Pwned's MailPwned component and similar toolkits.

Legitimate app-only mail access (e.g. a backup solution, compliance archiver) typically touches a bounded, consistent set of mailboxes. An adversary using application-level OAuth tokens will enumerate and read mailboxes across many distinct users in a short window, often from an unusual IP or outside business hours.

**Key insight:** App-only access is identified by `AccountType == "Application"` in `CloudAppEvents` — this means the `AccountObjectId` field represents the mailbox being accessed (the target), not an interactive user session. The `OAuthAppId` field carries the OAuth app's GUID.

> **Prerequisite:** `CloudAppEvents` requires the Microsoft 365 App Connector to be enabled in Defender for Cloud Apps (Settings → Cloud Apps → App Connectors → Microsoft 365 Activities checkbox). Confirm this is active in your tenant before running.

---

## Schema

| Field | Table | Notes |
|---|---|---|
| `CloudAppEvents` | Sentinel / Advanced Hunting | Populated by MCAS/Defender for Cloud Apps |
| `ActionType` | `string` | `"MailItemsAccessed"` for mail read events |
| `AccountType` | `string` | `"Application"` for service principal / app-only access |
| `AccountObjectId` | `string` | Target mailbox user object ID (not the app identity) |
| `OAuthAppId` | `string` | OAuth app GUID — use this to identify the registered app |
| `ApplicationId` | `int` | MCAS internal app ID — numeric, not a GUID |
| `AccountDisplayName` | `string` | Display name of the mailbox owner being accessed |
| `IPAddress` | `string` | Source IP of the Graph API call |
| `UserAgent` | `string` | Client user agent — Graph SDK calls have distinctive agents |
| `RawEventData` | `dynamic` | JSON blob — contains `ClientAppId`, `AppId`, `IsThrottled` |
| `Timestamp` | `datetime` | Advanced Hunting; use `TimeGenerated` in Sentinel Log Analytics |

> **Schema correction from stub:** Original stub used `ApplicationId != ""` to identify app-only access — this is incorrect. `ApplicationId` is an `int`, not a string, and cannot be compared to `""`. The correct filter is `AccountType == "Application"`. `OAuthAppId` (string GUID) is the right field to identify and allow-list specific apps.

---

## Query

```kql
// ---------------------------------------------------------------
// App-Only Bulk Mailbox Access via Microsoft Graph
// Table: CloudAppEvents (Sentinel Log Analytics)
// Use Timestamp instead of TimeGenerated for Advanced Hunting
// ---------------------------------------------------------------

// --- Configurable thresholds ---
let lookback = 1h;
let bulk_mailbox_threshold = 10;        // Distinct mailboxes accessed by one app in window
let high_volume_threshold = 500;        // Total mail access events — catch throttling-range activity

// --- Known-good OAuth app IDs (populate with your legitimate mail-accessing apps) ---
// Get these from Entra ID → App Registrations → Application (client) ID
let known_good_oauth_apps = dynamic([
    // "00000000-0000-0000-0000-000000000000",  // Example: your backup/archive app
    // "00000000-0000-0000-0000-000000000001"   // Example: compliance scanning app
]);

// --- Known Microsoft first-party app IDs (suppress) ---
let msft_first_party = dynamic([
    "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
    "00000002-0000-0ff1-ce00-000000000000",  // Exchange Online (legacy)
    "00000002-0000-0000-c000-000000000000"   // Azure AD Graph
]);

CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "MailItemsAccessed"
| where AccountType == "Application"           // App-only access — no interactive user
| where isnotempty(OAuthAppId)
| where OAuthAppId !in (known_good_oauth_apps)
| where OAuthAppId !in (msft_first_party)
// Summarise per app per hour
| summarize
    DistinctMailboxes  = dcount(AccountObjectId),
    TotalAccessEvents  = count(),
    MailboxList        = make_set(AccountDisplayName, 20),
    SourceIPs          = make_set(IPAddress, 5),
    UserAgents         = make_set(UserAgent, 3),
    FirstSeen          = min(TimeGenerated),
    LastSeen           = max(TimeGenerated)
    by OAuthAppId, ApplicationId, bin(TimeGenerated, lookback)
// Alert on bulk cross-mailbox access OR high total volume (throttling-range)
| where DistinctMailboxes >= bulk_mailbox_threshold
    or TotalAccessEvents  >= high_volume_threshold
| extend
    Severity = case(
        DistinctMailboxes >= 50 or TotalAccessEvents >= 1000, "High",
        DistinctMailboxes >= 20 or TotalAccessEvents >= 500,  "Medium",
        "Low"
    )
| project
    TimeGenerated,
    OAuthAppId,
    ApplicationId,
    DistinctMailboxes,
    TotalAccessEvents,
    Severity,
    MailboxList,
    SourceIPs,
    UserAgents,
    FirstSeen,
    LastSeen
| order by DistinctMailboxes desc
```

### Supplementary — Throttling Detection (High-Fidelity Indicator)
MailItemsAccessed throttling occurs when >1,000 events fire in <24h. Throttling itself is a high-fidelity signal of bulk access.

```kql
// Detect MailItemsAccessed throttling — indicates bulk mail read by an app
CloudAppEvents
| where TimeGenerated >= ago(24h)
| where ActionType == "MailItemsAccessed"
| where AccountType == "Application"
| extend IsThrottled = tostring(parse_json(tostring(RawEventData)).OperationProperties[1])
| where IsThrottled has "True"
| extend ClientAppId = tostring(parse_json(tostring(RawEventData)).ClientAppId)
| project TimeGenerated, OAuthAppId, ClientAppId, AccountObjectId, AccountDisplayName, IPAddress, UserAgent
```

---

## Validated Columns

- [ ] `CloudAppEvents.ActionType` — confirm `"MailItemsAccessed"` events present in your tenant (requires Purview Audit enabled + E5/E3)
- [ ] `CloudAppEvents.AccountType` — confirm `"Application"` value fires for service principal access (not just `"Regular"`)
- [ ] `CloudAppEvents.OAuthAppId` — confirm populated for app-only events (string GUID); may be empty in some tenants
- [ ] `CloudAppEvents.AccountObjectId` — confirm this is the **target mailbox** object ID, not the app's object ID, in app-only context
- [ ] `CloudAppEvents.ApplicationId` — confirm data type is `int` (schema docs confirm this — cannot be filtered as string)
- [ ] `CloudAppEvents.IPAddress` — confirm populated for Graph API calls (may be empty for some app-only scenarios)
- [ ] `RawEventData.OperationProperties[1]` — confirm IsThrottled path is correct in your tenant's raw event format
- [ ] `TimeGenerated` vs `Timestamp` — use `TimeGenerated` in Sentinel Log Analytics; use `Timestamp` in Advanced Hunting

### Populate Before Deploying
- [ ] `known_good_oauth_apps` list — enumerate legitimate mail-accessing apps from Entra ID → App Registrations. Run the audit query from [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] first.

---

## Exclusion Rationale

| Exclusion | Reason |
|---|---|
| `known_good_oauth_apps` | Your backup/archiving/compliance apps legitimately access multiple mailboxes — these must be allowlisted to prevent chronic FPs |
| `msft_first_party` | Microsoft's own Graph app IDs appear in sync/background traffic and are not attacker-controlled |
| `bulk_mailbox_threshold = 10` | Conservative — tune upward if legitimate apps remain noisy after allowlisting |

---

## Sentinel Analytics Rule Config

| Setting | Value |
|---|---|
| Rule Name | App-Only Bulk Mailbox Access via Microsoft Graph |
| Severity | Medium (dynamic — see Severity field in query output) |
| Query Frequency | 1h |
| Query Period | 1h |
| Trigger Threshold | Count > 0 |
| Entity Mapping | Account → OAuthAppId; IP → SourceIPs |
| MITRE Tactics | Collection, Exfiltration |
| MITRE Techniques | T1114.002, T1528 |
| Suppression | None initially — assess FP rate first |

---

## Test Results

- [ ] Query returns results in Sentinel Log Analytics
- [ ] `AccountType == "Application"` confirmed to filter correctly
- [ ] `OAuthAppId` confirmed populated for app-only events
- [ ] `known_good_oauth_apps` list populated from Entra audit
- [ ] Throttling detection sub-query validated
- [ ] False positive rate acceptable over 7d baseline
- [ ] Deployed to Sentinel

---

## Operational Notes

*(Populate post-deployment)*

---

## Related Notes
- [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] — source intel
- [[KQL-AuditLogs-GraphPermissionGrant-ServicePrincipal]] — companion rule (permissions grant)
- [[KQL-SigninLogs-AppOnly-NonInteractive-Anomaly]] — companion rule (sign-in anomaly)
- [[HARD-Entra-App-Registration-Permissions-Audit]]
- [[PROJ-M365-Hardening]]
- [[CLAUDE-KQL-Promotion-Workflow]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Stage 1 (Candidate) — promoted from INTEL-M365Pwned stub. Schema corrected: AccountType == "Application" replaces incorrect ApplicationId != "" filter. OAuthAppId identified as correct app identifier field. ApplicationId confirmed as int type. |
