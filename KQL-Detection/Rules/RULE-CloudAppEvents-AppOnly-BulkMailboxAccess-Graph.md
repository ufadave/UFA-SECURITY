---
title: "App-Only Bulk Mailbox Access via Microsoft Graph (MailItemsAccessed)"
date: 2026-05-03
source_intel: "[[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]"
schema: Sentinel / Log Analytics
table: CloudAppEvents
context: Sentinel (Log Analytics) / Defender XDR Advanced Hunting
mitre_tactics:
  - Collection
  - Exfiltration
mitre_techniques:
  - T1114.002 (Email Collection: Remote Email Collection)
  - T1528 (Steal Application Access Token)
status: Validated
promoted_to_rule: true

sentinel_rule_id: "326fc4bb-4cbc-4280-8bfa-f87d41a9b275"
tags:
  - "#detection/analytics-rule"
  - "#cloud"
  - "#identity"
  - "#status/done"

---

# RULE — App-Only Bulk Mailbox Access via Microsoft Graph

## Purpose

Detects a service principal or OAuth application accessing mailboxes across multiple distinct user accounts using application-level permissions (`Mail.Read`) via the Microsoft Graph API — the core collection mechanism of M365Pwned's MailPwned component and similar toolkits.

Legitimate app-only mail access (e.g. a backup solution, compliance archiver) typically touches a bounded, consistent set of mailboxes. An adversary using application-level OAuth tokens will enumerate and read mailboxes across many distinct users in a short window, often from an unusual IP or outside business hours.

**Key insight:** App-only access is identified by `AccountType == "Application"` in `CloudAppEvents` — this means the `AccountObjectId` field represents the mailbox being accessed (the target), not an interactive user session. The `OAuthAppId` field carries the OAuth client app's GUID.

> **Prerequisite:** `CloudAppEvents` requires the Microsoft 365 App Connector to be enabled in Defender for Cloud Apps (Settings → Cloud Apps → App Connectors → Microsoft 365 Activities checkbox). Confirm this is active in your tenant before running.

---

## Schema

| Field | Table | Notes |
|---|---|---|
| `CloudAppEvents` | Sentinel / Advanced Hunting | Populated by MCAS/Defender for Cloud Apps |
| `ActionType` | `string` | `"MailItemsAccessed"` for mail read events |
| `AccountType` | `string` | `"Application"` for service principal / app-only access |
| `AccountObjectId` | `string` | Target mailbox user object ID (not the app identity) |
| `OAuthAppId` | `string` | OAuth **client** app GUID — the registered app making the call; use this to identify and allowlist specific apps |
| `ApplicationId` | `int` | MCAS internal app ID — numeric, not a GUID; used here as an inclusion filter to scope to mail API calls |
| `AccountDisplayName` | `string` | Display name of the mailbox owner being accessed |
| `IPAddress` | `string` | Source IP of the Graph API call |
| `UserAgent` | `string` | Client user agent — Graph SDK calls have distinctive agents |
| `RawEventData` | `dynamic` | JSON blob — contains `ClientAppId`, `AppId`, `IsThrottled` |
| `Timestamp` | `datetime` | Advanced Hunting; use `TimeGenerated` in Sentinel Log Analytics |

> **Schema correction from stub:** Original stub used `ApplicationId != ""` to identify app-only access — this is incorrect. `ApplicationId` is an `int`, not a string, and cannot be compared to `""`. The correct filter is `AccountType == "Application"`. `OAuthAppId` (string GUID) is the right field to identify and allowlist specific client apps.

> **Exclusion correction (2026-05-28):** Earlier version applied a `msft_first_party` exclusion list to `OAuthAppId`. Those GUIDs are resource IDs, not client app IDs — they cannot appear in `OAuthAppId` and the filter was dead code. Removed. `mail_api_app_ids` inclusion filter added on `ApplicationId` instead. MCAS ID `20893` (Exchange Online) confirmed in tenant 2026-05-28; `11161` removed — does not fire.

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
// --- Known-good OAuth client app IDs (populate with your legitimate mail-accessing apps) ---
// Get these from Entra ID → App Registrations → Application (client) ID
// These are CLIENT app GUIDs — not resource IDs like Microsoft Graph or Exchange Online
let known_good_oauth_apps = dynamic([
    // "00000000-0000-0000-0000-000000000000",  // Example: your backup/archive app
    // "00000000-0000-0000-0000-000000000001"   // Example: compliance scanning app
]);
CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "MailItemsAccessed"
| where AccountType == "Application"           // App-only access — no interactive user
| where isnotempty(OAuthAppId)
| where OAuthAppId !in (known_good_oauth_apps)
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

- [x] `CloudAppEvents.ActionType` — confirm `"MailItemsAccessed"` events present in your tenant (requires Purview Audit enabled + E5/E3)
- [x] `CloudAppEvents.AccountType` — confirm `"Application"` value fires for service principal access (not just `"Regular"`)
- [x] `CloudAppEvents.OAuthAppId` — confirm populated for app-only events (string GUID); may be empty in some tenants
- [x] `CloudAppEvents.AccountObjectId` — confirm this is the **target mailbox** object ID, not the app's object ID, in app-only context
- [x] `CloudAppEvents.ApplicationId` — `20893` confirmed in tenant 2026-05-28 (337 events)
- [ ] `CloudAppEvents.IPAddress` — confirm populated for Graph API calls (may be empty for some app-only scenarios)
- [ ] `RawEventData.OperationProperties[1]` — confirm IsThrottled path is correct in your tenant's raw event format
- [x] `TimeGenerated` vs `Timestamp` — use `TimeGenerated` in Sentinel Log Analytics; use `Timestamp` in Advanced Hunting

### Populate Before Deploying
- [ ] `known_good_oauth_apps` list — enumerate legitimate mail-accessing *client* apps from Entra ID → App Registrations → Application (client) ID. Run the audit query from [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] first.

---

## Exclusion Rationale

| Filter                        | Type      | Reason                                                                                                                                            |
| ----------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `known_good_oauth_apps`       | Exclusion | Your backup/archiving/compliance apps legitimately access multiple mailboxes — allowlist by **client** app GUID from Entra ID → App Registrations |
| `mail_api_app_ids`            | Inclusion | Scopes query to mail API calls via MCAS numeric ApplicationId — confirmed value `20893` in tenant                                                 |
| `bulk_mailbox_threshold = 10` | Threshold | Conservative — tune upward if legitimate apps remain noisy after allowlisting                                                                     |
| mail_api_app_ids              |           | Removed as we also want to capture unknown apps.                                                                                                  |

> **Removed:** `msft_first_party` exclusion list previously applied to `OAuthAppId`. Those GUIDs are resource IDs, not client app IDs — they cannot appear in `OAuthAppId` and the filter was non-functional.

---

## Promoted

| Field           | Detail                                           |
| --------------- | ------------------------------------------------ |
| **Promoted**    | 2026-05-28                                       |
| **Deployed To** | `Sentinel Analytics Rule`                        |
| **Rule Name**   | App-Only Bulk Mailbox Access via Microsoft Graph |
| **Rule ID**     | 326fc4bb-4cbc-4280-8bfa-f87d41a9b275             |

<!-- INACTIVE: MDE Custom Detection — CloudAppEvents is a Sentinel / Log Analytics source; not available in Advanced Hunting custom detection rules -->

---

## Sentinel Analytics Rule Config

| Setting           | Value                                                               |
| ----------------- | ------------------------------------------------------------------- |
| Rule Name         | Custom  Sentinel - App-Only Bulk Mailbox Access via Microsoft Graph |
| Severity          | Medium                                                              |
| Query Frequency   | 1h                                                                  |
| Query Period      | 1h                                                                  |
| Trigger Threshold | Count > 0                                                           |
| Entity Mapping    | Account → OAuthAppId; IP → SourceIPs                                |
| MITRE Tactics     | Collection, Exfiltration                                            |
| MITRE Techniques  | T1114.002, T1528                                                    |
| Suppression       | None initially — assess FP rate first                               |

---

## Test Results

- [x] Query returns results in Sentinel Log Analytics
- [x] `AccountType == "Application"` confirmed to filter correctly
- [ ] `OAuthAppId` confirmed populated for app-only events
- [x] `ApplicationId 20893` confirmed in tenant (337 events — 2026-05-28)
- [ ] `known_good_oauth_apps` list populated from Entra audit
- [ ] Throttling detection sub-query validated
- [x] False positive rate acceptable over 7d baseline
- [x] Deployed to Sentinel

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
| Date       | Change                                                                                                                                                                                                                                                                                         |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-05-03 | Stage 1 (Candidate) — promoted from INTEL-M365Pwned stub. Schema corrected: AccountType == "Application" replaces incorrect ApplicationId != "" filter. OAuthAppId identified as correct app identifier field. ApplicationId confirmed as int type.                                            |
| 2026-05-28 | Corrected exclusion logic — removed non-functional `msft_first_party` list from `OAuthAppId` filter (resource GUIDs, not client app IDs). Replaced with `mail_api_app_ids` inclusion filter on `ApplicationId`. MCAS ID 20893 confirmed in tenant (337 events); 11161 removed — does not fire. |
| 2026-05-28 | Promoted to Sentinel Analytics Rule via promote rule command. Frequency: 1h, Lookback: 1h, Severity: Medium.                                                                                                                                                                                   |
