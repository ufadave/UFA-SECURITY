---
date: 2026-05-05
title: BEC Inbox Rule Forwarding with Concealment
table: "OfficeActivity"
schema: "Sentinel / Log Analytics"
mitre: "T1114.003, T1137.005, T1078.004"
tactic: "Collection, Persistence, Defence Evasion"
technique: "Email Forwarding Rule, Office Application Startup: Outlook Rules, Valid Accounts: Cloud Accounts"
status: "Draft"
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#identity"
  - "#email"
  - "#cloud"
---

# KQL — BEC Inbox Rule Forwarding with Concealment

---

**Table:** `OfficeActivity` | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1114.003, T1137.005, T1078.004 | **Tactic:** Collection, Persistence, Defence Evasion | **Technique:** Email Forwarding Rule, Outlook Rules, Valid Accounts: Cloud Accounts
**Created:** 2026-05-05 | **Status:** `Draft`

---

## Purpose

Detects inbox rules and mailbox-level forwarding configurations that combine a **forwarding destination** with a **concealment action** — the primary persistence and exfiltration mechanism in Business Email Compromise. The forwarding + concealment combination is a high-confidence BEC signal: legitimate auto-forward rules do not also delete, hide, or mark messages as read.

Covers four rule operations:
- `New-InboxRule` — new inbox rule created
- `Set-InboxRule` — existing inbox rule modified
- `UpdateInboxRules` — inbox rules updated (Outlook client path)
- `Set-Mailbox` — mailbox-level forwarding set via `ForwardingSmtpAddress`

Covers two attack patterns:
1. **Silent exfiltration** — forward all mail to attacker address, mark as read so victim doesn't notice unread count change
2. **Evidence destruction** — forward payment confirmations or vendor responses then delete them before the victim sees them

Directly relevant to the 2026-05-05 AiTM incident — see [[FIND-Graph-API-User-Enumeration-Sweden-Central]]. Deploy as an always-on scheduled rule to catch rule creation in real time going forward.

---

## Corrections Applied

This query was reviewed and corrected from its original form before filing. Corrections documented for auditability:

| Issue | Original | Fixed |
|-------|----------|-------|
| Broken URL artefact in field extraction | `tostring(http://Parsed.Name)` | `tostring(Parsed.Name)` — would have caused parse error or silent empty results |
| Leading space in `RedirectTo` filter | `" RedirectTo"` | `"RedirectTo"` — would have caused missed detections on redirect rules |
| `TimeGenerated` in `by` clause | `by TimeGenerated, UserId, Operation` | `by bin(TimeGenerated, 5m), UserId, Operation` — millisecond precision prevented summarise from grouping related actions |
| Empty strings in `ForwardDest` set | Not stripped | `set_difference(ForwardDest, dynamic([""]))` added — prevented `array_length > 0` from being always true |

---

## Query

```kql
// Table: OfficeActivity
// Schema: Sentinel / Log Analytics
// Purpose: Detect inbox rules combining forwarding with concealment actions
//          Forwarding + DeleteMessage/MarkAsRead/MoveToFolder = high-confidence BEC signal
//          Also catches mailbox-level forwarding via Set-Mailbox ForwardingSmtpAddress
// Requires: Office 365 data connector (OfficeActivity table)
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "Set-Mailbox"
  )
| extend Parsed = parse_json(Parameters)
| mv-expand Parsed
| extend ParamName  = tostring(Parsed.Name)    // Corrected from http://Parsed.Name
| extend ParamValue = tostring(Parsed.Value)
| where ParamName in (
    "ForwardTo",
    "RedirectTo",                               // Corrected — removed leading space
    "ForwardAsAttachmentTo",
    "ForwardingSmtpAddress",
    "DeleteMessage",
    "MarkAsRead",
    "MoveToFolder",
    "Name"
  )
| summarize
    RuleActions = make_set(ParamName),
    ForwardDest = make_set(iff(
        ParamName in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress"),
        ParamValue, "")),
    RuleName    = max(iff(ParamName == "Name", ParamValue, "")),
    ClientIP    = max(ClientIP),
    EventTime   = min(TimeGenerated)
    by bin(TimeGenerated, 5m), UserId, Operation  // Corrected — bin() prevents per-millisecond grouping
| extend ForwardDest = set_difference(ForwardDest, dynamic([""]))  // Strip empty string artefacts
| where RuleActions has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress")
      and (
          RuleActions has_any ("DeleteMessage", "MarkAsRead", "MoveToFolder")
          or array_length(ForwardDest) > 0
      )
// Uncomment and populate with your internal domains to reduce noise from legitimate forwarding
// | where not(ForwardDest has_any ("@yourdomain.com", "@subsidiary.com"))
| project
    EventTime,
    UserId,
    Operation,
    RuleName,
    ForwardDest,
    RuleActions,
    ClientIP
| order by EventTime desc
```

---

### Pre-deployment Baseline Query

Run with extended lookback before deploying as a scheduled rule. Establishes whether any forwarding rules exist from before the incident window — given the 5-month access hypothesis, results before 2026-05-05 should be investigated:

```kql
// Table: OfficeActivity
// Schema: Sentinel / Log Analytics
// Purpose: Baseline — run once before deployment to surface any historical forwarding rules
//          Extend lookback to maximum available retention
OfficeActivity
| where TimeGenerated > ago(30d)   // Extend to ago(90d) or longer if retention allows
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "Set-Mailbox"
  )
| extend Parsed = parse_json(Parameters)
| mv-expand Parsed
| extend ParamName  = tostring(Parsed.Name)
| extend ParamValue = tostring(Parsed.Value)
| where ParamName in (
    "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo",
    "ForwardingSmtpAddress", "DeleteMessage", "MarkAsRead",
    "MoveToFolder", "Name"
  )
| summarize
    RuleActions = make_set(ParamName),
    ForwardDest = make_set(iff(
        ParamName in ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress"),
        ParamValue, "")),
    RuleName    = max(iff(ParamName == "Name", ParamValue, "")),
    ClientIP    = max(ClientIP),
    EventTime   = min(TimeGenerated)
    by bin(TimeGenerated, 5m), UserId, Operation
| extend ForwardDest = set_difference(ForwardDest, dynamic([""]))
| where RuleActions has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress")
| project EventTime, UserId, Operation, RuleName, ForwardDest, RuleActions, ClientIP
| order by EventTime asc
```

---

## Validated Columns

- [ ] `OfficeActivity.Operation` — confirm `"New-InboxRule"`, `"Set-InboxRule"`, `"UpdateInboxRules"`, `"Set-Mailbox"` exact strings match events in your tenant
- [ ] `OfficeActivity.Parameters` — confirm dynamic array; `parse_json()` required before `mv-expand`
- [ ] `Parsed.Name` / `Parsed.Value` — confirm field names within the Parameters array match your tenant's event format; run pre-deployment structure query below to inspect
- [ ] `ParamName` values — confirm `"ForwardTo"`, `"RedirectTo"`, `"ForwardingSmtpAddress"`, `"DeleteMessage"` appear in your tenant's `Parameters` array for rule operations
- [ ] `OfficeActivity.ClientIP` — confirm field populated for rule creation events
- [ ] `OfficeActivity.UserId` — confirm format (UPN vs object ID) for entity mapping in Sentinel rule
- [ ] `set_difference()` — confirm function available in your Sentinel workspace KQL version
- [ ] `bin(TimeGenerated, 5m)` — confirm summarise grouping produces expected row count vs raw event count

### Parameters Structure Inspection Query

Run this first to inspect the raw `Parameters` array structure before running the full query:

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| take 5
| project TimeGenerated, UserId, Operation, Parameters
```

---

## Test Results

- [ ] Parameters structure inspection query run — `Parsed.Name` / `Parsed.Value` field names confirmed
- [ ] Pre-deployment baseline query run against 30d lookback — results reviewed
- [ ] Results before 2026-05-05 investigated if any returned
- [ ] `ForwardDest` set confirmed empty strings stripped correctly
- [ ] `RuleActions` set confirmed populated with correct param names
- [ ] Internal domain exclusion filter populated and uncommented if needed
- [ ] False positive rate assessed over 7 days in report-only mode
- [ ] Deployed to Sentinel as scheduled analytics rule

---

## Sentinel Analytics Rule

- **Rule Name:** BEC Inbox Rule — Forwarding with Concealment
- **Frequency:** Every 1 hour
- **Lookback:** 1 hour
- **Severity:** High
- **Threshold:** Count > 0
- **Entity Mapping:** Account → UserId | IP → ClientIP
- **MITRE Tactics:** Collection, Persistence, Defence Evasion
- **MITRE Techniques:** T1114.003, T1137.005, T1078.004
- **Suppression:** None — every forwarding + concealment rule warrants review
- **Deployed:** [ ]

> **Deployment note:** No allowlist by default. If chronic FPs emerge from a known-good provisioning workflow or legitimate external forwarding, add a domain-based exclusion scoped to that specific destination rather than suppressing the rule broadly. Uncomment the domain filter in the query and populate with your internal domains as a first noise-reduction step.

---

## Hardening Control Pair

- **Control:** [[HARD-Require-Compliant-Device-Office-365]]
- **Linked:** [ ]

---

## Related Notes

- [[FIND-Graph-API-User-Enumeration-Sweden-Central]] — triggering incident
- [[HUNTING-Post-Graph-Enumeration-O365-Follow-On]] — Query 1 in this hunt note covers inbox rules in the post-enumeration window
- [[HUNT-Long-Duration-AiTM-Token-Access-Graph-Recon]] — Query 5 covers mailbox access over extended window
- [[INTEL-Tycoon2FA-AiTM-PhaaS-Platform]] — threat actor context
- [[HARD-Require-Compliant-Device-Office-365]]
- [[HARD-Block-High-Risk-Sign-ins]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-05 | Created — query reviewed and corrected from original. Four issues fixed: http:// artefact in Parsed.Name, leading space in RedirectTo, TimeGenerated in by clause, empty string stripping in ForwardDest. Pre-deployment baseline query added. Triggered by AiTM incident review. |
