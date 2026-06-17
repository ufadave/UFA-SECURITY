---
date: 2026-06-16
title: CopilotActivity New Application Actor Baseline Deviation
table: "CopilotActivity"
schema: "Sentinel / Log Analytics"
mitre: "T1078"
tactic: "Defense Evasion, Persistence"
technique: "Valid Accounts"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#cloud"
  - "#identity"
---

# KQL — CopilotActivity New Application Actor Baseline Deviation

---

**Table:** CopilotActivity | **Schema:** Sentinel / Log Analytics
**MITRE ATT&CK:** T1078 | **Tactic:** Defense Evasion, Persistence | **Technique:** Valid Accounts
**Created:** 2026-06-16 | **Status:** `Draft`

---

## Purpose

Detects new application actors appearing in `CopilotActivity` that were not present in a known-good baseline window. Legitimate application actors in this environment are:

| ActorUserId | ActorName | AppIdentity | RecordType | Notes |
|---|---|---|---|---|
| `486758fd-644e-4fcd-9fd7-4171b04e4e10` | carey.gibson@ufa.com | *(empty)* | OutlookCopilotAutomation | Microsoft first-party Copilot — Outlook delegation |
| `8e55a7b1-6766-4f0a-8610-ecacfe3d569a` | *(GUID)* | Copilot.TeamCopilot.Message | TeamCopilotInteraction | Microsoft first-party Teams Copilot agent |

Any `ActorUserType == "Application"` event where the `ActorUserId` is not in this set warrants investigation. Particular concern if the actor is a privileged account, has a non-Microsoft `AppIdentity`, or appears in a new `RecordType`.

**Baseline established:** 2026-06-16. Update the exclusion list as new sanctioned actors are confirmed.

---

## Query

```kql
let BaselineActors = dynamic([
    "486758fd-644e-4fcd-9fd7-4171b04e4e10",  // carey.gibson Outlook Copilot delegation
    "8e55a7b1-6766-4f0a-8610-ecacfe3d569a"   // Teams Copilot agent
]);
CopilotActivity
| where ActorUserType == "Application"
| where ActorUserId !in (BaselineActors)
| summarize
    EventCount = count(),
    RecordTypes = make_set(RecordType),
    AppIdentities = make_set(AppIdentity),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ActorName, ActorUserId
| order by FirstSeen asc
```

---

## Validated Columns

- [ ] `ActorUserType` — confirm "Application" value is consistent in your tenant; may vary
- [ ] `ActorUserId` — GUID; confirmed present in sampled data
- [ ] `ActorName` — UPN or GUID depending on delegation model; confirmed present
- [ ] `RecordType` — confirmed: OutlookCopilotAutomation, TeamCopilotInteraction observed
- [ ] `AppIdentity` — empty for Outlook delegation rows; populated for Teams agent rows
- [ ] `TimeGenerated` — confirmed present

---

## Test Results

> Paste summarised query output here after running in environment.
> Expected: zero results against baseline window if actors are stable.
> Any new GUID appearing here is a triage candidate.

---

## Deployment

<!-- INACTIVE: This is a Sentinel / Log Analytics query — CopilotActivity is not available in MDE Advanced Hunting.
### MDE Custom Detection Rule
- Not applicable — CopilotActivity is not ingested into Advanced Hunting.
-->

### Sentinel Analytics Rule
- **Rule Name:** CopilotActivity New Application Actor Baseline Deviation
- **Frequency:** Every 1h
- **Lookback:** 1h
- **Severity:** Medium
- **Deployed:** [ ]
- **Rule GUID:** <!-- Populate sentinel_rule_id in frontmatter when deployed -->

> **Note:** Before promoting to a scheduled rule, extend the baseline window to at least 30 days and review whether the `BaselineActors` list needs expanding. Run as a hunting query first.

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-06-16 | Created — based on CopilotActivity baseline analysis; two known-good actors identified |
