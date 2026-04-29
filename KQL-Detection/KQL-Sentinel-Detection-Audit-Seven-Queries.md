---
title: Sentinel Detection Audit — Seven Queries
date: 2026-04-26
source: https://medium.com/@rohitashokgowd/seven-queries-to-audit-the-sentinel-detections-your-soc-may-have-missed-8e9c73fc2522
author: Rohitashokgowd
schema: Sentinel (Log Analytics)
tables:
  - _SentinelHealth()
  - SecurityAlert
  - SecurityIncident
  - SentinelAudit
  - Usage
  - SentinelAnalyticalRules_CL
  - SentinelDeployedAlerts_CL
mitre: []
tags:
  - "#detection"
  - "#resource"
  - "#status/active"
  - "#endpoint"
  - "#cloud"
  - "#action-required"
  - "#detection/audit"
---

# Sentinel Detection Audit — Seven Queries

> **Source:** [Seven Queries to Audit the Sentinel Detections Your SOC May Have Missed](https://medium.com/@rohitashokgowd/seven-queries-to-audit-the-sentinel-detections-your-soc-may-have-missed-8e9c73fc2522)
> **Author:** Rohitashokgowd (Senior Cybersecurity Engineer)
> **Schema:** Sentinel (Log Analytics)
> **Last Validated:** Not yet run in your environment

---

## Purpose

A Sentinel workspace accumulates rules over time — content hub imports, testing, staff turnover, forgotten tuning sessions. Standard health monitoring only tells you if a rule *runs*, not whether it adds value. A rule can be fully healthy and completely blind.

These seven queries surface the rules your SOC has forgotten but is still paying a compute and analyst tax on. Run as a detection library hygiene cycle — recommended every few months.

---

## Prerequisites

Before running any queries:

- **Auditing and Health enabled** → Sentinel → Settings → Auditing and Health Monitoring
- **Permissions** → Microsoft Sentinel Reader is sufficient for all queries
- **Inventory table** → Queries 4, 5, and 6 require `SentinelAnalyticalRules_CL` — rule definitions ingested via a scheduled Logic App calling the ARM REST API. Rule definitions live in ARM resources, not log tables. Without this, only Q1, Q2, Q3, and Q7 run out of the box.

> **Reference tool:** [Sentinel Assessment Tool](https://github.com/rohit8096-ag/Sentinel-Assessment-Tool) — PowerShell module generating an interactive HTML coverage report across Sentinel and Defender.

---

## Schema Validation

**Run these before filing — verify columns exist in your workspace:**

- [ ] `_SentinelHealth()` — confirm function is available; requires Auditing and Health enabled
- [ ] `ExtendedProperties.QueryResultAmount` — used in Q1; verify cast to `int` works in your workspace
- [ ] `SecurityAlert.ExtendedProperties["Analytic Rule Ids"]` — used in Q2; confirm key name matches exactly
- [ ] `SecurityIncident.Classification` — used in Q3; verify `BenignPositive` / `FalsePositive` / `TruePositive` are your actual values
- [ ] `SecurityIncident.ClassificationComment` — used in Q3 to filter automation noise; confirm field is populated in your workspace
- [ ] `Usage.DataType` — used in Q4; verify ingestion tracking is active
- [ ] `SentinelAudit.ExtendedProperties.UpdatedResourceState` — used in Q5; requires audit retention; confirm JSON path is accurate
- [ ] `SentinelAnalyticalRules_CL` — custom table; confirm Logic App is deployed before running Q4/Q5
- [ ] `SentinelDeployedAlerts_CL` — custom table; confirm this is distinct from `SentinelAnalyticalRules_CL` — Q6 uses a different inventory source
- [ ] `SecurityAlert.Techniques` — used in Q7; may be JSON array or comma-separated string depending on rule type; query handles both

---

## Query 1 — Silent Zombies

**What it catches:** Rules that run successfully on schedule but query empty tables, target decommissioned assets, or have thresholds reality never meets. Health status stays green. Detection is dead.

**Key insight:** `QueryResultAmount` in `_SentinelHealth()` shows rows found *before* grouping or thresholds. Consistently zero across 100+ runs is almost always broken, not perfect.

```kql
_SentinelHealth()
| where TimeGenerated > ago(30d)
| where SentinelResourceType == "Analytics Rule"
| where OperationName == "Scheduled analytics rule run"
| where Status == "Success"
| extend EP = todynamic(ExtendedProperties)
| extend EventsCount = toint(EP.QueryResultAmount)
| summarize
    TotalRuns = count(),
    TotalEventsSeen = sum(EventsCount),
    LastRun = max(TimeGenerated),
    FirstRunSeen = min(TimeGenerated)
    by RuleName = SentinelResourceName, RuleId = SentinelResourceId
| where TotalEventsSeen == 0
| where TotalRuns >= 100
| order by TotalRuns desc
```

**Triage:**
1. Re-run the rule query manually with a wider time window
2. Check whether the base table (e.g. `SigninLogs`, `DeviceProcessEvents`) is actually receiving data
3. If base table has data but filter returns nothing → rule logic too strict. If base table zero for 30 days → confirmed broken feed — go to Q4.

---

## Query 2 — Shadow Detectors

**What it catches:** Rules that fire alerts but those alerts never become incidents. Incident creation may be off, or an automation rule is silently closing/suppressing everything before any analyst sees it.

**Key insight:** Sentinel has no native dashboard showing alert-to-incident conversion rates. Without this check, you can have active rules producing zero analyst-visible output.

```kql
let window = 30d;
// Base alerts with RuleId
let Alerts =
    SecurityAlert
    | where TimeGenerated > ago(window)
    | extend
        SystemAlertId = tostring(SystemAlertId),
        RuleId = tostring(parse_json(ExtendedProperties)["Analytic Rule Ids"]);
// Alert volume per rule
let AlertsByRule =
    Alerts
    | summarize AlertCount = count(), RuleName = any(AlertName) by RuleId;
// Alerts that appear in incidents
let AlertsInIncidents =
    SecurityIncident
    | where TimeGenerated > ago(window)
    | mv-expand AlertIds
    | extend SystemAlertId = tostring(AlertIds)
    | project SystemAlertId, IncidentNumber;
// Map alerts → incidents → rules
let IncidentMapping =
    Alerts
    | join kind=inner AlertsInIncidents on SystemAlertId
    | summarize IncidentsFromRule = dcount(IncidentNumber) by RuleId;
// Final scoring
AlertsByRule
| join kind=leftouter IncidentMapping on RuleId
| extend IncidentsFromRule = coalesce(IncidentsFromRule, 0)
| extend AlertToIncidentRatio = round(todouble(IncidentsFromRule) / todouble(AlertCount), 3)
| extend PctAlertsOrphaned = round(100.0 * (AlertCount - IncidentsFromRule) / AlertCount, 1)
| where AlertCount >= 10
| where PctAlertsOrphaned >= 80
| project RuleName, RuleId, AlertCount, IncidentsFromRule, AlertToIncidentRatio, PctAlertsOrphaned
| order by AlertCount desc
```

**Triage:**
1. Verify incident creation is enabled on the rule
2. Check for automation rules silently closing or suppressing output
3. Audit automation rule scope — these often expand beyond original intent over time

---

## Query 3 — Everything Is Benign

**What it catches:** Rules that analysts close as False Positive or Benign Positive over 90% of the time. Uses actual incident classification data as ground truth for rule quality.

**Key insight:** `Classification` and `ClassificationReason` in `SecurityIncident` represent real human judgment. A rule producing 50 incidents where 48 are benign is a tax on analyst time, not a detection.

```kql
let window = 90d;
let MinIncidents = 20;
let MinNonActionableRate = 0.9;
// Closed incidents (filtered from automation noise)
let ClosedIncidents =
    SecurityIncident
    | where TimeGenerated > ago(window)
    | where Status == "Closed"
    | where isnotempty(Classification)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend TimeToClose = datetime_diff('second', ClosedTime, CreatedTime)
    | where ClassificationComment !contains "Auto Closed"
    | where ClassificationComment !contains "Playbook"
    | where TimeToClose > 60
    | project IncidentNumber, Classification, ClassificationReason, AlertIds, TimeToClose;
// Incident → Rule mapping
let IncidentRuleMap =
    ClosedIncidents
    | mv-expand AlertIds to typeof(string)
    | extend AlertId = tostring(AlertIds)
    | where isnotempty(AlertId)
    | join kind=leftouter (
        SecurityAlert
        | where TimeGenerated > ago(window)
        | extend SystemAlertId = tostring(SystemAlertId)
        | where isnotempty(SystemAlertId)
        | summarize AlertName = any(AlertName) by SystemAlertId
    ) on $left.AlertId == $right.SystemAlertId
    | extend RuleName = coalesce(AlertName, "UnknownRule")
    | project IncidentNumber, RuleName, Classification, ClassificationReason;
// Top reason per rule
let TopReasonPerRule =
    IncidentRuleMap
    | where isnotempty(ClassificationReason)
    | summarize ReasonCount = count() by RuleName, ClassificationReason
    | summarize arg_max(ReasonCount, ClassificationReason) by RuleName
    | project RuleName, TopReason = ClassificationReason;
// Rule-level aggregation
IncidentRuleMap
| summarize
    TotalIncidents = dcount(IncidentNumber),
    TP = dcountif(IncidentNumber, Classification == "TruePositive"),
    FP = dcountif(IncidentNumber, Classification == "FalsePositive"),
    BP = dcountif(IncidentNumber, Classification == "BenignPositive"),
    Undetermined = dcountif(IncidentNumber, Classification == "Undetermined")
  by RuleName
| extend
    NonActionable = FP + BP,
    NonActionableRate = round(todouble(FP + BP) / todouble(TotalIncidents), 3),
    FalsePositiveRate = round(todouble(FP) / todouble(TotalIncidents), 3),
    BenignPositiveRate = round(todouble(BP) / todouble(TotalIncidents), 3),
    UndeterminedRate = round(todouble(Undetermined) / todouble(TotalIncidents), 3)
| join kind=leftouter TopReasonPerRule on RuleName
| extend TopReason = coalesce(TopReason, "NotSpecified")
| extend Recommendation = case(
    FalsePositiveRate >= BenignPositiveRate and FalsePositiveRate >= UndeterminedRate and FalsePositiveRate >= 0.5,
        "Retune detection logic (False Positive dominant)",
    BenignPositiveRate >= FalsePositiveRate and BenignPositiveRate >= UndeterminedRate and BenignPositiveRate >= 0.5,
        "Add scoping/exclusions (Benign Positive dominant)",
    UndeterminedRate >= 0.5,
        "Improve alert clarity (Undetermined dominant)",
    "Mixed - review incidents"
)
| where TotalIncidents >= MinIncidents
| where NonActionableRate >= MinNonActionableRate
| project RuleName, TotalIncidents, TP, FP, BP, Undetermined, NonActionableRate, FalsePositiveRate, BenignPositiveRate, UndeterminedRate, TopReason, Recommendation
| order by TotalIncidents desc, NonActionableRate desc
```

**Decision matrix:**

| NonActionableRate | Action |
|---|---|
| 70–90% | Tune — add exclusions based on 10 closed incident review |
| >90%, TP > 0 | Tune aggressively or rewrite |
| >90%, TP = 0 over 90 days | Retire or convert to hunting query |

**FP vs BP split determines the fix:**
- FP dominant → Retune detection logic
- BP dominant → Add scoping/exclusions
- Undetermined dominant → Improve alert clarity/description

---

## Query 4 — Broken Feeds

**What it catches:** The scariest failure mode. Rule runs, reports success, no errors — it just has no data. A broken log forwarder, deleted DCR, or changed log format makes a rule blind with no visible indication.

**Key insight:** "My rules are green so I must be covered" is the most dangerous assumption in Sentinel. The `Usage` table is the only authoritative source for what is actually flowing.

**Requires:** `SentinelAnalyticalRules_CL` inventory table

```kql
let recentWindow = 7d;         // a table is "silent" if no ingestion in this window
let usageGracePeriod = 1d;     // Usage table lags ~1d so push windows back to compensate
let baselineWindow = 90d;      // require the table to have ingested somewhere in this prior window
let silentTables = toscalar(
    Usage
    | where TimeGenerated between (ago(baselineWindow) .. ago(recentWindow + usageGracePeriod))
    | where DataType !in ("Operation", "Watchlist")
    | summarize by DataType
    | join kind=leftanti (
        Usage
        | where TimeGenerated between (ago(recentWindow + usageGracePeriod) .. ago(usageGracePeriod))
        | summarize by DataType
      ) on DataType
    | summarize make_set(DataType));
let knownTables =
    Usage
    | where TimeGenerated > ago(baselineWindow)
    | where DataType !in ("Operation", "Watchlist")
    | summarize by DataType;
let RuleTableRefs =
    SentinelAnalyticalRules_CL
    | where IsEnabled_b == true and isnotempty(Query_s)
    | summarize QueryLower = any(tolower(Query_s)) by DisplayName_s
    | extend k = 1
    | join kind=inner (knownTables | extend k = 1, TableLower = tolower(DataType)) on k
    | where QueryLower has TableLower
    | distinct DisplayName_s, ReferencedTable = DataType;
RuleTableRefs
| summarize
    Silent = make_set_if(ReferencedTable, ReferencedTable in (silentTables)),
    All    = make_set(ReferencedTable)
    by DisplayName_s
| where array_length(Silent) > 0
| project
    Rule   = DisplayName_s,
    Status = "Feed broken — silent in last 7d",
    KnownTables = strcat_array(Silent, ", ")
| union (
    SentinelAnalyticalRules_CL
    | where IsEnabled_b == true and isnotempty(Query_s)
    | summarize by DisplayName_s
    | join kind=leftanti RuleTableRefs on DisplayName_s
    | project Rule = DisplayName_s, Status = "Tables not resolvable from query text", KnownTables = ""
  )
| order by Status asc, Rule asc
```

**Triage:**
1. Prioritise by blast radius — silent `DeviceProcessEvents` breaks dozens of rules; a silent custom table may break one
2. Investigate the specific connector or DCR feeding the broken table
3. If the source is permanently dead, disable dependent rules — an enabled rule with no data is false confidence, not coverage

---

## Query 5 — Forgotten Disabled Rules

**What it catches:** Rules disabled "temporarily" during a noisy migration or incident that were never re-enabled. Generates zero signal, no health events, no dashboard presence — invisible coverage gaps.

**Key insight:** `SentinelAudit` surfaces who disabled a rule and when, enabling accountability and informed decisions about restoration vs. deletion.

**Requires:** `SentinelAnalyticalRules_CL` inventory table

```kql
let auditRetentionDays = 90;
let DisableEvents =
    SentinelAudit
    | where SentinelResourceType == "Analytic Rule"
    | where Description == "Create or update analytics rule."
    | extend Updated  = parse_json(tostring(ExtendedProperties.UpdatedResourceState)).properties.enabled
    | extend Original = parse_json(tostring(ExtendedProperties.OriginalResourceState)).properties.enabled
    | where tobool(Original) == true and tobool(Updated) == false
    | summarize arg_max(TimeGenerated, tostring(ExtendedProperties.CallerName)) by RuleName = SentinelResourceName
    | project RuleName, DisabledAt = TimeGenerated, DisabledBy = ExtendedProperties_CallerName;
SentinelAnalyticalRules_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by Name_s
| where IsEnabled_b == false
| join kind=leftouter DisableEvents on $left.DisplayName_s == $right.RuleName
| extend DaysDisabled = datetime_diff("day", now(), DisabledAt)
| project
    RuleName = DisplayName_s,
    DisabledAt = iff(isnotempty(DisabledAt), tostring(DisabledAt), "unknown"),
    DaysDisabled,
    DisabledBy = coalesce(DisabledBy, "unknown"),
    Category = iff(isnotempty(DisabledAt), strcat("Disabled ", tostring(DaysDisabled), " days ago"), strcat("Disabled >", auditRetentionDays, " days ago (predates audit retention)"))
| order by DaysDisabled desc
```

**Triage:**
1. For each rule, determine if the original detection goal is still relevant
2. Re-enable and tune if still needed
3. Delete entirely if no longer relevant — disabled rules are clutter that mislead future auditors

---

## Query 6 — Untracked Detections

**What it catches:** Enabled, functional rules missing MITRE tactic/technique tags and/or entity mappings. Makes detections invisible in coverage workbooks. Without entity mappings, incidents arrive disconnected from users/hosts, UEBA doesn't feed, investigation graphs don't build.

**Requires:** `SentinelDeployedAlerts_CL` inventory table (distinct from `SentinelAnalyticalRules_CL`)

**Priority order for fixes:**
1. Entity mappings — highest priority; investigation graphs depend on these
2. Tactics — required for MITRE ATT&CK coverage workbooks
3. Techniques — documentation quality

```kql
SentinelDeployedAlerts_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by Name_s
| where IsEnabled_b == true
| extend
    MissingTactics = isnull(Tactics_s) or Tactics_s in ("", "[]"),
    MissingTechniques = isnull(Techniques_s) or Techniques_s in ("", "[]")
| where MissingTactics or MissingTechniques
| project
    RuleName = DisplayName_s,
    Severity = Severity_s,
    MissingTactics,
    MissingTechniques
| order by MissingTactics desc, MissingTechniques desc, RuleName asc
```

---

## Query 7 — Coverage Drift

**What it catches:** Detection coverage that silently degrades over time. Rules enabled, data flowing — but the behaviour stopped matching due to data format changes, over-aggressive tuning, or content pack updates.

**Key insight:** Q1 catches rules that never fire. Q4 catches data that never flows. Q7 is the middle ground — both functioning, but the pattern stopped matching. Cross-reference techniques appearing in both Q4 and Q7 — those are highest-priority fixes.

```kql
let recent =
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | extend TechArray = iff(Techniques startswith "[", parse_json(Techniques), split(replace_regex(Techniques, @"\s*,\s*", ","), ","))
    | mv-expand Technique = TechArray
    | extend Technique = tostring(Technique)
    | where isnotempty(Technique)
    | summarize RecentCount = count() by Technique;
let prior =
    SecurityAlert
    | where TimeGenerated between (ago(60d) .. ago(30d))
    | extend TechArray = iff(Techniques startswith "[", parse_json(Techniques), split(replace_regex(Techniques, @"\s*,\s*", ","), ","))
    | mv-expand Technique = TechArray
    | extend Technique = tostring(Technique)
    | where isnotempty(Technique)
    | summarize PriorCount = count() by Technique;
prior
| join kind=leftouter recent on Technique
| extend RecentCount = coalesce(RecentCount, 0)
| extend DropPercent = round(100.0 * (PriorCount - RecentCount) / PriorCount, 1)
| extend IsSilent = RecentCount == 0
| where PriorCount >= 20 and DropPercent >= 60
| project Technique, PriorCount, RecentCount, DropPercent, IsSilent
| order by IsSilent desc, PriorCount desc
```

**Triage:**
1. Find rules tagged with the drifted technique
2. Rules still firing → attacker behaviour likely changed; informational, monitor
3. Rules silent → detection broken; cross-reference Q4 (Broken Feeds) for confirmation

---

## Query Reference Summary

| # | Name | Primary Table | Requires Inventory | What It Finds |
|---|---|---|---|---|
| 1 | Silent Zombies | `_SentinelHealth()` | No | Rules running but returning zero results |
| 2 | Shadow Detectors | `SecurityAlert`, `SecurityIncident` | No | Rules producing alerts that never become incidents |
| 3 | Everything Is Benign | `SecurityIncident`, `SecurityAlert` | No | Rules with >90% FP/BP close rate |
| 4 | Broken Feeds | `Usage`, `SentinelAnalyticalRules_CL` | Yes | Rules querying tables with no recent ingestion |
| 5 | Forgotten Disabled | `SentinelAudit`, `SentinelAnalyticalRules_CL` | Yes | Disabled rules with who/when attribution |
| 6 | Untracked Detections | `SentinelDeployedAlerts_CL` | Yes | Enabled rules missing MITRE tags or entity mappings |
| 7 | Coverage Drift | `SecurityAlert` | No | MITRE techniques with >60% alert volume drop |

---

## Failure Mode Decision Tree

```
Rule is enabled
│
├── Never returns data (Q1 — Silent Zombie)
│     └── Why? → Check source table ingestion (Q4 — Broken Feed)
│
├── Returns data → Creates alerts → Never creates incidents (Q2 — Shadow Detector)
│     └── Why? → Incident creation off, or automation rule suppressing
│
├── Creates incidents → Analysts close as FP/BP >90% (Q3 — Everything Benign)
│     └── Fix: Tune exclusions (BP dominant) or rewrite logic (FP dominant)
│
├── Was detecting a technique, now isn't (Q7 — Coverage Drift)
│     └── Cross-ref with Q4 — if in both, it's a data problem not a logic problem
│
├── Disabled and forgotten (Q5 — Forgotten Disabled)
│     └── Re-enable or delete; never leave in ambiguous state
│
└── Enabled but missing metadata (Q6 — Untracked)
      └── Fix entity mappings first, then tactics, then techniques
```

---

## Environment Notes

- **Inventory table status** — `SentinelAnalyticalRules_CL` and `SentinelDeployedAlerts_CL` require a Logic App deploying ARM rule definitions. Confirm these tables exist before running Q4, Q5, or Q6.
- **Q3 thresholds** — `MinNonActionableRate = 0.9` is the retire/rewrite threshold; 70–90% is tune. Adjust to your environment's tolerance.
- **Q7 thresholds** — `PriorCount >= 20` and `DropPercent >= 60` are conservative starting points. Lower `PriorCount` to catch lower-volume techniques.
- **Run cadence** — every few months as a detection library hygiene cycle; consider scheduling after major content hub updates or connector changes.
- **OT/SCADA relevance** — Broken Feeds (Q4) is particularly relevant if your OT/SCADA assets are feeding Sentinel via Wazuh or custom DCRs. Silent tables there could mean zero coverage on the fertilizer plant assets.

---

## Hardening Control Pairs

- [[Hardening/Controls/HARD-Sentinel-Health-Monitoring]] — enable Auditing and Health as prerequisite
- [[Detection-KQL/Queries/KQL-Sentinel-Analytics-Rule-Inventory]] — Logic App for `SentinelAnalyticalRules_CL` if not yet deployed

---

## Related Notes

- [[Detection-KQL/Analytics-Rules/RULE-Detection-Engineering-Standards]]
- [[Research/Claude/CLAUDE-KQL-Schema-Validation-Reference]]
- [[Threat-Hunting/Campaigns/HUNT-MITRE-Coverage-Review]]
- [[Projects/M365-Hardening]]

---

## Test Results

> Not yet run in your environment. Validate schema columns above before executing.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-26 | Initial note created from Medium article — adapted to vault workflow |
