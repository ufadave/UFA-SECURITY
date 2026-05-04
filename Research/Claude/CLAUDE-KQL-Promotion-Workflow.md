---
title: "KQL Promotion Workflow — Stub to Deployed Rule"
date: 2026-05-03
type: claude
status: active
tags:
  - "#resource"
  - "#detection"
  - "#status/active"
---

# KQL Promotion Workflow — Stub to Deployed Rule

## Problem Statement

INTEL notes generated during inbox triage contain KQL detection stubs under a "Detection Notes" section. These stubs have schema validation checklists (`- [ ] ColumnName`) and test result placeholders, but no formal path to promotion. The result is a growing library of unvalidated detection candidates that never become operational coverage.

This note defines the full pipeline: **Stub → Candidate → Validated → Promoted → Deployed**.

---

## Pipeline Overview

```
INTEL note (stub)
      │
      ▼
[Stage 1] CANDIDATE
  KQL- note created, stub extracted, schema validated
      │
      ▼
[Stage 2] VALIDATED  
  Query runs clean against real data, logic confirmed
      │
      ▼
[Stage 3] PROMOTED
  Full KQL- note completed, analytics rule config populated
      │
      ▼
[Stage 4] DEPLOYED
  Rule live in Sentinel / MDE Custom Detection
      │
      ▼
[Stage 5] MONITORED
  Alert volume, FP rate, tuning notes tracked in KQL- note
```

---

## Stage 1 — Candidate

**Trigger:** INTEL note contains a KQL stub worth pursuing (detection_candidate: true in frontmatter).

**Actions:**
1. Create a new `KQL-` note using the KQL Query Template
2. Link it back to the source INTEL note: `Source: [[INTEL-...]]`
3. Set frontmatter status: `status: candidate`
4. Copy the stub into the query block — do not clean it up yet, preserve original intent
5. Add the `#detection/query` tag if it's a hunting query, `#detection/analytics-rule` if it's destined for Sentinel

**In the source INTEL note:**
- Update the stub section with: `→ Promoted to [[KQL-...]]`
- Check off the `detection_candidate` line

**Naming convention:**
```
KQL-[Table]-[Behaviour]-[Context].md
```
Examples:
- `KQL-CloudAppEvents-BulkMailboxEnumeration-AppOnly.md`
- `KQL-DeviceProcessEvents-AFALGSocketCreation-Linux.md`
- `KQL-AuditLogs-BroadGraphPermissionGrant-ServicePrincipal.md`

---

## Stage 2 — Validated

**Trigger:** Query has been run against real data in Advanced Hunting or Log Analytics.

**Actions:**
1. Run the query in the appropriate schema context:
   - **MDE Advanced Hunting** — for `DeviceXxx` tables
   - **Sentinel Log Analytics** — for `AuditLogs`, `SigninLogs`, `CloudAppEvents`, `SecurityEvent`
2. Work through the validated columns checklist — check off confirmed columns, annotate any that differ from expectation
3. Note actual result volume over a representative time window (e.g. 7d, 30d)
4. Assess signal quality: Does it fire on real events? False positive rate acceptable?
5. Document schema findings — column name differences, missing fields, alternative approaches
6. Update frontmatter: `status: validated`

**Common schema pitfalls to check at this stage:**
- `RemoteIPAddress` vs `RemoteIP` (table-dependent)
- `IsExternalUser` availability in `CloudAppEvents`
- `parse_json(AdditionalFields)` required for WDAC and many DeviceEvents fields
- `ProcessTokenElevationType` availability on Linux MDE agents
- `ApplicationId` vs `AppId` across Sentinel tables

**If the query fails schema validation:**
- Document what broke and why
- Revise the query
- If column is confirmed absent in your environment, flag with `⚠️ Not available in this tenant` and note workaround or accept as gap

---

## Stage 3 — Promoted

**Trigger:** Query is validated, signal quality is acceptable, decision made to operationalise.

**Actions:**
1. Decide deployment target:
   - **Sentinel Analytics Rule** — scheduled, generates incidents, feeds into SIEM workflow
   - **MDE Custom Detection** — continuous, generates alerts in Defender XDR portal
   - **Hunting Query only** — manual-run only, not deployed as a rule (document rationale)

2. Complete the Sentinel Analytics Rule config table in the KQL- note:

| Setting | Value |
|---|---|
| Rule Name | |
| Severity | Low / Medium / High / Critical |
| Query Frequency | e.g. 1h |
| Query Period (Lookback) | e.g. 1h |
| Trigger Threshold | Count > 0 |
| Entity Mapping | Account, Host, IP as applicable |
| MITRE Tactics | |
| MITRE Techniques | |
| Suppression | e.g. 5h if noisy |

3. Add exclusion logic for known-good baselines (service accounts, maintenance windows, AVD pools)
4. Define named `let` blocks for all list definitions (service account lists, known-good app IDs, etc.)
5. Update frontmatter: `status: promoted`

**Hunting-only rationale examples (document explicitly):**
- High noise in managed environment (AVD pools, scheduled tasks) — see 4688 time-series anomaly decision
- Requires manual context to interpret — not suitable for automated alerting
- Useful for periodic campaign hunting but not continuous monitoring

---

## Stage 4 — Deployed

**Trigger:** Rule is created in Sentinel or MDE.

**Actions:**
1. Create the rule in Sentinel (Analytics → Create) or MDE (Custom Detections → Create rule)
2. Record the rule ID or name in frontmatter: `sentinel_rule_id: "..."`
3. Check off test result checkbox in the note: `- [x] Deployed to Sentinel`
4. Update frontmatter: `status: deployed`, `promoted_to_rule: true`
5. Remove `#status/draft` tag, add `#status/active`
6. Remove `#action-required` tag if present

---

## Stage 5 — Monitored

**Trigger:** Rule has been live for at least one week.

**Actions:**
1. Note alert volume over first 7d and 30d in the KQL- note under a "## Operational Notes" section
2. Document any false positive patterns and exclusions added post-deployment
3. If rule is consistently noisy: consider demoting to hunting-only and document decision
4. If rule generates zero alerts over 90d: review whether the detection is positioned correctly or coverage is being missed

---

## Triage Queue — Current Promotion Candidates

Work through these in priority order. Each row links to the source INTEL note and the KQL stub that needs promoting.

| Priority | Source Note | Stub Description | Target | Stage |
|---|---|---|---|---|
| 🔴 High | [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] | App-only bulk mailbox access via Graph | Sentinel Analytics Rule | Candidate |
| 🔴 High | [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] | Broad Graph permission grant to service principal | Sentinel Analytics Rule | Candidate |
| 🔴 High | [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]] | Non-interactive app sign-in anomaly | Sentinel Analytics Rule | Candidate |
| 🟡 Medium | [[INTEL-CVE-2026-31431-CopyFail-Linux-LPE]] | AF_ALG socket / LPE process anomaly (Linux MDE) | Hunting Query | Candidate — schema TBC |
| 🟡 Medium | [[INTEL-Finding-Zero-Days-With-Any-Model-AI-Vuln-Research]] | No stub — strategic reference only | N/A | N/A |

---

## Conventions Reference

### Frontmatter Status Values
```yaml
status: candidate      # KQL- note created, stub extracted
status: validated      # Run against real data, schema confirmed
status: promoted       # Analytics rule config complete, ready to deploy
status: deployed       # Live in Sentinel or MDE
status: hunting-only   # Validated but intentionally not deployed as rule
status: deprecated     # Replaced or no longer relevant
```

### Tag Conventions
```
#detection/query          — generic KQL, not yet classified
#detection/analytics-rule — deployed or destined for Sentinel scheduled rule
#detection/hunting        — manual hunting query
#detection/audit          — point-in-time audit query (not continuous)
```

### Standard KQL- Note Sections
1. Frontmatter (title, date, source INTEL note, MITRE, status, sentinel_rule_id)
2. Purpose — one paragraph, what behaviour this detects and why
3. Schema — table, context (Advanced Hunting vs Log Analytics)
4. Query — full KQL with named `let` blocks
5. Validated Columns — markdown checkboxes
6. Exclusions — documented with rationale
7. Sentinel Analytics Rule Config — table
8. Test Results — checkboxes
9. Operational Notes — post-deployment alert volume, FP patterns, tuning
10. Related Notes — wikilinks to source INTEL, hardening controls
11. Changelog

---

## Related Notes
- [[CLAUDE-Intel-Obsidian-System-Improvement-Plan]]
- [[INTEL-M365Pwned-OAuth-Enumeration-Exfiltration-Toolkit]]
- [[INTEL-CVE-2026-31431-CopyFail-Linux-LPE]]

## Changelog
| Date | Change |
|---|---|
| 2026-05-03 | Initial workflow design |
