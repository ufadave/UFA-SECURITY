---
date: 2026-05-28
title: Phishing to RMM Fake Invitation Access Blind Spot Email
table: EmailEvents
schema: Advanced Hunting
mitre:
  - T1566.002
  - T1219
tactic: Initial Access
technique: "T1566.002 — Spearphishing Link"
status: Draft
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/draft"
  - "#email"
---

# KQL — Phishing to RMM Fake Invitation Access Blind Spot Email

**Table:** EmailEvents | **Schema:** Advanced Hunting
**MITRE ATT&CK:** T1566.002 | **Tactic:** Initial Access
**Created:** 2026-05-28 | **Status:** `Draft`

---

## Purpose

Email-side detection for the phishing-to-RMM fake invitation lure pattern. Attackers send fake conference/event/meeting invitations from `.de` domains with CAPTCHA redirect chains that ultimately deliver RMM installer payloads.

This stub targets the lure pattern specifically — `.de` sender or URL domains combined with invitation-themed subject lines. Intended as a hunting query or low-frequency scheduled rule to surface suspicious invitation emails for analyst review, not a high-confidence automated response trigger.

See `KQL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot-Device` for the endpoint-side signals (RMM tool execution and network connections).

> **Schema note:** `EmailEvents` is Advanced Hunting (MDO). Confirm your MDO connector is active and `EmailEvents` is populated. The `.de` domain pattern is specific to observed campaigns — expand or narrow based on your organisation's legitimate European email traffic volume.

---

## Query

```kql
// Fake invitation lure pattern — .de domains, invitation-themed subjects
// Based on observed campaign pattern: .de sender/URL domain + invitation subject
// Adjust domain list and subject keywords to match your threat intelligence
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where SenderFromDomain endswith ".de"
    or UrlDomain endswith ".de"
| where Subject has_any ("invitation", "invite", "event", "conference", "meeting")
| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
          Subject, UrlDomain, DeliveryAction, DetectionMethods
| order by Timestamp desc
```

---

## Validated Columns
- [ ] `EmailDirection` — EmailEvents ✓ confirm `"Inbound"` is valid value
- [ ] `SenderFromDomain` — EmailEvents ✓ standard column
- [ ] `UrlDomain` — EmailEvents — **validate in your environment**; may need `UrlInfo` table join for full URL data
- [ ] `Subject` — EmailEvents ✓ standard column
- [ ] `DeliveryAction` — EmailEvents ✓ standard column
- [ ] `DetectionMethods` — EmailEvents ✓ confirm field is populated for your MDO configuration
- [ ] `EmailEvents` table — confirm MDO connector is active and ingesting events

---

## Test Results

- [ ] Tested in environment
- [ ] Baseline run — assess volume of `.de` inbound email for false positive risk
- [ ] Adjust domain and subject filters to match observed lure patterns in your environment
- [ ] FP rate acceptable

---

## Deployment

### MDE Custom Detection Rule
- **Rule Name:** Custom - Phishing to RMM Fake Invitation Email Pattern
- **Frequency:** every 1h
- **Lookback:** 1h
- **Severity:** Medium
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- INACTIVE: EmailEvents is Advanced Hunting only -->
<!-- Deploy via MDE Custom Detection -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot]]
- [[KQL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot-Device]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-28 | Created — backfill companion to [[INTEL-Phishing-to-RMM-Fake-Invitation-Access-Blind-Spot]] via backfill stubs command |
