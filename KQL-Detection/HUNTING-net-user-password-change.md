---
date: 2026-05-07
title: net user password change
table: DeviceProcessEvents
schema: Advanced Hunting
mitre: T1098
tactic: TA0003 / TA0004
technique: T1098 — Account Manipulation
status: Draft
promoted_to_rule: false
sentinel_rule_id: ""
tags:
  - "#detection/hunting"
  - "#endpoint"
  - "#identity"
  - "#status/done"
---

# HUNTING — net user password change

---

**Table:** `DeviceProcessEvents` | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1098 | **Tactic:** Persistence / Privilege Escalation | **Technique:** Account Manipulation
**Created:** 2026-05-07 | **Status:** `Draft`

---

## Purpose

Detect interactive use of `net user <target> *` (or `net user <target> <password>`) on managed endpoints — the canonical Windows command for changing an account's password from the command line. The pattern is suspicious when the initiator and target accounts differ, when it occurs outside known help-desk workflows, or when chained with account-creation or group-membership changes.

This is filed as a **hunting query, not an analytics rule**, because legitimate help-desk and IT-admin workflows produce a non-trivial false-positive baseline. Promoting to a scheduled rule requires environmental tuning of the IT-admin allowlist (see "Promotion criteria" below).

Seeded by finding [[IR-2026-05-07-lt13069-net-user-tcai]].

---

## Query

```kql
// HUNT — net user password change activity
// Surfaces interactive password modifications via net.exe / net1.exe.
// Both binaries are captured because net.exe always shells out to net1.exe;
// either may be the visible process depending on event source.
//
// Lookback: 30d default — adjust per cadence.
let LookbackDays = 30d;
//
// Known IT/help-desk operators — populate with delegated admin accounts.
// Empty default = no exclusions, all events surfaced.
let HelpDeskOperators = dynamic([
    // "helpdesk-svc",
    // "itadmin1"
]);
//
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where ActionType == "ProcessCreated"
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine matches regex @"(?i)\bnet1?\s+user\s+\S+\s+(\*|\S+)"
// Exclude pure account enumeration (no password argument):  "net user <name>"
| where ProcessCommandLine !matches regex @"(?i)\bnet1?\s+user\s+\S+\s*$"
// Exclude /domain operations — these are rarely the persistence primitive
// and produce most help-desk noise. Comment out if you want domain coverage.
| where ProcessCommandLine !contains "/domain"
| extend TargetAccount = extract(@"(?i)\bnet1?\s+user\s+(\S+)\s+", 1, ProcessCommandLine)
| extend IsSelfChange = tolower(TargetAccount) == tolower(AccountName)
| extend IsHelpDeskOperator = AccountName in~ (HelpDeskOperators)
// Hunting view: keep self-changes + helpdesk visible but flagged
| project Timestamp, DeviceName, AccountDomain, AccountName, TargetAccount,
          IsSelfChange, IsHelpDeskOperator, ProcessIntegrityLevel,
          ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessAccountName, ReportId
| sort by Timestamp desc
```

---

## Validated Columns

- [ ] `Timestamp` — event time
- [ ] `DeviceName` — host where the command ran
- [ ] `AccountDomain` / `AccountName` — initiator (the user running `net.exe`)
- [ ] `ProcessCommandLine` — full command for regex match and target extraction
- [ ] `FileName` — `net.exe` or `net1.exe`
- [ ] `ProcessIntegrityLevel` — Medium IL flagging non-elevated execution
- [ ] `InitiatingProcessFileName` — parent process (expect `cmd.exe`, `powershell.exe`)
- [ ] `InitiatingProcessParentFileName` — grandparent for lineage context
- [ ] `ReportId` — for unique row reference

---

## Test Results

- [ ] Run against last 30d of telemetry — confirm baseline volume
- [ ] Identify and document IT operator accounts → populate `HelpDeskOperators` list
- [ ] Validate regex against known-good samples:
    - `net user alice *` → match, target=alice
    - `net1 user bob NewP@ss123` → match, target=bob
    - `net user` (enumerate all) → no match
    - `net user alice` (lookup only) → no match (excluded)
    - `net user alice * /domain` → no match (excluded)
- [ ] Confirm initial finding [[IR-2026-05-07-lt13069-net-user-tcai]] is surfaced

---

## Hunting Cadence

**Recommended:** Monthly hunt, run interactively in MDE Advanced Hunting.

**Triage workflow per hit:**
1. Is `IsSelfChange == true`? → likely benign self-service password change, deprioritise.
2. Is `IsHelpDeskOperator == true`? → expected, but spot-check the device makes sense for that operator's scope.
3. Otherwise — initiator ≠ target and not a known operator → investigate as per finding template, capture as `IR-` finding.

---

## Sentinel Analytics Rule

- **Rule Name:** _(not promoted — see promotion criteria)_
- **Frequency:** N/A
- **Lookback:** N/A
- **Severity:** N/A
- **Deployed:** [ ]

### Promotion Criteria

This query is suitable for promotion to a scheduled analytics rule **only after**:

1. `HelpDeskOperators` list is populated and stable (validated against 60+ days of telemetry).
2. False-positive rate per week is in the low single digits.
3. A documented IT workflow exists describing when local-account password changes are legitimate (excludes service account rotation, break-glass account maintenance, etc.).

If FP rate stays high after tuning, **keep this as a hunting query** — consistent with the principle that detection-primitive fit to environment matters more than coverage breadth.

---

## Hardening Control Pair

- **Control:** [[]] _(candidate: restrict local admin distribution; restrict interactive logon for service accounts)_
- **Linked:** [ ]

Hardening pairing rationale: this query becomes much higher-signal in an environment where local admin rights are tightly controlled. If LAPS + reduced local admin sprawl is in place, any interactive `net user *` from a non-IT account is by definition anomalous.

---

## Notes & References

- T1098 — Account Manipulation (https://attack.mitre.org/techniques/T1098/)
- `net.exe` always invokes `net1.exe` for the actual operation — both are surfaced to avoid telemetry source variance.
- Asterisk in MDE telemetry is **literal** (the interactive password-prompt argument), not redaction.
- `/domain` switch deliberately excluded — domain password resets via `net.exe` are rarer in modern environments (Set-ADAccountPassword / ADUC dominate) and tend to produce help-desk-heavy noise. Re-enable if domain coverage is desired.

---

## Related Notes

- [[IR-2026-05-07-lt13069-net-user-tcai]] — seeding finding (sample positive case)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-07 | Created — seeded by lt13069 finding |
