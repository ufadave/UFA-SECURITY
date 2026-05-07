# Phase 2 — Testing & Validation (Audit Mode)

**Status:** ⬜ Not Started
**Prerequisite:** Phase 1 complete (base policy + Ring 0 supplemental built in AppControl Manager)
**Soak period:** 14 days minimum per ring (longer for POS — see `04-POS-Rollout.md`)

---

## Objectives

1. Deploy base policy in **audit mode** to Ring 0 devices.
2. Collect audit events from MDE Advanced Hunting.
3. Identify legitimate apps that would be blocked.
4. Generate supplemental policies via AppControl Manager.
5. Validate that re-deploying the supplemental clears the audit blocks.
6. Repeat for each ring before promoting to enforce mode (Phase 3).

---

## Audit Mode Process

1. Build base policy in audit mode (`Audit Mode` option enabled in AppControl Manager).
2. Deploy via Intune device configuration profile to the ring's device group.
3. Confirm policy applied:
   - Check `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\` for the `{GUID}.cip` file with a recent timestamp.
   - Or use `CiTool.exe --list-policies` (see `WDAC-Policy-Management-Commands.md`).
4. Have testers exercise the full app workflow (see Tester Engagement below).
5. Pull audit events from MDE AH using `KQL-Audit-Mode-Blocks.md`.
6. Import audit CSV into AppControl Manager → generate supplemental policy.
7. Deploy supplemental → confirm next audit run is clean.

---

## Tester Engagement — CRITICAL

Per attempt-1 lessons, this is the single biggest risk factor. Cardlock team's default testing was insufficient ("make sure the lights come on").

### Per-app exercise checklist

For each in-scope app, document:

- Who the **actual heavy users** are (not just the assigned testers).
- What workflows must be exercised (login, transaction, print, swipe, sync, end-of-day, reports, etc.).
- Sign-off from the heavy user that the workflow ran cleanly during audit period.

### Tester Roster

| Business Unit | App | Heavy User(s) | Pass-through Tester | Sign-off Status |
|---------------|-----|---------------|---------------------|-----------------|
| Cardlock | _(TBD)_ | Diane Wesley, Michelle Tiery (?) | Felix, Stephen | ⬜ |
| _(populate)_ | | | | |

> **Note:** Confirm spelling of names and engage these users directly during Phase 2 setup. Felix has confirmed they do the heavy lifting on testing.

---

## Audit Data Collection

### Primary KQL queries

- `KQL-Audit-Mode-Blocks.md` — full event detail for new supplemental rules
- `KQL-AppControl-Activity-Summary.md` — fleet-wide sanity check (right devices, right scope)
- `KQL-Device-Scoped-AppControl.md` — single-device deep dive

### Schema dependency

All KQL above runs against `DeviceEvents` in MDE Advanced Hunting. **Validate schema** before each Phase 2 run:

- Confirm `ActionType` values still include `AppControlCodeIntegrityPolicyAudited` and related.
- Confirm `AdditionalFields` JSON still parses with current keys (`SHA256`, `Publisher`, `PolicyName`).

Microsoft has changed AppControl `ActionType` naming before — re-validate any time queries return zero results unexpectedly.

---

## Compatibility Tracker

For each ring, maintain a list of audit-mode blocks, their resolution, and which supplemental version captured them.

| Ring | App / File | First Seen (Date) | SHA256 | Resolution | Supplemental Version | Confirmed Clean |
|------|------------|-------------------|--------|------------|----------------------|-----------------|
| _(populate during audit period)_ | | | | | | |

### Known blocks from attempt 1 (carry-forward)

| File | App | Notes |
|------|-----|-------|
| `OPOSSigCap.ocx` | POS / cardlock | Blocked enforce mode in attempt 1. Added to POS supplemental. Re-validate in attempt 2. |

---

## Audit Period Exit Criteria

A ring exits audit mode when:

- [ ] All identified heavy users have signed off on workflow testing.
- [ ] Soak period has elapsed (14 days minimum).
- [ ] Last 7 days of audit data show no new blocks for in-scope apps.
- [ ] Compatibility tracker is fully resolved (no open items).
- [ ] Supplemental policy is finalised and committed (version locked, see `01-Policy-Design.md` changelog).
- [ ] Rollback procedure tested for the ring (see `WDAC-Rollback-Procedure.md`).

---

## Open Items

- [ ] Confirm MDE AH `ActionType` schema before first audit deployment.
- [ ] Build full tester roster across all in-scope business units.
- [ ] Define per-app workflow checklists.
- [ ] Decide on audit→enforce switching tool (AppControl Manager preferred — test first).
