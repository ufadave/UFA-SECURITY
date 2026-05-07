# Phase 3 — Pilot Ring Deployment (Enforced)

**Status:** ⬜ Not Started
**Prerequisite:** Phase 2 complete for Ring 0 and Ring 1 (audit-mode soak passed)
**Scope:** Ring 0 (IT/Security) and Ring 1 (early adopter volunteers)

---

## Objectives

1. Switch base policy from audit to enforce mode for Ring 0.
2. Soak Ring 0 in enforce mode for 14 days minimum.
3. Promote to Ring 1 once Ring 0 is stable.
4. Soak Ring 1.
5. Sign off Phase 3 before starting Phase 4 (POS).

---

## Pre-Flight Checklist

Before flipping enforce mode for Ring 0:

- [ ] Phase 2 audit-mode exit criteria all met (see `02-Testing-Validation.md`).
- [ ] Rollback procedure tested on a Ring 0 device (`WDAC-Rollback-Procedure.md`).
- [ ] Audit→enforce switch method confirmed working (see `WDAC-Switch-Audit-To-Enforce.md`).
- [ ] Ring 0 device list confirmed in Intune.
- [ ] Communication sent to Ring 0 users with rollback expectation.
- [ ] On-call coverage in place for first 72 hours.

---

## Deployment Steps

1. Edit base policy in AppControl Manager — disable audit mode.
2. Increment policy version (document in `01-Policy-Design.md` changelog).
3. Deploy via Intune to Ring 0 group.
4. Force Intune sync on a sample device.
5. Confirm policy update on device:
   - `CiTool.exe --list-policies` shows enforce mode.
   - `Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CI_State` confirms state.
6. Run `KQL-Enforced-Mode-Blocks.md` over first 24 hours — expect zero blocks if Phase 2 was thorough.

---

## Soak Period — Ring 0

**Duration:** 14 days minimum.
**Daily check:** `KQL-Enforced-Mode-Blocks.md` for new `AppControlCodeIntegrityPolicyBlocked` events.
**Exit criteria:**

- [ ] No enforced blocks for legitimate apps for the last 7 days.
- [ ] No user-reported issues in last 7 days.
- [ ] Rollback drill performed once during soak (full procedure, not just dry-run).

### Ring 0 Issue Tracker

| Date | Device | Issue | Resolution | Supplemental Update? |
|------|--------|-------|------------|----------------------|
| _(populate during soak)_ | | | | |

---

## Promotion to Ring 1

Same process as Ring 0:

1. Confirm Ring 1 supplemental built and tested (Phase 2).
2. Build deployment to Ring 1 group in Intune.
3. Comms to Ring 1 volunteers.
4. Deploy.
5. Soak 14 days.

### Ring 1 Issue Tracker

| Date | Device | Issue | Resolution | Supplemental Update? |
|------|--------|-------|------------|----------------------|
| _(populate during soak)_ | | | | |

---

## Phase 3 Exit Criteria

- [ ] Ring 0 + Ring 1 both stable in enforce mode for 14+ days.
- [ ] All issues resolved or accepted.
- [ ] No new blocks in last 7 days across both rings.
- [ ] Phase 4 prerequisites met (see `04-POS-Rollout.md`).
