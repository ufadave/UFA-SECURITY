# Phase 4 — POS Terminal Rollout

**Status:** ⬜ Not Started
**Prerequisite:** Phase 3 complete (Ring 0 + Ring 1 stable in enforce)
**Approach:** Staggered, one site at a time, outside trading hours only

---

## POS Context

- Fixed, known software stack — ideal for strict lockdown.
- Remote management only — no on-site IT at most locations.
- Staggered rollout by location.
- Deploy outside trading hours only.
- **Must test rollback on POS test unit before any production deployment.**

---

## Pre-Flight Checklist (Project-Wide)

Before starting any POS site:

- [ ] POS supplemental policy built and audit-tested (Phase 2).
- [ ] Rollback procedure validated on POS test unit (full execution, not dry-run).
- [ ] `OPOSSigCap.ocx` confirmed in POS supplemental (carry-forward from attempt 1).
- [ ] Comms plan agreed with location managers.
- [ ] On-call coverage for first 4 hours post-deployment, per site.
- [ ] Out-of-hours deployment window confirmed per site.

---

## Per-Site Pre-Flight Checklist

For each site, before deployment:

- [ ] Site identified and Intune device group built.
- [ ] Local manager notified with deployment date/time.
- [ ] Trading hours confirmed for site (deployment must be outside).
- [ ] All POS terminals at site checked-in to Intune within last 24 hours.
- [ ] Rollback path confirmed working (group exists, unsigned supplemental ready).

---

## Per-Site Post-Deployment Checks

Within 4 hours of deployment:

- [ ] All terminals at site report policy applied (`KQL-AppControl-Activity-Summary.md`).
- [ ] Zero `AppControlCodeIntegrityPolicyBlocked` events for site (`KQL-Enforced-Mode-Blocks.md` filtered by device).
- [ ] Site manager sign-off on first transactions of next trading day.

---

## Site Rollout Tracker

| Site | Province | Terminals | Deploy Date | Out-of-Hours Window | Post-Deploy Status | Sign-off |
|------|----------|-----------|-------------|---------------------|--------------------|----------|
| _(populate as sites are scheduled)_ | | | | | | |

---

## Rollback Decision Tree

If any of the following occurs, **roll back immediately** per `WDAC-Rollback-Procedure.md`:

- A POS terminal fails to process a transaction within 1 hour of trading day start.
- Any block event for a known-good POS binary (cross-check against attempt-1 list and POS supplemental).
- Site manager reports terminal unusable.

Do not attempt remote troubleshooting on a POS terminal during trading hours — roll back, then diagnose.

---

## Phase 4 Exit Criteria

- [ ] All POS sites deployed and stable for 14+ days post-deployment.
- [ ] Zero unresolved enforced blocks across the POS estate.
- [ ] Project sign-off documented.
