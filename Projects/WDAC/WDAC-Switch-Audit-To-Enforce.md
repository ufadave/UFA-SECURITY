# Runbook — Switching Policy from Audit to Enforce Mode

**Purpose:** Document the procedure (and known gotcha) for switching a deployed policy from audit to enforce.
**Status:** ⚠️ Verify in current AppControl Manager version before using — failed in attempt 1.

---

## Attempt-1 Gotcha

In attempt 1, switching the policy from audit to enforce in **AppControl Manager** failed for unclear reasons. The fallback was to use the **WDAC Wizard** for the switch.

This may have been:

- A bug in the AppControl Manager version at the time.
- A permission issue (Intune integration not authorised for the action).
- A user-error / workflow misunderstanding.

**Action before Phase 3:** Re-test the audit→enforce switch in AppControl Manager on a Ring 0 test device. If it still fails, log a GitHub issue and update this runbook.

---

## Preferred Procedure — AppControl Manager

1. Open AppControl Manager.
2. Load the base policy.
3. Disable the **Audit Mode** rule option.
4. Save → policy version increments automatically (verify the increment is intentional).
5. Document the version change in `01-Policy-Design.md` policy version changelog.
6. Deploy via AppControl Manager's Intune integration to the target group.
7. Force a sync on a test device and confirm:
   - `CiTool.exe --list-policies` shows enforce mode.
   - `Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CI_State` confirms.

---

## Fallback Procedure — WDAC Wizard

> Only use this if AppControl Manager fails. Document in `WDAC-Lessons-Learned-Attempt-1.md` follow-up if used.

1. Open WDAC Wizard.
2. Load the existing policy XML.
3. Toggle off audit mode.
4. Save the policy XML.
5. Deploy via Intune (manual upload to device configuration profile).
6. Validate as above.

---

## Validation After Switch

Within 24 hours of switching to enforce mode:

- [ ] `KQL-Enforced-Mode-Blocks.md` shows no `AppControlCodeIntegrityPolicyBlocked` events for legitimate apps.
- [ ] Sample test devices report enforce mode in `CiTool.exe --list-policies`.
- [ ] No user reports of broken apps.

If any block events appear:

1. Investigate the blocked file (path, signature, hash).
2. If legitimate, update the supplemental policy.
3. If unknown / suspicious, treat as a security event — DFIR workflow.

---

## Policy Version Discipline

Per attempt-1 lesson 3 (`WDAC-Lessons-Learned-Attempt-1.md`): policy version 10.0.5.1 worked but 10.0.5.3 failed without clear root cause. Always:

- Diff the old and new policy XML before deploying a new version.
- Capture the diff in the version changelog.
- Don't bump the version unless something actually changed.
