# WDAC — Lessons Learned from Attempt 1

> **Read this before Phase 2.** These are the things that bit us in the first attempt and need to be addressed in attempt 2.

---

## 1. Audit-mode testing was inadequate

**What happened:** Felix and Stephen tested in audit mode but missed several blocks that only surfaced once the policy was switched to enforce mode. New errors kept appearing in production-like testing (e.g. `OPOSSigCap.ocx` block on the POS test device, then more blocks after that).

**Root cause:** Conversation with Felix confirmed the cardlock team's testing approach is "make sure the lights come on" — they don't exercise the full app workflow.

**Action for attempt 2:**
- Identify the actual heavy-testers per business unit before audit period starts. Per Felix, **Diane Wesley** and **Michelle Tiery** (?) do the substantive testing on cardlock — confirm spelling and engage them directly.
- Define what "exercised" means per app — log in, run a transaction, print a receipt, run a card swipe, run end-of-day, etc. Not just "did the app open".
- Set a minimum audit-mode soak period per ring before enforce switch. Suggest 14 days minimum, longer for POS (Phase 4).
- Track exercised vs unexercised paths in `02-Testing-Validation.md`.

---

## 2. Switching from audit to enforce mode in AppControl Manager failed

**What happened:** Couldn't switch the test policy from audit to enforce using AppControl Manager. Had to fall back to the WDAC Wizard to make the switch.

**Status:** Unclear if this was a bug in the AppControl Manager version at the time, a permission issue, or a workflow misunderstanding. AppControl Manager auto-updates from Microsoft Store, so retest in attempt 2.

**Action for attempt 2:**
- Retest the audit→enforce switch in AppControl Manager on the current version before Ring 0 deployment.
- If it still fails, log a GitHub issue against `HotCakeX/Harden-Windows-Security` and document the workaround in `WDAC-Switch-Audit-To-Enforce.md`.

---

## 3. Policy version 10.0.5.1 worked, 10.0.5.3 did not

**What happened:** Same base policy, two different version numbers, different behaviour. 10.0.5.1 deployed and enforced cleanly. 10.0.5.3 failed.

**Status:** Root cause was never confirmed in attempt 1. Settings difference between the two versions was noted but not captured in detail.

**Action for attempt 2:**
- Diff every policy version before deployment using AppControl Manager's policy editor.
- Capture full policy XML for every version in source control or `01-Policy-Design.md`.
- Don't increment the version unless something changed, and document what changed.

---

## 4. AppControl Manager install was finicky

**What happened:** Install via elevated PowerShell appeared to succeed but the app didn't appear in the Start menu. Had to uninstall as elevated, then reinstall as a regular user for it to actually work.

**Action for attempt 2:**
- Install from the Microsoft Store (now the recommended method per project instructions) rather than sideloading the MSIX. This avoids the elevated/non-elevated context issue.
- See `WDAC-AppControl-Manager-Install.md` for current procedure.

---

## 5. Intune Management Extension as Managed Installer failed on test device

**What happened:** Managed Installer policy for Intune Management Extension failed on the test device. Reboot did not resolve. Issue was unresolved when notes were taken (March 19).

**Action for attempt 2:**
- Test Managed Installer config on a clean device in Phase 2 before deploying to Ring 0.
- Capture the specific failure (event ID, error code) and search HotCakeX wiki + GitHub issues — this is a known-tricky area.

---

## 6. Switching from WDAC Wizard to AppControl Manager mid-project caused confusion

**What happened:** Started with WDAC Wizard, switched to AppControl Manager partway through. Mixed workflows, mixed documentation.

**Action for attempt 2:**
- AppControl Manager is the only sanctioned tool going forward, per project instructions.
- WDAC Wizard usage retained only as a documented fallback (e.g. for the audit→enforce switch above, until verified fixed).
- Uninstall the Wizard from any test devices before starting attempt 2: `Get-AppxPackage -name "Microsoft.WDAC.WDACWizard" | Remove-AppxPackage`

---

## 7. Unexpected devices appearing in audit data

**What happened:** Expected only `ps10004.ad.corp.local` to be in audit data. Saw additional devices including `lt13019` (not domain joined). Source of the policy on those devices was never fully traced.

**Action for attempt 2:**
- Tag every test deployment in Intune with a clear assignment group — never deploy by "All Devices" filter.
- Validate group membership in Intune *and* in MDE Advanced Hunting before assuming a deployment is scoped correctly.
- The `KQL-AppControl-Activity-Summary.md` query is the right starting point for sanity-checking scope.

---

## 8. SiPolicy.p7b conversion is not needed for Intune deployment

**Confirmed during attempt 1:** The `ConvertFrom-CIPolicy` cmdlet to produce `SiPolicy.p7b` is only needed when deploying via PowerShell script, not via Intune. Intune handles the binary conversion.

**Reference command (kept for non-Intune scenarios only):**
```powershell
ConvertFrom-CIPolicy -xmlFilePath .\AllowMicrosoft2026-02-20.xml -BinaryFilePath .\SiPolicy.p7b
```

The note that "the SiPolicy.p7b file is only used if you have a single policy" — this matches Microsoft guidance that `SiPolicy.p7b` is the legacy single-policy format. Multiple-policy environments use `{PolicyGUID}.cip` files in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`.

---

## 9. Removing a stuck policy required CITool

**What happened:** Got stuck during testing — only resolution was manual removal via CITool.

```powershell
CiTool.exe --list-policies
CiTool.exe --remove-policy "{policy-guid}" -json
```

This is now documented in `WDAC-Policy-Management-Commands.md` and forms the basis of the rollback runbook (`WDAC-Rollback-Procedure.md`).

---

## 10. Open question — `hvsimgr.exe` / Defender Application Guard

**What happened:** Investigated `hvsimgr.exe` references during attempt 1. Hunt for execution events returned nothing. No evidence Application Guard is actually running in the environment.

**Action for attempt 2:** Likely a non-issue, but worth re-running the hunt before declaring the environment clean. Query is in `KQL-Device-Scoped-AppControl.md` adjacent notes.

---

## Summary — Top 3 things to do differently in attempt 2

1. **Get the right testers involved early.** Identify and engage actual app power-users (not just the cardlock team's pass-through testers) before audit mode starts.
2. **Lock down policy versioning.** Diff every version, document what changed, never bump the version "just because".
3. **Verify the audit→enforce switch in AppControl Manager works** before committing to it as the only tool. Keep the Wizard available as a fallback until confirmed.
