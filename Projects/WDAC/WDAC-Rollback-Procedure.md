# Runbook — Remote Rollback via Intune

**Purpose:** Roll back a WDAC policy on affected devices remotely, without on-site IT.
**Trigger:** Enforced policy is blocking legitimate apps and supplemental fix is not viable in time.
**Method:** Intune-deployed unsigned supplemental policy + CITool execution on next sync.

---

## When to Use This

Use this runbook when:

- An enforced policy is causing user-blocking issues that can't wait for a supplemental update.
- A POS terminal is failing to process transactions (see `04-POS-Rollout.md` rollback decision tree).
- A pilot ring deployment is misbehaving and the soak period needs to abort.

Do NOT use this for:

- Routine policy updates — use a supplemental policy update instead.
- Recovery on a single test device — use the manual `CiTool.exe --remove-policy` from `WDAC-Policy-Management-Commands.md`.

---

## Pre-Requisites

- AppControl Manager available with Intune integration configured.
- Identified device group affected.
- Intune permissions: `Group.Read.All`, `DeviceManagementConfiguration.ReadWrite.All`.

---

## Procedure

### 1. Build Unsigned Supplemental Policy

In AppControl Manager:

1. Open the base policy that needs rolling back.
2. Create an unsigned supplemental policy that disables enforcement (or removes the offending base policy effect).
3. Save and name with a clear identifier — e.g. `Rollback-Ring0-2026-05-06`.

### 2. Deploy via Intune

Either via AppControl Manager's native Intune deployment (preferred), or:

1. Export the policy XML.
2. Create a new Intune device configuration profile (Custom — OMA-URI for App Control).
3. Assign to the affected device group.

### 3. Force Sync

For urgent rollbacks, instruct affected users to manually sync:

- **Settings → Accounts → Access work or school → Connect → Info → Sync**

Or trigger remote sync from Intune admin console.

`CiTool.exe /Update` runs on next Intune sync and applies the new policy.

### 4. Confirm Rollback on Device

Use Live Response or remote PowerShell:

```powershell
# Confirm the new policy is present
CiTool.exe --list-policies

# Check Code Integrity event log for recent state changes
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 20 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message
```

### 5. Verify in MDE Advanced Hunting

Run `KQL-Enforced-Mode-Blocks.md` filtered to the affected devices. Confirm no new `AppControlCodeIntegrityPolicyBlocked` events after the rollback timestamp.

```kql
DeviceEvents
| where DeviceName in ("device1", "device2")
| where ActionType == "AppControlCodeIntegrityPolicyBlocked"
| where Timestamp > datetime(2026-05-06T14:00:00Z)  // rollback time
| order by Timestamp desc
```

---

## Post-Rollback

- [ ] Document the failure mode that triggered rollback.
- [ ] Update compatibility tracker in `02-Testing-Validation.md`.
- [ ] Build a corrected supplemental policy before re-attempting the deployment.
- [ ] Add to `WDAC-Lessons-Learned-Attempt-1.md` (or a new lessons-learned doc) if root cause is novel.

---

## Manual Fallback (Last Resort)

If Intune sync isn't reaching the device, fall back to direct CITool removal via Live Response:

```powershell
CiTool.exe --list-policies
CiTool.exe --remove-policy "{policy-guid}" -json
```

This requires Live Response access in MDE. See `WDAC-Policy-Management-Commands.md`.
