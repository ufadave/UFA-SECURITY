# Phase 1 — Policy Design & Creation

**Status:** 🟡 In Progress
**Owner:** Security
**Tooling:** AppControl Manager (primary), WDAC Wizard (fallback only)

---

## Objectives

1. Stand up AppControl Manager on the security analyst workstation.
2. Decide on the base policy template and supplemental structure.
3. Build the base policy and Ring 0 supplemental.
4. Document the policy version control and review process.

---

## Base Policy Decision

Per project instructions, the recommended base is **Allow Microsoft**. Supplementals layer on per-ring business apps.

| Template | Allows | ISG Needed | Best For |
|----------|--------|-----------|---------|
| Allow Microsoft | Microsoft-signed files only | No | General fleet, POS |
| Default Windows | Windows built-in only | No | Strictest — test/lab only |
| Signed and Reputable | Microsoft + ISG-trusted | Yes (internet) | Flexible general use |

**Decision:** Allow Microsoft as base for all rings. POS gets a stricter supplemental than general fleet.

### Important caveat — Smart App Control example policy

> When using the Smart App Control example policy as the basis for your own custom policy, you must remove the option `Enabled:Conditional Windows Lockdown Policy` so it's ready for use as an App Control for Business policy.
>
> *Source: [Microsoft Learn — App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)*

---

## Policy Architecture

### File Rule Precedence

App Control evaluates rules in this order:

1. Explicit deny rules
2. Explicit allow rules
3. Managed Installer claim (if enabled by policy)
4. ISG fallback (if enabled by policy)

> **Microsoft recommendation:** Maintain separate ALLOW and DENY policies on Windows versions that support multiple App Control policies, to make policies easier to reason over.
>
> *Source: [select-types-of-rules-to-create](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)*

### Ring Structure

| Ring | Scope | Policy |
|------|-------|--------|
| Ring 0 | IT/Security team devices | Base + Ring 0 supplemental |
| Ring 1 | Early adopter volunteers | Base + Ring 1 supplemental |
| Ring 2 | General fleet | Base + Ring 2 supplemental |
| Ring 3 | POS terminals | Base + POS supplemental (strict) |

### Active Policy Location on Endpoint

```
C:\Windows\System32\CodeIntegrity\CiPolicies\Active\
```

Filenames correspond to policy GUIDs (`{GUID}.cip` format for multi-policy environments).

### Deployment Note

`SiPolicy.p7b` conversion is **not** required for Intune-based deployment — Intune handles binary conversion. See lessons learned for context.

---

## Software Inventory

> **Action item:** Build software inventory per ring before generating supplemental policies. AppControl Manager can generate supplementals from MDE Advanced Hunting audit logs, so the workflow is:
>
> 1. Deploy base in audit mode to ring devices.
> 2. Let users exercise apps.
> 3. Pull audit events via MDE AH.
> 4. Feed into AppControl Manager.
> 5. Generate supplemental.

Inventory tracker per ring goes in `02-Testing-Validation.md`.

---

## Policy Version Control

Per attempt-1 lessons, version control is critical. Process:

1. Every policy version gets its full XML committed (location TBD — Git, Obsidian, or shared drive).
2. Bump version only when something actually changed.
3. Diff between versions documented in a changelog (in this note, table below).
4. Use AppControl Manager's policy editor to review changes before deploying.

### Policy Version Changelog

| Policy | Version | Date | Change | Deployed To |
|--------|---------|------|--------|-------------|
| _(to be populated as policies are created)_ | | | | |

---

## AppControl Manager Setup

See `WDAC-AppControl-Manager-Install.md` for install procedure.

### Required Intune Permissions

- `Group.Read.All`
- `DeviceManagementConfiguration.ReadWrite.All`

### Key Capabilities to Use

- GUI-based base + supplemental policy creation
- Audit log scanning + supplemental policy generation from logs
- Native Intune integration — direct deployment to Intune device groups
- MDE Advanced Hunting integration — bulk audit log collection at fleet scale
- Managed Installer — auto-allow apps deployed via Intune (test carefully — failed in attempt 1)
- Policy signing, merging, editing

---

## Open Questions / To Resolve in Phase 1

- [ ] Confirm AppControl Manager audit→enforce switch works in current version (attempt-1 blocker).
- [ ] Confirm Managed Installer policy works for Intune Management Extension (attempt-1 blocker).
- [ ] Decide policy version XML storage location.
- [ ] Confirm spelling and engage Diane Wesley + Michelle Tiery as cardlock test leads.
- [ ] Re-run `hvsimgr.exe` execution hunt to confirm Application Guard isn't a factor.
