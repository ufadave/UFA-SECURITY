---
title: BitLocker — Configure Minimum Startup PIN Length
date: 2026-04-28
control-id: HARD-BitLocker-MinPIN
source: Microsoft Defender for Endpoint recommendation
gpo-path: Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives\Configure minimum PIN length for startup
registry-path: HKLM\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN
tags:
  - "#hardening"
  - "#endpoint"
  - "#status/active"
status: active
---

# BitLocker — Configure Minimum Startup PIN Length

## Recommendation Source

Microsoft Defender for Endpoint — Secure Score recommendation  
*"Set 'Minimum PIN length for startup' to 6 or more characters"*

CIS Benchmark: Windows 11 L1 — Recommendation 18.9.11.1.3 (value: 6)  
CIS Benchmark: Windows 11 L2 — Recommendation 18.9.11.1.3 (value: 8)

---

## ⚠️ Scope Warning — Read Before Deploying

> **This policy change does NOT enforce startup PINs on your existing endpoints.**

Your environment currently uses **TPM-only BitLocker unlock**. Applying this policy sets the minimum length requirement for startup PINs — but since no startup PINs are configured, there is nothing to enforce against. Existing devices will continue to boot with TPM-only after this change.

**What this policy actually does:** If a user or admin attempts to configure a BitLocker startup PIN on a device in the future, Windows will reject any PIN shorter than 6 characters.

**What this policy does NOT do:** It does not add a PIN requirement to currently protected TPM-only drives. It does not change the unlock method on any existing device.

**PIN management risk — if startup PINs are ever enabled:**

Without a defined PIN management process, enabling startup PINs at scale introduces real operational risk:

| Scenario | Risk |
|---|---|
| PIN forgotten, recovery key not escrowed | Device unbootable until physical access + 48-digit recovery key retrieved — brick risk at remote sites |
| Support analyst sets device-specific PINs informally | Undocumented per-device secret living in one person's head — no recovery path if they leave |
| Standardised PIN across fleet | Shared secret — compromise of one device compromises the PIN value fleet-wide |
| Startup PIN on remote/headless devices | Device won't boot after reboot without someone physically present to enter PIN — availability risk for servers, OT equipment |

**Prerequisites before enabling startup PINs on any device:**
- All BitLocker recovery keys confirmed escrowed to Entra ID or AD
- PIN management process defined — individual PINs with escrow, or an approved shared standard
- Exception list defined for headless/remote devices that must remain TPM-only
- Helpdesk process documented for PIN-locked device recovery

**To actually require startup PINs** (the real security improvement), a separate policy is required:  
`Require additional authentication at startup → Require startup PIN with TPM`  
This is a significant operational change — all 150+ endpoints would require a PIN entered at every boot. Recovery key/PIN distribution workflow, helpdesk process for locked devices, and remote/headless machine handling (servers, OT endpoints) must be planned before deploying.

>Explain how this pin works, does the user need to enter it every time they start their computer?

Yes, if you enable startup PINs the user has to enter it every single time the machine powers on or reboots — before Windows even starts loading. It's a pre-boot authentication prompt, so it happens at the firmware/bootloader stage, before any Windows login screen.

**How it works mechanically:**

BitLocker with TPM-only works like this today: the TPM chip holds the encryption key and releases it automatically at boot if the system passes integrity checks (bootloader hasn't been tampered with, etc.). The user sees nothing — the drive just decrypts transparently and Windows loads normally.

When you add a startup PIN, you're adding a second factor. The TPM still holds the key, but it will only release it if the correct PIN is also provided. So the boot sequence becomes: power on → black screen with BitLocker PIN prompt → user enters PIN → TPM releases key → Windows loads → normal Windows login screen.

**Practical implications for your environment:**

- **Every reboot requires someone at the keyboard.** Windows Update reboots, patch cycles, unexpected crashes — anything that causes a reboot leaves the machine sitting at the BitLocker PIN screen waiting for human input
- **Remote endpoints are a problem.** If a machine at a remote site, a server room, or the fertilizer plant reboots overnight, it won't come back up until someone physically enters the PIN. RDP and remote management tools won't help because Windows hasn't loaded yet
- **AVD/virtual machines** — startup PINs don't apply in the same way to VMs since there's no physical TPM in the traditional sense; Hyper-V has a virtual TPM but the PIN prompt behaviour depends on the hypervisor configuration
- **POS terminals** — depending on how they're managed, a BitLocker PIN prompt at every boot could be a significant operational disruption
- **OT/SCADA endpoints** — almost certainly need to stay TPM-only; an unattended reboot that leaves a PLC workstation sitting at a PIN screen is an availability risk you don't want near process control equipment

**The security benefit is real but narrow:**

The threat startup PIN actually protects against is physical theft of a powered-off device. Without a PIN, a stolen laptop with TPM-only BitLocker — while still encrypted — is theoretically vulnerable to a cold boot attack or a TPM sniffing attack where an attacker intercepts the key passing between the TPM and CPU on the bus. Adding a PIN means the TPM won't release the key even with physical hardware access, closing that vector.

For a laptop fleet where devices travel and theft is a realistic risk, that's a meaningful control. For fixed workstations, servers, and OT equipment that never leave the building, the operational cost almost certainly outweighs the benefit.

**Bottom line for your environment:** Startup PINs are probably only worth the operational overhead for your laptop/mobile workforce, if you have one. Fixed workstations, servers, AVD, POS, and OT endpoints should stay TPM-only. If you do pursue it, it should be scoped tightly and treated as a separate project — not something that falls out of applying the minimum PIN length policy you're deploying now.

---

## Configuration

### GPO Setting

| Field | Value |
|---|---|
| **Policy path** | `Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives` |
| **Policy name** | Configure minimum PIN length for startup |
| **Setting** | Enabled |
| **Minimum characters** | 6 |

### Registry

| Field | Value |
|---|---|
| **Key** | `HKLM\SOFTWARE\Policies\Microsoft\FVE` |
| **Value name** | `MinimumPIN` |
| **Type** | `DWORD` |
| **Data** | `6` |

### Intune (Settings Catalog)

| Field | Value |
|---|---|
| **Category** | BitLocker |
| **Setting name** | BitLocker — Minimum PIN Length |
| **Value** | 6 |

> If managing BitLocker via Intune endpoint protection profiles, this maps to the **OS drive** BitLocker settings. Confirm the setting is not already defined in an existing profile before creating a new assignment to avoid policy conflict.

---

## Deployment Scope

| Scope | Include |
|---|---|
| Workstations | ✅ Yes |
| Servers | ✅ Yes |
| AVD fleet | ✅ Yes — policy-only, no operational impact |
| OT/SCADA endpoints | ⚠️ Review — confirm BitLocker status on plant assets before applying |
| POS terminals | ⚠️ Review — confirm BitLocker configuration |

---

## Validation

### Confirm GPO is applied
```powershell
# Run on a target endpoint
gpresult /r /scope computer | findstr -i "bitlocker"
```

### Confirm registry value
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN"
# Expected: MinimumPIN = 6
```

### Confirm via manage-bde
```powershell
manage-bde -status C:
# Confirms current unlock method — will still show "TPM Only" after this change
# That is expected — this policy does not change the unlock method
```

---

## Validation Checkboxes

- [ ] GPO created and linked to correct OU
- [ ] Registry value confirmed on test endpoint — `MinimumPIN = 6`
- [ ] Defender Secure Score recommendation cleared (allow 24–48h)
- [ ] OT/SCADA and POS endpoint scope reviewed
- [ ] Confirmed no conflicting Intune BitLocker profile exists
- [ ] No existing startup PINs shorter than 6 characters in environment (check before applying if any PINs exist)

---

## Future Work — Actual Startup PIN Enforcement

If the organisation wants the full security benefit (TPM+PIN unlock):

1. **Assess operational feasibility** — 150+ endpoints all requiring PIN at boot; remote/headless devices need exception handling
2. **Define exceptions** — servers, OT endpoints, headless kiosks, POS terminals likely need to remain TPM-only
3. **Recovery key process** — ensure all recovery keys are escrowed to Entra ID / AD before enforcing
4. **Deploy policy** — `Require additional authentication at startup → Require startup PIN with TPM`
5. **User communication** — affected users need PIN set before policy enforces; staged rollout recommended

Related policy to deploy together:  
`Configure use of passwords for operating system drives` — if PIN enforcement is adopted, also set minimum password complexity for the recovery password.

---

## MITRE ATT&CK

| Technique | Description |
|---|---|
| T1052.001 — Exfiltration over Physical Medium | Startup PIN prevents cold boot / physical theft attacks on unattended devices |
| T1200 — Hardware Additions | Mitigates evil maid attacks against unattended endpoints |

---

## Related Notes

- [[HARD-BitLocker-RequireStartupAuth]] — future control if startup PIN enforcement is adopted
- [[PROJ-M365-Hardening]] — parent project

---

## Tags

`#hardening` `#endpoint` `#status/active`

---

## Changelog

| Date | Author | Change |
|---|---|---|
| 2026-04-28 | Dave | Added PIN management risk table to scope warning — covers forgotten PIN, per-device informal PINs, standardised PIN risk, and headless device availability risk. Prerequisites for safe PIN enforcement documented. |
