# Runbook — AppControl Manager Install

**Purpose:** Install AppControl Manager on a security analyst workstation. Replaces the legacy WDAC Wizard.
**Author of tool:** HotCakeX (Violet Hansen)
**Wiki:** [AppControl Manager Wiki](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager)

---

## Recommended — Install from Microsoft Store

1. Open Microsoft Store.
2. Search for **AppControl Manager**.
3. Install.
4. Launch — confirm it appears in Start menu.

The Store install handles auto-updates and avoids the elevated/non-elevated install issue from attempt 1.

---

## Fallback — Sideload MSIX (if Store unavailable)

> **Attempt-1 gotcha:** Install via elevated PowerShell appeared to succeed but app didn't show in Start menu. Had to uninstall as elevated, then reinstall as a regular user. Use Store install instead unless absolutely required.

```powershell
Add-AppxPackage -Path "Path\To\YourFile.msix"
```

If installed via elevated session and the app is missing from Start menu:

```powershell
# Remove
Get-AppxPackage -name "AppControlManager*" | Remove-AppxPackage
# Then reinstall in a non-elevated PowerShell session
```

---

## Confirm Installed

```powershell
Get-AppxPackage | Where-Object { $_.Name -like "*AppControl*" }
```

---

## Uninstall Legacy WDAC Wizard

The legacy Wizard should be removed from any workstation before Phase 1 work, to avoid the dual-tool confusion from attempt 1.

```powershell
Get-AppxPackage -name "Microsoft.WDAC.WDACWizard" | Remove-AppxPackage
```

> **Exception:** Keep the Wizard available on one analyst workstation as a documented fallback until the audit→enforce switch is confirmed working in AppControl Manager. See `WDAC-Switch-Audit-To-Enforce.md`.

---

## First-Run Configuration

After install, configure the Intune integration:

1. Sign in with an account that has the required Graph permissions:
   - `Group.Read.All`
   - `DeviceManagementConfiguration.ReadWrite.All`
2. Configure MDE Advanced Hunting integration (sign in with MDE-permitted account).
3. Test: pull a small audit query from MDE to confirm integration works.
