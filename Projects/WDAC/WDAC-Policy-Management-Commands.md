cmd
# Runbook — Policy Management Commands

**Purpose:** PowerShell + CITool reference for common WDAC policy operations on an endpoint.
**Audience:** Analyst running these locally or via Live Response in MDE.

---

## List Active Policies on a Device

```powershell
CiTool.exe --list-policies
```

Returns all policies installed on the device with attributes including PolicyID, Name, Version, Mode, and Enforcement state.

For JSON output (parseable):

```powershell
CiTool.exe --list-policies -json
```

### Active Policy File Location

	```
C:\Windows\System32\CodeIntegrity\CiPolicies\Active\
```

Files are named `{PolicyGUID}.cip` for multi-policy environments, or `SiPolicy.p7b` for legacy single-policy.

---

## Remove a Policy

> Used during attempt 1 to recover from a stuck test policy. This is the manual fallback when Intune-based removal isn't working.

```powershell
# 1. List to find the policy GUID
CiTool.exe --list-policies

# 2. Remove
CiTool.exe --remove-policy "{policy-guid}" -json
```

For the **standard remote rollback procedure**, use `WDAC-Rollback-Procedure.md` instead — that uses an Intune-deployed unsigned supplemental rather than direct CITool.

---

## Check WDAC State via WMI

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CI_State
```

Returns the current Code Integrity policy state (audit vs enforce, signed vs unsigned, UMCI status, etc).

---

## Check for AppLocker Policies

Useful for clean-state validation — confirm no legacy AppLocker policy is interfering before deploying WDAC.

```powershell
Get-AppLockerPolicy -Effective -Xml
```

---

## Convert XML to Binary (NON-Intune Deployments Only)

Not needed for Intune deployment — Intune handles this. Kept here as reference only.

```powershell
ConvertFrom-CIPolicy -xmlFilePath .\AllowMicrosoft2026-02-20.xml -BinaryFilePath .\SiPolicy.p7b
```

---

## Quick Triage Block — Run on a Suspected Misbehaving Device

```powershell
# Active policies
CiTool.exe --list-policies

# CI state
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CI_State

# Active policy files on disk
Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\"

# Recent CodeIntegrity events (last hour)
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 50 |
  Where-Object { $_.Id -in 3076, 3077, 3089 } |
  Select-Object TimeCreated, Id, LevelDisplayName, Message
```

| Event ID | Meaning |
|----------|---------|
| 3076 | Audit block (would have been blocked) |
| 3077 | Enforced block (was blocked) |
| 3089 | Signature info for blocked/audited file |
