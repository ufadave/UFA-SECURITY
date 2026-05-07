# KQL — SiPolicy.p7b File Creation

**Purpose:** Track creation of `SiPolicy.p7b` (and policy `.cip` files) on endpoints. Validates that policy deployment actually landed.
**Source:** MDE Advanced Hunting (`DeviceFileEvents`)
**Use case:** Phase 1/2 deployment validation. Used in attempt 1 to debug a deployment that wasn't applying.

---

## ⚠️ Schema + Context Notes

- `SiPolicy.p7b` is the **legacy single-policy** filename. Multi-policy environments (the project's setup) deploy `{PolicyGUID}.cip` files into `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`.
- This query is most useful as a sanity check that *some* policy file write occurred on the device after Intune sync.
- If a deployment succeeded in Intune but no file event appears here, the policy didn't reach the device.

---

## Query — SiPolicy.p7b creation (legacy / single-policy)

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName =~ 'SiPolicy.p7b'
| where ActionType == 'FileCreated'
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

## Query — Multi-policy `.cip` file creation (current project)

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has @"\System32\CodeIntegrity\CiPolicies\Active"
| where ActionType == 'FileCreated'
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Variations

### Scoped to a specific device

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where DeviceName =~ 'ps10004.ad.corp.local'
| where FolderPath has @"\System32\CodeIntegrity\CiPolicies\Active"
| where ActionType == 'FileCreated'
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

### Confirm policy update via specific GUID

```kql
let TargetPolicyGUID = "{D62668AE-5BD7-4A22-A2CA-B6BDE57F48DC}";  // example from attempt 1
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName has TargetPolicyGUID
| where ActionType == 'FileCreated'
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Expected Initiating Processes

Legitimate WDAC policy file creation should be initiated by:

- `tiworker.exe` — Windows Modules Installer Worker
- `setuphost.exe` — Setup host process
- `dismhost.exe` — DISM host
- `IntuneManagementExtension.exe` — for Intune-deployed policies

Anything else writing to this folder is suspicious and warrants investigation.

---

## Attempt-1 Note

In attempt 1, this query was used to debug why a deployment to `ps10004.ad.corp.local` wasn't applying — no file creation event was seen for that device, despite Intune showing the deployment as successful. Resolution required a reboot. If a similar pattern appears in attempt 2, capture the device's `IntuneManagementExtension.log` for root cause.
