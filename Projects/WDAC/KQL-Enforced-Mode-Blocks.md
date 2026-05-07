# KQL — Enforced Mode Blocks

**Purpose:** List all `AppControlCodeIntegrityPolicyBlocked` events. These are real blocks — files that were prevented from running.
**Source:** MDE Advanced Hunting (`DeviceEvents`)
**Use case:** Phase 3 + Phase 4. Daily check during enforce-mode soak. Triggers rollback decisions.

---

## ⚠️ Schema Validation Required

Before relying on results:

- Confirm `ActionType == "AppControlCodeIntegrityPolicyBlocked"` is the current ActionType name.
- Confirm `AdditionalFields` JSON keys (`SHA256`, `Publisher`) parse correctly.
- Run the same validation snippet from `KQL-Audit-Mode-Blocks.md`.

---

## Query

```kql
DeviceEvents
| where ActionType == "AppControlCodeIntegrityPolicyBlocked"
| extend ParsedFields = parse_json(AdditionalFields)
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Variations

### Last 24 hours, scoped to a ring

```kql
let RingDevices = dynamic(["device1", "device2", "device3"]);
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "AppControlCodeIntegrityPolicyBlocked"
| where DeviceName in (RingDevices)
| extend ParsedFields = parse_json(AdditionalFields)
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    InitiatingProcessFileName
| order by TimeGenerated desc
```

### POS-specific (Phase 4 daily check)

```kql
let POSDevices = dynamic(["pos-site1-01", "pos-site1-02"]);  // populate per site
DeviceEvents
| where Timestamp > ago(4h)  // post-deployment window
| where ActionType == "AppControlCodeIntegrityPolicyBlocked"
| where DeviceName in (POSDevices)
| extend ParsedFields = parse_json(AdditionalFields)
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    InitiatingProcessFileName
| order by TimeGenerated desc
```

### Combined audit + enforce script blocks (broader hunt)

Useful for catching script-level blocks alongside file-level. Pulled from attempt-1 troubleshooting.

```kql
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited"
| where DeviceName == "ps10004.ad.corp.local"  // adjust per investigation
| order by Timestamp desc
```

---

## Block Triage

For each block:

1. Identify the file (FileName, FolderPath, SHA256, Publisher).
2. Decide:
   - **Legitimate** → add to supplemental policy, redeploy.
   - **Unknown / suspicious** → DFIR workflow. Treat as potential malicious execution attempt that the policy successfully blocked.
3. If legitimate and time-critical, consider rollback (`WDAC-Rollback-Procedure.md`) while the supplemental update is built.

---

## Attempt-1 Reference Block

`OPOSSigCap.ocx` was a known false-positive enforce block in attempt 1 — added to the POS supplemental. Cross-check this file is in the current POS supplemental before Phase 4.
