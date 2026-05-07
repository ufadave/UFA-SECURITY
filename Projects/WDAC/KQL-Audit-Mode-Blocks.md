# KQL — Audit Mode Blocks

**Purpose:** List all `AppControlCodeIntegrityPolicyAudited` events with file detail. Primary feed for building supplemental policies.
**Source:** MDE Advanced Hunting (`DeviceEvents`)
**Use case:** Phase 2. Run during audit period, export to CSV, feed into AppControl Manager to generate supplemental policy.

---

## ⚠️ Schema Validation Required

Before relying on results:

- Confirm `ActionType == "AppControlCodeIntegrityPolicyAudited"` is the current ActionType name (Microsoft has renamed in the past).
- Confirm the keys in `AdditionalFields` JSON still include `SHA256`, `Publisher`, `PolicyName`. Validate by running:
  ```kql
  DeviceEvents
  | where ActionType == "AppControlCodeIntegrityPolicyAudited"
  | take 1
  | extend P = parse_json(AdditionalFields)
  | project AdditionalFields, P
  ```

---

## Query

```kql
DeviceEvents
| where ActionType == "AppControlCodeIntegrityPolicyAudited"
| extend ParsedFields = parse_json(AdditionalFields)
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    PolicyName = tostring(ParsedFields.PolicyName),
    InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Variations

### Filtered to a single ring (by device group)

Adjust the device list to match Intune ring assignment:

```kql
let RingDevices = dynamic(["device1", "device2", "device3"]);
DeviceEvents
| where ActionType == "AppControlCodeIntegrityPolicyAudited"
| where DeviceName in (RingDevices)
| extend ParsedFields = parse_json(AdditionalFields)
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    PolicyName = tostring(ParsedFields.PolicyName),
    InitiatingProcessFileName
| order by TimeGenerated desc
```

### Top blocked files (build target list for supplemental)

```kql
DeviceEvents
| where ActionType == "AppControlCodeIntegrityPolicyAudited"
| where Timestamp > ago(7d)
| extend ParsedFields = parse_json(AdditionalFields)
| summarize
    BlockCount = count(),
    DistinctDevices = dcount(DeviceName),
    Publisher = any(tostring(ParsedFields.Publisher)),
    SHA256 = any(tostring(ParsedFields.SHA256))
  by FileName, FolderPath
| order by BlockCount desc
```

---

## Workflow — Feed into AppControl Manager

1. Run the main query above (or filtered variant).
2. Export results as CSV.
3. Open AppControl Manager → audit log scanning workflow.
4. Import the CSV.
5. Review the parsed file list, select files to allow.
6. Generate supplemental policy.
7. Deploy via AppControl Manager's Intune integration.
