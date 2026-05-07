# KQL — Device-Scoped AppControl Events

**Purpose:** Pull all AppControl events for a single device. Used during testing and triage.
**Source:** MDE Advanced Hunting (`DeviceEvents`)
**Use case:** Investigating a specific test device or a reported issue on a single endpoint.

---

## ⚠️ Schema Validation Required

Same caveats as other AppControl KQL — validate `ActionType` naming family hasn't changed.

---

## Query

```kql
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited"
| where DeviceName == "ps10004.ad.corp.local"  // change to target device
| order by Timestamp desc
```

---

## Variations

### Last hour only (during active testing)

```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited"
| where DeviceName == "device-under-test"
| order by Timestamp desc
```

### With parsed AdditionalFields for full file context

```kql
DeviceEvents
| where DeviceName == "device-under-test"
| where ActionType startswith "AppControl"
| extend ParsedFields = parse_json(AdditionalFields)
| project
    Timestamp,
    ActionType,
    FileName,
    FolderPath,
    SHA256 = tostring(ParsedFields.SHA256),
    Publisher = tostring(ParsedFields.Publisher),
    PolicyName = tostring(ParsedFields.PolicyName),
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Adjacent Hunt — Application Guard Check

Attempt-1 open question — confirm `hvsimgr.exe` (Microsoft Defender Application Guard Manager) is not running in the environment:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ 'hvsimgr.exe'
```

Expected result: empty. If results appear, Application Guard is active and may interact with WDAC policy in unexpected ways — investigate before continuing.
