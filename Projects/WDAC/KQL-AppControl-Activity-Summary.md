# KQL — AppControl Activity Summary

**Purpose:** Summarise AppControl ActionTypes across the fleet — sanity-check that policy is hitting the expected devices and only the expected devices.
**Source:** MDE Advanced Hunting (`DeviceEvents`)
**Use case:** First query to run after deploying any policy. Confirms scope before drilling into specific blocks.

---

## ⚠️ Schema Validation Required

Before relying on results, validate:

- `DeviceEvents` table is accessible in the current MDE AH workspace.
- `ActionType` values still include the `AppControl*` family (Microsoft has renamed these in the past).
- If a query returns zero results unexpectedly, run `DeviceEvents | where ActionType startswith "AppControl" | distinct ActionType | take 50` to confirm current naming.

---

## Query

```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType startswith "AppControl"
| summarize Machines = dcount(DeviceName) by ActionType
| order by Machines desc
```

---

## Variations

### 30-day window

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "AppControl"
| summarize Machines = dcount(DeviceName) by ActionType
| order by Machines desc
```

### Devices summary (which devices, which ActionType)

```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType startswith "AppControl"
| summarize EventCount = count() by DeviceName, ActionType
| order by EventCount desc
```

---

## Attempt-1 Context

This query exposed the issue in attempt 1 where the policy was hitting unexpected devices (not just the test machine `ps10004.ad.corp.local` — also `lt13019` which wasn't even domain joined). Use it the same way: validate that the device count and identity match what was deployed in Intune.
