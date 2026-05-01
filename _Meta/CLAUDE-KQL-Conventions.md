---
title: Claude KQL Conventions
date_created: 2026-04-28
last_updated: 2026-04-28
tags:
  - "#resource"
  - "#detection"
  - "#status/active"
icon: LiDatabase
---

# KQL Conventions & Schema Reference

> Environment-specific KQL knowledge consolidated from validated queries. Updated as new schema issues are discovered. Reference this when building or validating queries.

---

## Schema Contexts — Always Specify

| Context | Where Used | Tables |
|---------|-----------|--------|
| **Advanced Hunting (MDE)** | MDE portal, Microsoft 365 Defender | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents`, `DeviceRegistryEvents`, `CloudAppEvents`, `EmailEvents` |
| **Log Analytics (Sentinel)** | Microsoft Sentinel workspace | `SecurityEvent`, `AuditLogs`, `SigninLogs`, `AADServicePrincipalSignInLogs`, `OfficeActivity`, `CommonSecurityLog` |

Queries written for one context **do not automatically work in the other**. Always label which schema a query targets.

---

## Known Column Gotchas

### DeviceNetworkEvents
| Column | Status | Notes |
|--------|--------|-------|
| `RemoteIP` | ✅ Confirmed | Standard remote IP field |
| `RemoteIPAddress` | ⚠️ Flag for validation | Name varies across environments — prefer `RemoteIP` |
| `RemoteIPType` | ⚠️ Flag for validation | May not exist in all tenants — always add to validated columns checklist |
| `LocalIP` | ✅ Confirmed | |
| `RemotePort` | ✅ Confirmed | |
| `InitiatingProcessFileName` | ✅ Confirmed | |

### DeviceProcessEvents
| Column | Status | Notes |
|--------|--------|-------|
| `ProcessCommandLine` | ✅ Confirmed | Full command line including args |
| `InitiatingProcessFileName` | ✅ Confirmed | Parent process name |
| `InitiatingProcessCommandLine` | ✅ Confirmed | Parent process full command line |
| `InitiatingProcessParentFileName` | ✅ Confirmed | Grandparent — useful for chain detection |
| `SHA1` / `SHA256` | ✅ Confirmed | |
| `AccountName` | ✅ Confirmed | |
| `FolderPath` | ✅ Confirmed | |

### DeviceFileEvents
| Column | Status | Notes |
|--------|--------|-------|
| `FolderPath` | ✅ Confirmed | |
| `FileName` | ✅ Confirmed | |
| `SHA1` / `SHA256` | ✅ Confirmed | |
| `InitiatingProcessFileName` | ✅ Confirmed | |

### DeviceEvents
| Column | Status | Notes |
|--------|--------|-------|
| `AdditionalFields` | ⚠️ Requires `parse_json()` | Always wrap: `parse_json(AdditionalFields).FieldName` — required for WDAC events and many DeviceEvents fields |
| `ActionType` | ✅ Confirmed | Differentiates event subtypes within the table |

### DeviceLogonEvents
| Column | Status | Notes |
|--------|--------|-------|
| `LogonType` | ✅ Confirmed | |
| `RemoteIPType` | ⚠️ Flag for validation | Same caveat as DeviceNetworkEvents |
| `AccountName` | ✅ Confirmed | |
| `IsLocalAdmin` | ✅ Confirmed | |

### SecurityEvent (Log Analytics)
| Column | Status | Notes |
|--------|--------|-------|
| `IpAddress` | ⚠️ Varies | Field availability and naming varies across event IDs — validate per EventID |
| `Account` | ✅ Confirmed | Format: `DOMAIN\username` |
| `SubjectUserName` | ✅ Confirmed | For 4624/4625/4688 etc |
| `ObjectName` | ✅ Confirmed | For 4663 (object access) |
| `AccessMask` | ✅ Confirmed | Hex string — decode inline for readability |

### AuditLogs (Sentinel / Entra ID)
| Column | Status | Notes |
|--------|--------|-------|
| `InitiatedBy` | ✅ Confirmed | Nested — use `tostring(InitiatedBy)` or parse as JSON |
| `TargetResources` | ✅ Confirmed | Array — use `mv-expand` or `tostring()` |
| `AdditionalDetails` | ✅ Confirmed | Array of key/value pairs |
| `OperationName` | ✅ Confirmed | |
| `Result` | ✅ Confirmed | `"success"` / `"failure"` |

### SigninLogs (Sentinel / Entra ID)
| Column | Status | Notes |
|--------|--------|-------|
| `UserPrincipalName` | ✅ Confirmed | |
| `AppId` | ✅ Confirmed | Use for known app ID filtering (e.g. Azure CLI = `04b07795-8ddb-461a-bbee-02f9e1bf7b46`) |
| `DeviceDetail` | ✅ Confirmed | Nested — `DeviceDetail.isCompliant`, `DeviceDetail.isManaged` |
| `ConditionalAccessStatus` | ✅ Confirmed | `"success"`, `"failure"`, `"notApplied"` |
| `AuthenticationRequirement` | ✅ Confirmed | `"multiFactorAuthentication"` / `"singleFactorAuthentication"` |
| `IPAddress` | ✅ Confirmed | |

### AADServicePrincipalSignInLogs
| Column | Status | Notes |
|--------|--------|-------|
| ⚠️ **Table availability** | Confirm connected | Often missed in Sentinel workspace connector setup — verify before using in analytics rules |
| `ServicePrincipalName` | ✅ Confirmed | |
| `AppId` | ✅ Confirmed | |
| `IPAddress` | ✅ Confirmed | |

### CloudAppEvents (MDE / MCAS)
| Column | Status | Notes |
|--------|--------|-------|
| `IsExternalUser` | ⚠️ Flag for validation | Confirm availability in your environment |
| `RawEventData` | ⚠️ Requires `parse_json()` | `parse_json(RawEventData).FieldName` |
| `ActionType` | ✅ Confirmed | |
| `AccountDisplayName` | ✅ Confirmed | |
| `Application` | ✅ Confirmed | |

---

## Known App IDs

| App | App ID |
|-----|--------|
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
| Microsoft Graph Explorer | `de8bc8b5-d9f9-48b1-a8ad-b748da725064` |
| Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |

---

## AccessMask Quick Reference (SecurityEvent 4663)

| Hex | Meaning |
|-----|---------|
| `0x1` | ReadData / ListDirectory |
| `0x2` | WriteData / AddFile |
| `0x4` | AppendData |
| `0x10` | ReadEA |
| `0x20` | WriteEA |
| `0x40` | WriteAttributes |
| `0x80` | ReadAttributes |
| `0x100000` | SYNCHRONIZE |
| `0x10000` | DELETE |
| `0x20000` | READ_CONTROL |
| `0x40000` | WRITE_DAC |

---

## Sentinel Analytics Rule Defaults

Use these as a starting baseline — adjust based on detection fidelity:

| Severity | Frequency | Lookback | Use For |
|----------|-----------|----------|---------|
| High | 5 min | 5 min | Confirmed malicious behaviour, very low FP rate |
| Medium | 15 min | 1 hour | Suspicious behaviour requiring triage |
| Low | 1 hour | 24 hours | Hunting-grade, baselining, high-noise detections |
| Informational | 1 hour | 24 hours | Audit, compliance, visibility queries |

---

## Standard Exclusions

Apply these in most endpoint detection queries unless the scenario specifically targets these accounts:

```kql
| where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where AccountName !endswith "$"  // exclude machine accounts
```

For process-based queries, common legitimate noise sources:
```kql
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe",      // Defender
    "SenseIR.exe",      // MDE IR
    "SenseCncProxy.exe" // MDE
)
```

---

## parse_json() Pattern Reference

```kql
// DeviceEvents — AdditionalFields
| extend PolicyName = parse_json(AdditionalFields).PolicyName
| extend FileName = parse_json(AdditionalFields).FileName

// AuditLogs — InitiatedBy
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)

// AuditLogs — TargetResources (array)
| mv-expand TargetResources
| extend TargetName = tostring(TargetResources.displayName)
| extend ModifiedProps = TargetResources.modifiedProperties

// CloudAppEvents — RawEventData
| extend OAuthAppId = tostring(parse_json(RawEventData).AppId)
```

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created — consolidated from KQL notes and session history |
