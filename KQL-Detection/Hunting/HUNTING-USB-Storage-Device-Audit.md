---
date: 2026-06-09
title: USB Storage Device Audit
analyst: Dave
table: "DeviceEvents"
schema: "Advanced Hunting (MDE)"
mitre: "T1052.001"
tactic: "Exfiltration"
technique: "Exfiltration Over Physical Medium: Exfiltration over USB"
saved_in: ""
query_name: ""
status: "Draft"
tags:
  - "#detection/hunting"
  - "#status/draft"
  - "#endpoint"
  - "#hunt"
---

# HUNTING — USB Storage Device Audit

---

## Hypothesis

> USB storage devices represent an unmonitored data exfiltration and malware introduction
> vector across the ~150 endpoint estate. This hunt establishes a baseline of all writable
> USB storage devices connected to managed endpoints, identifies users and devices with
> elevated USB activity, and surfaces any high-risk or unknown devices for follow-up.
> Findings will inform whether a formal USB device control policy (Intune Device Control)
> is warranted.

---

## Scope

- **Table:** `DeviceEvents`
- **Schema:** Advanced Hunting (MDE)
- **Lookback:** Up to 180 days (E5 retention limit)
- **Devices:** All managed endpoints (~150 Windows endpoints + POS terminals)
- **Exclusions:** Optical drives (DVD/CD-ROM), virtual drives, VMware virtual devices

---

## Query

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "UsbDriveMounted"
| extend DiskSize = tostring(parse_json(AdditionalFields).DiskSize)
| extend Manufacturer = tostring(parse_json(AdditionalFields).Manufacturer)
| extend ProductName = tostring(parse_json(AdditionalFields).ProductName)
| extend SerialNumber = tostring(parse_json(AdditionalFields).SerialNumber)
// Exclude read-only optical drives and virtual devices
| where ProductName !has_any (
    "DVD", "CD-ROM", "CD/ROM", "CDR", "Virtual",
    "Msft Virtual", "VMware"
)
| where Manufacturer !has_any ("Msft", "NECVMWar", "hp HLDS")
| project
    Timestamp,
    DeviceName,
    AccountName,
    Manufacturer,
    ProductName,
    SerialNumber,
    DiskSize,
    FolderPath
| order by Timestamp desc
```

---

## Extended Lookback (>30 days)

To query beyond the Advanced Hunting UI default of 30 days, set a custom time range
in the portal and adjust the `Timestamp` filter accordingly. E5 retention supports up
to 180 days:

```kql
// Replace ago(30d) with a specific window for extended lookback
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-06-09))
```

**Note:** `DeviceEvents` is high-volume. For extended windows across all endpoints,
consider filtering by `DeviceName` or `AccountName` to avoid query timeouts.

---

## Saved Query

- **Saved In:** <!-- Advanced Hunting — Shared Queries -->
- **Query Name:** <!-- USB Storage Device Audit -->

---

## Validated Columns

- [ ] `ActionType == "UsbDriveMounted"` — confirm generates events in this tenant
- [ ] `parse_json(AdditionalFields).ProductName` — confirmed populated from tenant CSV (5,147 events)
- [ ] `parse_json(AdditionalFields).Manufacturer` — confirmed populated
- [ ] `parse_json(AdditionalFields).SerialNumber` — confirmed populated (use for allowlist)
- [ ] `parse_json(AdditionalFields).DiskSize` — confirmed populated

**Schema notes from tenant validation (2026-06-09, 5,147 events):**
- `MassStorageClass` from `Generic` manufacturer is ambiguous — can be a flash drive or
  card reader. Leave in and triage manually, or add:
  `| where not(ProductName == "MassStorageClass" and Manufacturer has "Generic")`
- Top writable devices seen: USB DISK 2.0, USB Flash Drive, DataTraveler 3.0,
  Micro SD/M2, SD/MMC, STORE N GO, Verbatim, Lexar, Kingston, Seagate
- Optical drive noise removed by ProductName and Manufacturer filter (~4,100 of 5,147 rows)

---

## Findings

| Date | Device | User | Manufacturer | Product | Serial | Notes |
|------|--------|------|--------------|---------|--------|-------|
| | | | | | | |

---

## Promote to Detection?

Retain as a hunting/audit query. If specific high-risk devices or users are identified,
consider promoting to an MDE Custom Detection rule targeting specific `SerialNumber`
values not on an approved allowlist, or evaluate Intune Device Control policy for USB
block/allow enforcement.

---

## Related Notes

- [[HARD-BitLocker-MinPIN]] — related endpoint hardening
- [[FIND-VSCode-Remote-Tunnels-Active-No-Policy-Control-2026-05-12]] — adjacent unmanaged tool risk

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-09 | Created — USB storage audit query; optical drive noise filtered via ProductName/Manufacturer exclusions; schema validated against 5,147-row tenant result set |
