---
title: WDAC Phase 1 — Audit & Inventory
status: active
type: project
created: 2026-05-05
phase: 1
project: WDAC-Deployment
---

# WDAC Phase 1 — Audit & Inventory

## Objective

Stand up Phase 1 of the WDAC deployment programme: build an authoritative inventory of binaries and signers running across each endpoint ring, deploy a baseline audit-mode policy via AppControl Manager, and collect 14–30 days of audit telemetry to inform enforcement-mode tuning.

This phase is non-blocking — no enforcement, no end-user impact. The deliverable is a tuned audit-mode policy and a documented gap list before moving to Phase 2 (enforcement on Ring 0).

## Scope

### In scope

- Ring 0 (IT/SecOps): full inventory, AppControl Manager deployment, audit-mode policy
- Ring 1 (corporate office): inventory only this phase
- Reference machine selection (one clean image per ring)
- MDE Advanced Hunting baseline for `DeviceEvents` ActionType `AppControlCodeIntegritySigningInformation` and event IDs 3076/3077
- Documentation of all signers, hash exceptions, and unsigned binaries flagged in audit mode

### Out of scope (Phase 1)

- POS terminals — Phase 3, separate ring and change window
- Fertilizer plant / OT-SCADA endpoints — Phase 4, assess after IT/OT segmentation work
- Enforcement mode on any ring
- Managed Installer / ISG tagging strategy — Phase 2 design

## Linked Vault Notes

- [[WDAC-Deployment]] — parent project
- [[WDAC/Policies/]] — policy XML artefacts will live here
- [[WDAC/Rings/Ring-0-IT-SecOps]] — to be created
- [[WDAC/Rings/Ring-1-Corporate]] — to be created
- [[Detection-KQL/Hunting-Queries/]] — Phase 1 hunting queries (audit blocks, unsigned binaries)
- [[Hardening/Controls/LSA-Protection-RunAsPPL]] — adjacent control already deployed

## Actions

- [ ] Confirm AppControl Manager licensing / deployment path on E5 (verify MDE P2)
- [ ] Select Ring 0 reference machine — clean install, fully patched, full app stack
- [ ] Generate baseline policy from reference machine (Audit mode: Allow Microsoft + signed apps + reputation/ISG)
- [ ] Deploy via Intune to Ring 0 only — confirm no enforcement
- [ ] Wait 14 days. Collect 3076/3077 events via MDE Advanced Hunting
- [ ] Build hunting query: `KQL-WDAC-Audit-Blocks-Phase1.md` — list flagged binaries by file/signer/hash
- [ ] Triage flagged binaries — categorise (legitimate / unknown / known-bad / dual-use)
- [ ] Document hash and signer exceptions required for Ring 0
- [ ] Repeat inventory pass for Ring 1 reference machine
- [ ] Phase 1 closeout: signed-off audit policy + gap list → Phase 2 design kickoff

## KQL Stubs

### Audit-mode block events (MDE Advanced Hunting)

```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType startswith "AppControlCodeIntegrity"
| extend Parsed = parse_json(AdditionalFields)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, Parsed
| summarize Count=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by FileName, FolderPath, SHA256, ActionType, tostring(Parsed.Signers)
| sort by Count desc
```

### Unsigned binaries observed in execution (baseline sanity check)

```kql
let RefHosts = dynamic(["RING0-REF-01"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName in (RefHosts)
| where isempty(InitiatingProcessSignerType) or InitiatingProcessSignerType == "Unsigned"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
| summarize Count=count() by FileName, FolderPath, SHA256
| sort by Count desc
```

> Validate columns before filing. `InitiatingProcessSignerType` enum values vary by tenant; the `Parsed.Signers` shape inside `AdditionalFields` should be confirmed against a real audit event.

### Validated columns

- [ ] `DeviceEvents.ActionType` — confirm full enum for AppControl events
- [ ] `DeviceEvents.AdditionalFields.Signers` — confirm structure
- [ ] `DeviceProcessEvents.InitiatingProcessSignerType` — confirm enum values

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-05 | Start with Ring 0 (IT/SecOps) | Lowest blast radius, highest tolerance for friction, fastest feedback loop |
| 2026-05-05 | AppControl Manager as primary tool | Already identified as project tooling; native E5 path |
| 2026-05-05 | OT/SCADA deferred to Phase 4 | IT/OT segmentation must precede WDAC; OT change windows are restrictive |

## Risks & Watch Items

- **Driver blocks** — audit will flag third-party drivers (printer, VPN, MDM). Plan a vendor-signer allowlist early.
- **Script enforcement** — confirm scope before Phase 2. PowerShell Constrained Language Mode interaction is non-trivial.
- **Managed Installer not yet tagged** — Intune-deployed apps need MI configuration before enforcement, otherwise legitimate deployments will block.
- **Telemetry volume** — 3076/3077 on a fresh audit rollout is noisy. Use per-device summarisation in hunting queries.
- **OT scope creep** — fertilizer plant assets must NOT receive this policy. Confirm Intune device group exclusions before deployment.

## Tags

#project #wdac #endpoint #status/active #action-required

## Changelog

- 2026-05-05 — Note created. Phase 1 kickoff.
