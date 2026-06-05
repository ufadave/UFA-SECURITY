---
title: GreyNoise POC
status: active
type: project
created: 2026-06-03
owner: Dave
vendor: GreyNoise
eval_status: POC
tags:
  - "#project"
  - "#status/active"
  - "#vendor"
  - "#detection"
  - "#identity"
  - "#endpoint"
  - "#ot-scada"
  - "#action-required"
---

# Project — GreyNoise POC

---

## Objective

Run a time-boxed proof of concept to determine whether GreyNoise materially reduces alert volume, improves outbound C2 detection coverage on MDE telemetry, and surfaces OT/SCADA scanning intelligence relevant to the Iranian APT threat targeting Rockwell/Allen-Bradley equipment at the plant. Success is measured against current Shodan-based workflow and existing Sentinel/MDE detection coverage.

The decision at the end of the POC is binary: replace or augment Shodan with GreyNoise as the primary internet intelligence source, or reject and continue with Shodan.

---

## Scope

### In scope

- Native GreyNoise Sentinel data connector deployment — confirmed true data connector, no API query budget constraint, so enrichment can be applied broadly without per-row cost concern
- KQL detections and joins against the GreyNoise table (confirm tenant-specific table name during deployment — likely `GreyNoise_CL` or a managed table under the `ThreatIntelligence` namespace)
- Alert enrichment / noise suppression against `SigninLogs`, `AuditLogs`, `CloudAppEvents`, `EmailEvents`, `OfficeActivity`
- C2 Detection cross-referencing against MDE `DeviceNetworkEvents` (Advanced Hunting — device telemetry is not in Sentinel Log Analytics, so this is an MDE Custom Detection candidate)
- OT/SCADA scanning campaign visibility — Rockwell/EtherNet/IP, Modbus, DNP3 tags; Iranian APT (Handala/CL-STA-1128) infrastructure tracking
- GreyNoise UI as a hunting/IR pivot tool — replacing Shodan workflow
- Recall capability evaluation for retrospective IOC scoping
- Tag fidelity validation across at least two Picus simulations or controlled tests

### Out of scope (POC)

- SOAR/playbook automation — defer until tag fidelity validated
- Active blocklist push to firewall or MDE custom indicators — defer until POC decision
- POS terminal-specific use cases — no internet-facing scope on POS estate
- Plant edge surveillance via GreyNoise sensor deployment — separate evaluation if POC succeeds

---

## Success Criteria

The POC succeeds if **all three** of the following are met:

| # | Criterion | Measurement |
|---|---|---|
| 1 | Alert volume reduction | ≥30% reduction in target rule set alert volume over 2-week shadow window with zero confirmed true-positive suppression |
| 2 | C2 detection coverage | At least one validated C2 hit on `DeviceNetworkEvents` over POC window OR confirmed coverage against a controlled Picus simulation of known C2 infrastructure |
| 3 | OT/SCADA visibility uplift | Weekly OT-relevant scanning intelligence report producible from GreyNoise that is not producible from current Shodan workflow |

A "stretch" outcome — useful but not required for a yes/no decision — is at least one successful threat hunt or IR pivot where GreyNoise materially shortened analyst time vs Shodan.

---

## Use Cases by Tier

### Tier 1 — Must prove

**UC-1 — Sentinel alert enrichment / noise suppression**

Cross-reference public source IPs from high-volume rules against GreyNoise classification. Suppress or downgrade alerts where the IP is classified as opportunistic mass-scanner traffic. Target rule families:

- `SigninLogs` — failed sign-ins, unfamiliar sign-in properties, atypical travel
- `OfficeActivity` / `EmailEvents` — inbound sender IP context
- `CloudAppEvents` — external IPs touching cloud apps

Run in **shadow mode** for the first 2 weeks: log GreyNoise classifications alongside alerts, do not suppress. Compare suppressed vs raw alert counts against analyst dispositions before enabling production suppression.

**UC-2 — C2 detection on MDE outbound traffic**

Build an MDE Advanced Hunting custom detection that joins `DeviceNetworkEvents.RemoteIP` against GreyNoise C2-tagged infrastructure. Deployment path is **MDE Custom Detection Rule** (device tables not in Sentinel Log Analytics).

Sample KQL shape (validate columns and table name before promoting):

```kql
// Table: DeviceNetworkEvents (Advanced Hunting)
// Schema: Advanced Hunting
// Purpose: Detect outbound connections to GreyNoise-classified C2 infrastructure
let GreyNoiseC2 =
    externaldata(IP:string, Tag:string, LastSeen:datetime)
    [@"<replace-with-greynoise-c2-feed-export>"]
    with (format="csv", ignoreFirstRecord=true);
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| join kind=inner (GreyNoiseC2) on $left.RemoteIP == $right.IP
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Tag, LastSeen
```

Final form depends on how GreyNoise exposes C2 data to the Sentinel connector — direct KQL table join is preferred if available.

**UC-3 — OT/SCADA scanning campaign visibility**

Pull GreyNoise tag inventory for ICS/OT protocol scanners (EtherNet/IP, Modbus, DNP3, Siemens S7, Rockwell-specific). Correlate against:

- Any external scanning observed against tenant-edge IPs that touch the plant network path
- Iranian APT infrastructure where attributable (Handala/CL-STA-1128)
- Weekly trend reporting on volume and origin of OT-targeted scanning

This is the differentiator vs Shodan. If Tier 1 succeeds and Tier 3 doesn't, the OT story is weaker — explicit measurement matters.

### Tier 2 — Validate during POC

**UC-4 — Hunting and IR pivot tool**

Replace Shodan UI workflow with GreyNoise UI for IP investigation during hunts and IR. Capture analyst time-to-context for at least three real investigations during the POC window.

**UC-5 — Recall for retrospective scoping**

When a fresh IOC drops (intel feed, advisory, IR), use Recall to surface first-observed date and tag history. Apply to at least two retrospective investigations during the POC.

**UC-6 — EmailEvents sender IP enrichment**

Enrich sender IPs in MDO/`EmailEvents` against GreyNoise classification. BEC and phishing sender infrastructure frequently has prior GreyNoise tagging. Could feed a Sentinel detection that elevates phishing alerts where sender IP is targeted-classified.

### Tier 3 — Nice-to-have

**UC-7 — External exposure validation** — confirm whether tenant-edge IPs and any plant-adjacent edge IPs are being probed and how they're tagged.

**UC-8 — Blocklist automation** — feed high-confidence malicious tags into Sentinel watchlists or MDE custom indicators. Only after tag fidelity validated.

---

## Timeline

| Week | Milestone |
|------|-----------|
| Week 1 | Native Sentinel connector deployed; confirm table name and schema; baseline alert volume captured on target rule set; GreyNoise UI access provisioned |
| Week 1–2 | UC-1 shadow mode running (classification logged, no suppression); UC-2 KQL built and tested in Advanced Hunting |
| Week 2 | UC-3 OT/SCADA tag inventory pulled; weekly OT scanning report v1 produced |
| Week 3 | UC-2 promoted to MDE Custom Detection; UC-4 / UC-5 used during live hunts or IR if opportunity arises |
| Week 4 | UC-1 enabled in production on validated rules; mid-POC review against success criteria |
| Week 5 | UC-6 EmailEvents enrichment built and shadow-tested |
| Week 6 | Tag fidelity validation via Picus simulation; final data collection |
| Week 7 | Decision write-up, recommendation to director, vendor evaluation note updated |

---

## Open Questions

- [ ] What is the tenant-specific GreyNoise table name in Log Analytics? Confirm during connector deployment
- [ ] Does the data connector include the full classification taxonomy (benign / unknown / malicious / targeted) or a reduced subset?
- [ ] Are C2 indicators delivered as a separate table or a tag within the main GreyNoise table? Affects KQL join shape
- [ ] Canadian data residency — still unconfirmed from vendor evaluation. Required before final decision
- [ ] Does Recall expose data via the connector or only via the UI/API?
- [ ] Are RIOT (legitimate business IP) lookups in scope of the POC licence?

---

## Linked Vault Notes

- [[VENDOR-GreyNoise-Internet-Intelligence]] — primary vendor evaluation note
- [[VENDOR-Censys-Internet-Intelligence]] — comparator vendor evaluation
- [[Threat-Hunting/TTPs/]] — Iranian APT context (Handala / CL-STA-1128)
- [[Projects/OT-SCADA-Assessment/]] — plant assessment context driving OT use case
- [[PLAYBOOK-Graph-API-Broad-Permission-Grant]] — example of identity-side enrichment opportunity

---

## Actions

- [ ] Deploy native GreyNoise Sentinel data connector and confirm table name/schema
- [ ] Capture baseline alert volume on `SigninLogs`, `OfficeActivity`, `EmailEvents`, `CloudAppEvents` rule families for shadow-mode comparison
- [ ] Build UC-1 enrichment KQL — shadow mode (classification logged, no suppression)
- [ ] Build UC-2 C2 detection KQL against `DeviceNetworkEvents` in MDE Advanced Hunting
- [ ] Pull GreyNoise OT/ICS tag inventory and build weekly scanning report (UC-3)
- [ ] Confirm Canadian data residency in writing with vendor
- [ ] Validate tag fidelity via Picus simulation in Week 6
- [ ] Mid-POC review at Week 4 against success criteria
- [ ] Final write-up and recommendation at end of Week 7

---

## Decisions Log

| Date | Decision |
|------|----------|
| 2026-06-03 | POC project created. Native Sentinel data connector confirmed; no API query budget — enrichment can run broadly. Three Tier 1 use cases scoped: alert noise suppression, MDE C2 detection, OT/SCADA scanning visibility |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-03 | Created |
