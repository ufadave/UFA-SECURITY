---
title: Intel to Advanced Hunting Detection Rule — Workflow
date: 2026-05-06
type: reference
tags:
  - "#resource"
  - "#detection"
  - "#status/active"
---

# Intel to Advanced Hunting Detection Rule — Workflow

**Date:** 2026-05-06
**Owner:** Dave

> End-to-end pipeline from Gmail inbox to deployed detection rule, mapped to vault structure and router conventions.

---

## Overview

```
[INTEL] Email
    ↓
INTEL- note (Threat-Hunting/TTPs/)
    ↓
Triage — detection_candidate: true?
    ↓
KQL- note (KQL-Detection/)         ← draft + stub
    ↓
Validate in Advanced Hunting / Sentinel Logs
    ↓
Promote — tag + frontmatter update
    ↓
Deploy — MDE Custom Detection (default) or Sentinel Analytics Rule (exception)
    ↓
Pair with HARD- note (Hardening/Controls/)
    ↓
Close loop — INTEL #status/done, KQL #status/done
```

---

## Step 1 — Intake: Gmail to Vault

**Trigger:** `check mail` / `check mail quick` / `check mail triage`

- Gmail search surfaces unread emails tagged `[INTEL]`, `[INFO]`, `[RESEARCH]`
- Each `[INTEL]` thread fetched in full via `get_thread` (FULL_CONTENT)
- Converted to an `INTEL-` prefixed note and dropped to `~/Downloads/obsidian-inbox/`
- Router sends it to `Threat-Hunting/TTPs/`

**Note populated with:**
- Source URL, author, publish date
- MITRE ATT&CK mapping
- `detection_candidate: true` if a KQL opportunity exists
- KQL stub block
- Hardening actions checklist
- Tags: `#intel #status/draft` + domain/actor tags

**Surfaces in Home.md:**
- **Intel Feed — Last 14 Days** (all `#intel` notes)
- **Detection Backlog — From Intel** (where `detection_candidate = true` and not `#status/done`)

---

## Step 2 — Triage: Decide What's Worth Building

Open the INTEL note. Gate on three questions:

- [ ] Is the TTP relevant to your environment? (MDE endpoints, Entra ID, OT/SCADA, POS terminals, hybrid AD, MDO email)
- [ ] Are the required data sources available? (Advanced Hunting tables, or Sentinel Log Analytics for identity/cloud/email)
- [ ] Is the KQL stub viable, or does it need a full rewrite?

**If yes → proceed to Step 3.**

If no → tag INTEL note `#status/done` and add a one-line note explaining why it wasn't pursued.

---

## Step 3 — Draft: Create the KQL Note

Create a new file prefixed `KQL-` — router sends it to `KQL-Detection/`.

**Filename:** `KQL-<Descriptive-Name>.md`
**Template:** KQL-Query-Template

**Populate:**
- `table`, `schema`, `mitre`, `tactic`, `technique` in frontmatter
- `status: Draft`, `promoted_to_rule: false`
- `mde_rule_id: ""` or `sentinel_rule_id: ""` depending on target (leave blank until deployed)
- Query block (promote stub from INTEL note, refine as needed)
- Validated columns checklist (unchecked until tested)
- Test results placeholder
- Deployment section — MDE or Sentinel config as appropriate

**Tag for content subtype** — replaces subfolder structure:

| Tag | Use |
|-----|-----|
| `#detection/mde-rule` | MDE Advanced Hunting custom detection — **default for all device-based detections** |
| `#detection/analytics-rule` | Sentinel scheduled analytics rule — identity, cloud, and email signals only |
| `#detection/hunting` | Hunting query — kept manual, not scheduled |
| `#detection/audit` | Audit/visibility — not alerting |

> **Default is `#detection/mde-rule`.** Device tables (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, etc.) are not ingested into Log Analytics — Advanced Hunting is the only deployment target for these. Use `#detection/analytics-rule` only when the signal source exists exclusively in Sentinel: SigninLogs, AuditLogs, CloudAppEvents, EmailEvents, OfficeActivity.

Minimum tags: `#detection` + subtype + `#status/draft`

**Cross-link:** Add wikilink to source INTEL note in Related Notes. Add reciprocal link in the INTEL note.

**Surfaces in Home.md:** Detection Notes — Draft

---

## Step 4 — Validate: Run in Advanced Hunting or Sentinel Logs

Run the query over a representative lookback (7–30 days).

**Checklist:**
- [ ] Tick off each column in Validated Columns as schema is confirmed
- [ ] Review sample results — paste representative output into Test Results
- [ ] Tune for noise — document tuning rationale inline
- [ ] Assess signal quality — is this schedulable or manual-hunt territory?

**Schema gotchas to check:**
- `RemoteIPAddress` vs `RemoteIP` — differs by table
- `IpAddress` in `SecurityEvent` — can vary
- `IsExternalUser` in `CloudAppEvents` — confirm availability
- `parse_json(AdditionalFields)` — required for WDAC and many `DeviceEvents` fields

**If low signal on common LOLBins or environment-specific noise:** keep as `#detection/hunting` — do not promote to a scheduled rule. Detection quality over coverage.

---

## Step 5 — Promote: Choose Destination

Destination is a **tag and frontmatter change** — the note stays in `KQL-Detection/` throughout.

| Destination | When | Tag | Frontmatter |
|-------------|------|-----|-------------|
| MDE Custom Detection | Device-based signal — any DeviceX table | `#detection/mde-rule` | `promoted_to_rule: true`, `mde_rule_id: <ID>` |
| Sentinel Analytics Rule | Identity/cloud/email signal — SigninLogs, AuditLogs, CloudAppEvents, EmailEvents | `#detection/analytics-rule` | `promoted_to_rule: true`, `sentinel_rule_id: <GUID>` |
| Hunting Query | Useful but noisy / context-dependent / LOLBin volume anomaly | `#detection/hunting` | `promoted_to_rule: false` |

Update note status: `#status/draft` → `#status/active`

---

## Step 6 — Deploy

### MDE Custom Detection Rule (default)
1. In Defender XDR → Advanced Hunting → **Custom detection rules** → New rule
2. Paste validated query
3. Set frequency, lookback, severity, impacted entities, and automated response actions if applicable
4. Save and capture the rule ID
5. Update KQL note frontmatter:
   - `promoted_to_rule: true`
   - `mde_rule_id: <ID>`
   - `status: Active`
6. Changelog entry with deployment date

### Sentinel Analytics Rule (identity / cloud / email only)
1. Create scheduled rule in Sentinel using config from KQL note (frequency, lookback, severity, entity mappings)
2. Capture the rule GUID
3. Update KQL note frontmatter:
   - `promoted_to_rule: true`
   - `sentinel_rule_id: <GUID>`
   - `status: Active`
4. Changelog entry with deployment date

**Surfaces in Home.md:** Promoted to Sentinel Rules
> Note: Home.md Dataview query currently keys on `sentinel_rule_id` — MDE deployments are not surfaced. See known gap #6.

---

## Step 7 — Pair with a Hardening Control

If the detection has a logical hardening counterpart, create or link a `HARD-` note in `Hardening/Controls/`.

**Examples:**
- Detecting WMI persistence ↔ ASR rule blocking WMI child process creation
- Detecting NTLM relay ↔ SMB signing / NTLMv2 enforcement
- Detecting suspicious Entra ID sign-ins ↔ Conditional Access policy

Both notes reference each other. Treat the **detect + harden pair** as the unit of work — this enforces closure and prevents orphaned detections.

---

## Step 8 — Close the Loop

| Note | Action |
|------|--------|
| INTEL note | Tag `#status/draft` → `#status/done` |
| KQL note | `status: Active`, changelog entry with deployment date |
| HARD note (if created) | `status: Active` or `Deployed` |

When the rule fires in production, IR cases (`IR-` prefix in `IR-DFIR/Cases/`) link back to the KQL note via Related Notes.

---

## Tag and Status Transitions

```
INTEL note:   #status/draft → (KQL drafted + linked) → #status/done
KQL note:     #status/draft → (validated) → #status/active → (deployed) → #status/done
HARD note:    #status/draft → (deployed) → #status/active → (validated) → #status/done
```

---

## Schema Decision Tree

```
Is the signal source a DeviceX table?
    ↓ Yes → Advanced Hunting → #detection/mde-rule
    ↓ No  → What's the source?
               SigninLogs / AuditLogs / CloudAppEvents / EmailEvents / OfficeActivity
                   → Sentinel Log Analytics → #detection/analytics-rule
               Noisy / LOLBin volume anomaly / context-dependent
                   → Manual hunt → #detection/hunting
               Audit / visibility only
                   → #detection/audit
```

---

## Known Workflow Gaps

| # | Gap | Status |
|---|-----|--------|
| 1 | Attachment handling — ~25% of intel emails require manual upload | Open |
| 2 | Action-required closure loop — no Dataview weekly review mechanism yet | Open |
| 3 | KQL stub promotion — stubs stall at draft; this pipeline is the fix | **Highest leverage** |
| 4 | Persistent threat actor notes — no accumulating `HUNT-` notes per actor (e.g. Handala/CL-STA-1128) | Open |
| 5 | Processed-thread log — no dedup record of triage runs | Open |
| 6 | Home.md Promoted Rules Dataview only surfaces `sentinel_rule_id` — MDE deployments are invisible | Open |

---

## Related Notes

- [[Home]]
- [[KQL-Detection/]]
- [[Threat-Hunting/TTPs/]]
- [[Hardening/Controls/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-06 | Created |
| 2026-05-06 | Split `#detection/mde-rule` from `#detection/analytics-rule` — MDE is default deployment path; Sentinel reserved for identity/cloud/email sources not ingested into Advanced Hunting |
