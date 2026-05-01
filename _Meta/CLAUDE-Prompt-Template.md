---
title: Claude Prompt Template
date_created: 2026-04-28
tags:
  - "#resource"
  - "#status/active"
icon: LiFileEdit
---

# Claude Prompt Template

> Use this scaffold for complex or high-stakes requests. For simple asks (quick KQL tweak, email check, single note) you don't need this — just ask. Reach for this when the task is ambiguous, multi-step, or the output needs to be right first time.

---

## The Template

```
## Role
[Who should Claude be for this task?]

Examples:
- Detection engineer validating KQL against MDE Advanced Hunting schema
- DFIR analyst building a playbook for [scenario]
- KQL schema validator — flag any columns that may not exist in this environment
- Threat intel analyst summarising a campaign for an E5 environment

---

## Context
[What does Claude need to know to do this well?]

- Environment facts relevant to this specific ask
- Related vault notes (wikilinks or paste key sections)
- Prior work / decisions already made
- Known constraints or gotchas

---

## Task
[One clear sentence describing exactly what you want.]

If it needs more than one sentence, it's probably two tasks. Split them.

---

## Output Format
- [ ] .md note — prefix: ___  
- [ ] KQL query only (no note)  
- [ ] Inline response  
- [ ] Table  
- [ ] Batch of .md files (zipped)

---

## Examples / Reference
[Paste a good example, a related note, or a query to use as a model.]

---

## Constraints
[What should Claude avoid, watch for, or not assume?]

Examples:
- Don't assume RemoteIPType exists — flag for validation
- Exclude SYSTEM and known service accounts
- Don't generate a full note — query only
- Schema is Advanced Hunting (MDE), not Log Analytics
- This is for a hunting query, not an analytics rule
```

---

## Worked Examples

### Example 1 — New KQL Detection from Intel

```
## Role
Detection engineer. MDE Advanced Hunting schema. E5 environment.

## Context
Iranian APT (Handala/CL-STA-1128) is actively using LNK files with oversized 
command lines to bypass Windows Explorer's Properties display. 
The lnk-it-up toolkit is now public so weaponisation is commodity-level.
Related note: INTEL-LNK-Spoofing-Trust-Me-Im-A-Shortcut-Beukema

## Task
Build a KQL hunting query for DeviceProcessEvents detecting LNK-spawned 
processes where ProcessCommandLine exceeds 260 characters.

## Output Format
- [x] .md note — prefix: KQL-

## Constraints
- Flag RemoteIPType if used — validate in environment
- Include Sentinel analytics rule recommendation
- Exclude known admin tools in the suppression list
```

---

### Example 2 — DFIR Playbook

```
## Role
DFIR analyst. Microsoft Sentinel + MDE environment. Hybrid Entra ID.

## Context
Investigating a potential service principal credential append — 
consistent with Agent ID Administrator abuse (now patched but 
historic exploitation possible). Related: INTEL-EntraAgentID-ServicePrincipalHijack

## Task
Build an IR playbook for investigating a suspected compromised 
service principal in Entra ID.

## Output Format
- [x] .md note — prefix: PLAYBOOK-

## Constraints
- Include KQL stubs for AuditLogs and AADServicePrincipalSignInLogs
- Note that AADServicePrincipalSignInLogs may not be connected — add validation step
- Scope to Entra ID only, not on-prem AD
```

---

### Example 3 — Intel Note from URL

```
## Role
Threat intel analyst. Summarise for an E5 environment with OT/SCADA assets.

## Context
Forwarded email with subject [INTEL]. URL: https://example.com/article

## Task
Fetch the URL, research the content, and generate a fully populated 
INTEL- note for the vault.

## Output Format
- [x] .md note — prefix: INTEL-

## Constraints
- Flag detection_candidate: true if there's a KQL opportunity
- Include KQL stubs if applicable
- Note #pending-review if the source couldn't be fetched
- Always note OT/SCADA relevance if applicable
```

---

## When to Use This

| Situation | Use Template? |
|-----------|--------------|
| Email check / triage | ❌ Just ask |
| Quick KQL tweak | ❌ Just ask |
| New detection from scratch | ✅ Yes |
| DFIR playbook | ✅ Yes |
| Complex hunting campaign note | ✅ Yes |
| OT/SCADA risk note | ✅ Yes — include regulatory scope |
| Single intel note from URL | ❌ Usually fine without |
| Batch of notes / complex research | ✅ Yes |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created |
