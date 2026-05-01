---
title: Claude Context Brief
date_created: 2026-04-28
last_updated: 2026-04-28
tags:
  - "#resource"
  - "#status/active"
icon: LiBrainCircuit
---

# Claude Context Brief

> Paste this note at the start of any Claude session outside the main project to restore full working context. Update the Dynamic Layer weekly or when priorities shift.

---

## Environment

| Field | Detail |
|-------|--------|
| **Stack** | MDE, Microsoft Sentinel, Entra ID, MDO, MCAS |
| **Endpoints** | ~150+ across Alberta, BC, Saskatchewan — includes POS terminals |
| **OT/SCADA** | Recently acquired fertilizer plant — Rockwell/Allen-Bradley PLCs, network segmentation unconfirmed |
| **Identity** | Hybrid Entra ID + Active Directory (Entra Connect) |
| **MDM** | Intune + Active Directory |
| **Schema** | Advanced Hunting (MDE) and Log Analytics (Sentinel) — always specify which |
| **Platform** | Mac (personal), Windows (work) — vault on OneDrive |
| **Training** | Blu Raven Academy (cyb3rmonk) |

---

## Vault

| Field | Detail |
|-------|--------|
| **Path** | `~/Documents/UFA-Security` |
| **Router watch folder** | `~/Downloads/obsidian-inbox/` |
| **Router script** | `/usr/local/bin/obsidian_router.py` |
| **Output convention** | Always `.md` files with correct prefix — never inline note content |

### Key Prefix → Folder Routing

| Prefix | Destination |
|--------|-------------|
| `KQL-` | `Detection-KQL/Queries/` |
| `RULE-` | `Detection-KQL/Analytics-Rules/` |
| `HUNTING-` | `Detection-KQL/Hunting-Queries/` |
| `INTEL-` | `Threat-Hunting/TTPs/` |
| `TTP-` | `Threat-Hunting/TTPs/` |
| `HUNT-` | `Threat-Hunting/Campaigns/` |
| `IR-` | `IR-DFIR/Cases/` |
| `PLAYBOOK-` | `IR-DFIR/Playbooks/` |
| `HARD-` | `Hardening/Controls/` |
| `WDAC-` | `WDAC/Runbooks/` |
| `OT-` | `OT-SCADA/Assets/` |
| `PROJ-` | `Projects/` |
| `INFO-` | `Research/Articles/` |
| `TOOL-` | `Research/Tools/` |
| `TRAINING-` | `Research/Training/` |
| `CLAUDE-` | `Research/Claude/` |
| `MTG-` | `Meetings/` |

---

## Output Conventions

- All notes delivered as `.md` files with correct router prefix
- KQL notes: include table, schema, MITRE, purpose, query, validated columns (checkboxes), Sentinel rule settings, changelog
- INTEL notes: include source URL, MITRE, detection candidate flag (`detection_candidate: true/false`), KQL stubs, hardening actions, related wikilinks
- KQL frontmatter always includes `promoted_to_rule: false` and `sentinel_rule_id: ""`
- Tags: minimum one type tag + one status tag per note
- Never refer to the organisation by name — always "your organisation" or "your environment"

---

## 🔴 Dynamic Layer — Current State
> **Last updated: 2026-04-28 (Week 4)**

### Threat Priorities

| Priority | Detail |
|----------|--------|
| 🔴 **Iranian APT (Handala / CL-STA-1128)** | Targeting Intune, Entra ID, Rockwell Automation OT. Directly relevant to both IT and plant. |
| 🔴 **OT/SCADA — Fertilizer Plant** | Network segmentation unconfirmed. Nmap/OpenVAS/Wazuh deployed. Illumio evaluation pending. Treat Iranian APT OT targeting as urgent. |
| 🟠 **Entra Connect SyncJacking** | GA hardening available — not yet applied. |
| 🟠 **Service Principal Abuse** | Agent ID Administrator CVE patched April 9. Audit role assignments outstanding. |
| 🟠 **Conditional Access Gap** | Registered ≠ Compliant. Device code flow not blocked. CA policy audit outstanding. |
| 🟡 **Infostealer Credential Exposure** | Monitor for domain credential leaks. |

### Active Projects

| Project | Status | Next Action |
|---------|--------|-------------|
| **WDAC Deployment** | Not started | Phase 1 planning — AppControl Manager as primary tool |
| **OT/SCADA Assessment** | In progress | Illumio evaluation pending, segmentation audit outstanding |
| **M365 Hardening** | Ongoing | SyncJacking hardening + CA policy gap are priority items |

### Detection Backlog (from Intel)

Notes with `detection_candidate: true` that haven't been promoted yet:

- `INTEL-LNK-Spoofing-Trust-Me-Im-A-Shortcut-Beukema` — LNK spoofing techniques, lnk-it-up toolkit
- `INTEL-EntraAgentID-ServicePrincipalHijack` — SP hijack via Agent ID Administrator role
- `INTEL-M365Pwned-OAuth-Token-Exfil-Tool` — OAuth app abuse, tenant-wide exfil
- `INTEL-CA-RegisteredNotCompliant-Bypass` — CA policy gap exploitation
- `INTEL-GlassWorm-FakeVSCode-Extensions` — supply chain via fake VS Code extensions

### Hardening Controls Deployed
Anonymous share enumeration, NTLMv2 enforcement, SMB signing, Autoplay disabled, Network Bridge disabled, IPv6/IPv4 source routing, WMI persistence blocked, LSA protection (RunAsPPL), LDAP signing/channel binding/sealing, local credential storage restricted, ASR policy monitoring active.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created |
