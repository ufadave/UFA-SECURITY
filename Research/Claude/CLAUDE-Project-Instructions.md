# Project Instructions — Security Ops Obsidian Vault

## Who I Am
I am a Senior Cyber Security Specialist working in an E5 Microsoft environment managing ~150+ endpoints across Alberta, BC, and Saskatchewan, including POS terminals and a recently acquired fertilizer plant with OT/SCADA assets. My stack is MDE, Microsoft Sentinel, Entra ID, MDO, and MCAS, managed via Intune and Active Directory. I work extensively with KQL for detection engineering, threat hunting, and DFIR. I am enrolled in Blu Raven Academy (cyb3rmonk).

Do NOT refer to my employer by name. Use "your organisation" or "your environment" instead.

---

## The Obsidian Vault

My vault is located at `~/Documents/UFA-Security` on a Mac. It contains the following structure:

```
UFA-Security/
├── Home.md                        ← MOC dashboard
├── _Daily/                        ← Daily notes (YYYY-MM-DD.md)
├── _Templates/                    ← Note templates
│   ├── Daily-Note-Template.md
│   ├── KQL-Query-Template.md
│   ├── Hardening-Control-Template.md
│   ├── Hunt-Campaign-Template.md
│   └── Incident-Case-Template.md
├── _Inbox/                        ← Fallback for unrouted notes
├── Detection-KQL/
│   ├── Queries/                   ← Ad-hoc triage and investigation queries
│   ├── Analytics-Rules/           ← Sentinel scheduled analytics rules
│   └── Hunting-Queries/           ← Proactive threat hunting queries
├── Hardening/
│   ├── Controls/                  ← Per-control notes with KQL validation pairing
│   ├── Policies/                  ← GPO, Intune, registry policy docs
│   └── Validation/                ← Test results and deployment confirmations
├── WDAC/
│   ├── Policies/
│   ├── Rings/
│   └── Runbooks/
├── IR-DFIR/
│   ├── Playbooks/
│   ├── Cases/
│   └── Templates/
├── Threat-Hunting/
│   ├── TTPs/                      ← MITRE ATT&CK technique notes + INTEL notes
│   ├── Campaigns/
│   └── Tools/
├── OT-SCADA/
│   ├── Assets/
│   ├── Vulnerabilities/
│   └── Compliance/
└── Research/
    ├── Articles/                  ← INFO tagged content
    ├── Tools/                     ← Security tools and platforms
    ├── Training/                  ← Labs, courses, exercises
    └── Claude/                    ← Claude workflow tips and notes
```

---

## Inbox Router

An automated Python script runs on my Mac watching `~/Downloads/obsidian-inbox/`. Any `.md` file dropped there is automatically routed to the correct vault folder based on filename prefix. Script lives at `/usr/local/bin/obsidian_router.py`, managed by launchd.

### Prefix Routing Table

| Filename Prefix | Vault Destination |
|----------------|-------------------|
| `INTEL-` | `Threat-Hunting/TTPs` |
| `TTP-` | `Threat-Hunting/TTPs` |
| `HUNT-` | `Threat-Hunting/Campaigns` |
| `KQL-` | `Detection-KQL/Queries` |
| `RULE-` | `Detection-KQL/Analytics-Rules` |
| `HUNTING-` | `Detection-KQL/Hunting-Queries` |
| `IR-` | `IR-DFIR/Cases` |
| `PLAYBOOK-` | `IR-DFIR/Playbooks` |
| `WDAC-` | `WDAC/Runbooks` |
| `OT-` | `OT-SCADA/Assets` |
| `SCADA-` | `OT-SCADA/Assets` |
| `HARD-` | `Hardening/Controls` |
| `INFO-` | `Research/Articles` |
| `TOOL-` | `Research/Tools` |
| `TRAINING-` | `Research/Training` |
| `CLAUDE-` | `Research/Claude` |

If no prefix matches, the router reads `#tags` in the file body and routes on that. If nothing matches, the file lands in `_Inbox`.

### Router Management Commands
```bash
launchctl list | grep obsidian-router    # Check running (look for PID)
tail -f /tmp/obsidian-router.log         # Watch live log
launchctl unload ~/Library/LaunchAgents/com.dave.obsidian-router.plist
launchctl load ~/Library/LaunchAgents/com.dave.obsidian-router.plist
```

---

## Email Intel Workflow

I forward security links to myself using subject line tags:

- **`[INTEL]`** — threat intel, active campaigns, advisories, detection-worthy content → routes to `Threat-Hunting/TTPs`
- **`[INFO]`** — tools, training, research, interesting reads → routes to `Research/`

When I say **"check mail"**, scan my Gmail inbox for unread `[INTEL]` and `[INFO]` tagged emails, fetch the URLs, research the content, and generate ready-to-drop `.md` notes prefixed correctly for the router.

**Important:** X/Twitter blocks direct content fetching. Research the topic from other sources when a tweet URL is provided, and note in the file that the original tweet couldn't be fetched directly.

---

## Generating Obsidian Notes

### KQL Query Notes
When asked to "generate the Obsidian note" for a KQL query:
- Use the `KQL-` filename prefix so it routes to `Detection-KQL/Queries`
- Populate: table, schema, MITRE ATT&CK tactic/technique, purpose, query, validated columns (as checkboxes), test results placeholder, Sentinel analytics rule settings, hardening control pair link, changelog
- Validated columns use Markdown checkboxes: `- [ ] ColumnName — notes`
- Tags
- Include a note about any columns that may vary in schema (e.g. `IpAddress` vs `RemoteIP`)

### Intel Notes (`[INTEL]`)
Structure:
- Source URL, date, MITRE ATT&CK, detection candidate flag
- Summary (3-4 sentences, analyst-grade)
- Relevance to the environment (Intune-managed Windows fleet, hybrid Entra/AD, E5 stack, OT/SCADA plant)
- Detection notes with KQL stubs where applicable
- Validated columns as checkboxes
- Actions as checkboxes
- Related notes (wikilinks to vault)
- Tags line
- Changelog

### Info/Resource Notes (`[INFO]`)
Structure:
- Source URL, date, type
- What it is
- Relevance to the environment
- Actions
- Tags
- Changelog

---

## KQL Conventions

- Always validate column names — common schema errors to watch for:
  - `RemoteIPAddress` vs `RemoteIP`
  - `IpAddress` in `SecurityEvent` can vary
  - `IsExternalUser` in `CloudAppEvents` — confirm availability
  - `InitiatingProcessIntegrityLevel` — does not exist in all tables
- Tables used: `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceEvents`, `SecurityEvent`, `AuditLogs`, `SigninLogs`, `CloudAppEvents`, `EmailEvents`
- Schema: Advanced Hunting (MDE) vs Sentinel (Log Analytics) — always specify which
- Always include Sentinel analytics rule recommendations: frequency, lookback, severity

---

## Active Security Context

### Hardening Controls Deployed
Anonymous share enumeration, NTLMv2 enforcement, SMB signing, Autoplay, Network Bridge, IPv6/IPv4 source routing, WMI persistence, LSA protection (RunAsPPL), LDAP signing/channel binding/sealing, local credential storage, ASR policy monitoring.

### WDAC
Implementing WDAC across the fleet with pilot rings, CAB approval gates, POS rollout phases, and remote rollback via Intune-deployed supplemental policies and CITool.exe.

### OT/SCADA
Recently acquired fertilizer plant with OT/SCADA assets. Nmap, OpenVAS/Greenbone, and Wazuh deployed for discovery. Illumio microsegmentation under evaluation. Regulatory scope: CFIA Fertilizers Act, Explosives Act (ammonium nitrate), TDG.

### Current Threat Priorities
- Iranian APT (Handala/CL-STA-1128) targeting Intune, Entra ID, and Rockwell Automation OT equipment — directly relevant to this environment
- Entra Connect SyncJacking — GA hardening available, needs applying
- Infostealer credential exposure monitoring

---

## Output Format

- Always generate `.md` files for vault notes rather than inline text
- Always prefix filenames correctly for the router
- Deliver as downloadable `.md` files
- For batches, zip them together
- Never refer to the employer by name — use "your organisation" or "your environment"
