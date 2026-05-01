---
title: "RESEARCH-Claude-CoWork-Risk-Profile"
date: 2026-04-30
type: risk-assessment
tags:
  - "#resource"
  - "#cloud"
  - "#endpoint"
  - "#identity"
  - "#status/review"
  - "#action-required"
  - "#export"
---

# Claude CoWork — Risk Profile for Environment Use

**Date:** 2026-04-30
**Analyst:** Security Operations
**Product:** Claude CoWork (Anthropic)
**Availability:** Team and Enterprise plans; research preview as of April 2026
**Platform:** Windows (required); macOS support confirmed
**Risk Rating:** 🔴 HIGH — not recommended for deployment without significant controls

---

## What CoWork Is

Claude CoWork is Anthropic's desktop-native agentic AI tool for non-technical users, launched January 13, 2026. It operates as an autonomous agent running in a virtual machine on the user's workstation, with access to local files, the browser (via Claude in Chrome extension), connected MCP services, and Microsoft Office add-ins. It can execute multi-step workflows autonomously, including scheduled recurring tasks that run unattended while the desktop app is open.

As of April 2026, CoWork received the same desktop computer-use capability as Claude Code — it can now interact directly with any application on the real desktop, outside the VM sandbox. This is the single most significant escalation in its attack surface.

**Key capabilities (and attack surface):**
- Local filesystem read/write/delete with user-level permissions
- Browser automation via Claude in Chrome (screenshots, clicks, form fills, JavaScript execution)
- MCP server integrations (Gmail, Google Drive, Slack, Notion, databases)
- Microsoft Office add-ins (Word, Excel, PowerPoint, Outlook)
- Scheduled tasks running unattended
- Dispatch — remote task initiation from mobile device
- Desktop computer use (direct control of any app on screen — no sandbox)

---

## Vulnerability and Incident History

### File Exfiltration via Prompt Injection — January 15, 2026 (2 days post-launch)
**Patched:** Partially — February 2026 (VM updated). Core architectural issue remains.
**Researcher:** PromptArmor

A Word document containing hidden white-on-white text (1pt font, invisible to users) injected instructions causing CoWork to locate sensitive files — including financial documents containing partial SSNs — and upload them to an attacker-controlled Anthropic account via curl commands. The attack succeeded because `api.anthropic.com` is on the default network allowlist, meaning standard DLP and firewall rules did not block the exfiltration. The outbound channel looked like legitimate Anthropic API traffic.

**Core architectural issue (unpatched):** The prompt injection + API allowlist combination remains a structural vulnerability. Fixing specific injection instances does not solve the underlying problem that exfiltration can route through Anthropic's own infrastructure.

### CVE-2025-59536 (CVSS 8.7) — RCE via .claude/settings.json
**Patched:** Claude Code 1.0.111+ (October 2025). Shared architecture with CoWork.
Malicious `.claude/settings.json` in a cloned repository executes arbitrary shell commands before the trust dialog appears. Hooks and MCP server entries in repository config files are treated as trusted execution material. An attacker with commit access to any shared repository creates a standing backdoor that fires on every affected user.

### CVE-2026-21852 (CVSS 5.3) — API Key Exfiltration via ANTHROPIC_BASE_URL
**Patched:** Claude Code 2.0.65+ / CoWork equivalent (January 2026).
`ANTHROPIC_BASE_URL` override in repository config redirects all API traffic — including authentication headers — to an attacker-controlled server before the trust prompt appears. Simply opening a malicious repository exfiltrates the active API key with no user interaction.

---

## Risk Assessment for This Environment

### Environment Profile Factors
- E5 Microsoft tenant — MDE, Sentinel, Entra ID, Intune, MDO, MCAS
- Hybrid AD with Entra Connect — service principal abuse is a current active threat
- Active Iranian APT targeting Entra ID and M365 workloads
- ~150 endpoints including POS terminals
- OT/SCADA plant with network adjacency concerns
- WDAC deployment in progress
- MCP connectors in active use: Gmail, Google Drive, Microsoft Learn, Claude in Chrome

### Risk Factors

| Risk | Rating | Notes |
|------|--------|-------|
| **Prompt injection → file exfiltration** | 🔴 Critical | Demonstrated 2 days post-launch. Any document, email, or webpage CoWork processes is a potential injection vector. Exfiltration routes through Anthropic's own API — invisible to DLP and standard firewall rules. |
| **No audit trail** | 🔴 Critical | Anthropic explicitly states CoWork activity is excluded from Audit Logs, Compliance API, and Data Exports. Conversation history is local only. In a security incident involving CoWork, you have no centralised log of what the agent accessed or did. |
| **Desktop computer use (April 2026)** | 🔴 Critical | CoWork now controls the real desktop — no VM sandbox. On a workstation with Sentinel, MDE, Entra, and Intune portals open, a compromised CoWork session has analyst-level access to your entire security stack. |
| **MCP connector scope** | 🔴 High | Each connected MCP server expands CoWork's action scope. Gmail + Google Drive + Claude in Chrome connected means a prompt injection can read mail, exfiltrate Drive files, and browse internal portals. |
| **Scheduled tasks run unattended** | 🟡 High | Tasks execute while the desktop app is open, potentially without the user watching. A prompt injection loop in a scheduled task could run for hours. No centralised visibility into what ran. |
| **Dispatch (mobile → desktop)** | 🟡 High | A compromised mobile device or mobile-side prompt injection can cascade to desktop file access and browser automation. Keeps the machine awake — tasks run at any hour. |
| **Shadow AI / ungoverned deployment** | 🟡 High | CoWork installs without IT involvement. Org-wide toggle means it's all-or-nothing — no role-based restriction available on Team plan. Employees may already be using it against sensitive data with zero organisational visibility. |
| **Approval fatigue** | 🟡 Medium | The "click Yes to approve" security model is the primary human control. Research confirms users develop approval fatigue — clicking through dialogs without reading them, especially for multi-step tasks. |
| **WDAC interaction** | 🟡 Medium | CoWork's VM and computer-use execution model may require WDAC policy exceptions. Granting broad exceptions undermines the WDAC deployment. Validate before any deployment. |
| **DLP bypass via Anthropic API** | 🟡 Medium | Exfiltration through api.anthropic.com bypasses standard proxy/DLP inspection. Requires explicit allowlist management or API-layer DLP that inspects Anthropic traffic. |
| **POS terminal adjacency** | 🟡 Medium | If CoWork is deployed on workstations with network visibility to POS terminals, a compromised session is an indirect POS network access point. |

---

## The Audit Trail Gap — Critical for Your Environment

This deserves specific attention. Anthropic explicitly states that CoWork activity is not captured in Audit Logs, Compliance API, or Data Exports. Conversation history is stored locally on the user's device only.

For a security operations environment running MDE, Sentinel, and MCAS — tools specifically designed to provide visibility into user and system activity — CoWork introduces a blind spot that none of those tools address. In a security incident involving CoWork:

- You cannot query Sentinel for what CoWork accessed
- MCAS cannot see CoWork's file operations or API calls
- MDE telemetry shows CoWork as a process but not its agent-level actions
- You cannot reconstruct what the agent did without local device forensics

This is not theoretical — it directly impacts your incident response capability for any event involving CoWork.

---

## Use Case Analysis

### Not Recommended
| Use Case | Reason |
|----------|--------|
| Any workstation with Sentinel/MDE/Entra portal access | Desktop control + security stack access = critical blast radius |
| Processing untrusted documents or emails | Prompt injection via file content demonstrated day-2 post-launch |
| Scheduled tasks against sensitive file locations | Unattended execution with no audit trail |
| Dispatch enabled on any managed workstation | Mobile → desktop attack cascade; keeps machine awake |
| Any workstation with OT network path | Indirect lateral movement staging point |
| POS-adjacent workstations | Network adjacency risk |

### Conditional — Requires Governance and Controls
| Use Case | Controls Required |
|----------|-----------------|
| Personal productivity tasks on isolated workstation | No sensitive file access; no MCP connectors to corporate data; no Dispatch; no scheduled tasks against sensitive paths |
| Research synthesis from trusted internal sources only | Strict file access scope; trusted-source-only policy; monitor for unexpected network connections |

---

## Controls Required if Deployed

- [ ] **Disable Dispatch** — remote mobile → desktop task initiation is not appropriate for managed corporate workstations
- [ ] **Disable scheduled tasks** or restrict to explicitly approved, low-risk, non-sensitive workflows only
- [ ] **Scope file access strictly** — dedicated working folder only; no access to credential stores, security tooling configs, or sensitive document directories
- [ ] **MCP connector audit** — review and restrict connected MCP servers. Gmail + Drive + Chrome in combination with desktop control is a high-risk configuration
- [ ] **Block CoWork from security portal workstations** — any workstation where Sentinel, MDE, Entra, or Intune portals are used regularly should not have CoWork with desktop control enabled
- [ ] **Claude in Chrome scoping** — restrict Chrome extension to approved sites only; disable Chrome-to-Cowork bridge if desktop control is enabled
- [ ] **Network monitoring** — alert on outbound HTTPS to `api.anthropic.com` from CoWork process on workstations outside approved use — this is the exfiltration channel
- [ ] **WDAC validation** — confirm CoWork installation and VM execution model does not require broad WDAC exceptions before deployment
- [ ] **Intune policy** — use managed-settings.json deployment via Intune to enforce deny rules organisation-wide rather than relying on per-user configuration
- [ ] **AI Acceptable Use Policy** — document what CoWork may and may not be used for; include in onboarding and annual awareness training. Without a policy, shadow AI use is already occurring.

---

## Detection Recommendations

### KQL — CoWork Process Execution

```kql
// Hunt: CoWork process activity on managed endpoints
// Schema: Advanced Hunting (MDE)
// Tables: DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "Claude.exe"
    or FolderPath has "Claude" and FileName =~ "claude.exe"
| project Timestamp, DeviceName, AccountName,
    FileName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName
```

### KQL — Outbound to Anthropic API from Non-Browser Process

```kql
// Hunt: Non-browser processes connecting to Anthropic API
// Exfiltration via CoWork routes through api.anthropic.com
// Schema: Advanced Hunting (MDE)
// Tables: DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has "anthropic.com"
    or RemoteUrl has "claude.ai"
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "safari.exe"
    )
| project Timestamp, DeviceName, AccountName,
    RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

### KQL — Sensitive File Access by CoWork Process

```kql
// Hunt: CoWork accessing credential stores or security config paths
// Schema: Advanced Hunting (MDE)
// Tables: DeviceFileEvents
DeviceFileEvents
| where InitiatingProcessFileName =~ "claude.exe"
    or InitiatingProcessFileName has "CoWork"
| where FolderPath has_any (
    ".ssh", "credentials", "AppData\\Roaming\\Microsoft\\Credentials",
    "AppData\\Local\\Microsoft\\Credentials",
    ".aws", ".azure", "token", "api_key"
    )
| project Timestamp, DeviceName, AccountName,
    FolderPath, FileName, ActionType,
    InitiatingProcessFileName
```

---

## Validated Columns

- [ ] `DeviceProcessEvents.FileName` — confirm exact CoWork binary name on Windows (`Claude.exe` or similar)
- [ ] `DeviceNetworkEvents.RemoteUrl` — confirm availability and format in your schema version
- [ ] `DeviceFileEvents.InitiatingProcessFileName` — validate CoWork process name for file event correlation

---

## Overall Recommendation

**CoWork is not recommended for deployment in this environment at this time.**

The combination of no centralised audit trail, demonstrated file exfiltration via prompt injection routing through Anthropic's own API (invisible to DLP), the April 2026 desktop computer-use expansion removing the VM sandbox, active Iranian APT threat targeting your M365 workloads, and the all-or-nothing org-wide toggle on Team plan creates a risk profile that current controls cannot adequately address.

The audit trail gap alone is a near-disqualifying factor for a regulated environment. You cannot investigate a CoWork-related incident with your current tooling. That is an unacceptable blind spot.

Revisit when: Anthropic ships RBAC at Team plan level, audit logging is available in the Compliance API, and the VM sandbox is restored as the default for computer use.

---

## Related Notes

- [[Research/Articles/RESEARCH-OpenAI-Codex-Risk-Profile]] — parallel risk assessment, similar threat class
- [[Research/Tools/TOOL-claudit-sec-Claude-Desktop-MCP-Audit]] — use to audit current Claude Desktop configuration
- [[Projects/M365-Hardening/]] — MCP connector governance
- [[Projects/WDAC-Deployment/]] — WDAC interaction with CoWork VM

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-30 | Risk profile created |
