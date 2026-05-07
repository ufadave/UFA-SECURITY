---
title: "RESEARCH-Claude-Code-Risk-Profile"
date: 2026-04-30
type: risk-assessment
tags:
  - "#resource"
  - "#cloud"
  - "#endpoint"
  - "#supply-chain"
  - "#status/review"
  - "#action-required"
  - "#export"
---

# Claude Code — Risk Profile for Environment Use

**Date:** 2026-04-30
**Analyst:** Security Operations
**Product:** Claude Code (Anthropic)
**Current Version:** 2.1.x (as of April 2026; track via npm @anthropic-ai/claude-code)
**Minimum Safe Version:** 2.0.65+ (CVE-2026-21852 patched)
**Risk Rating:** 🟡 MEDIUM — permitted with mandatory controls

---

## What Claude Code Is

Claude Code is Anthropic's terminal-based AI coding agent, released April 2025. Unlike CoWork (which targets non-technical users), Claude Code is designed for developers — it operates in the terminal, interacts with codebases, runs shell commands, executes tests, proposes pull requests, and manages repositories. It can also be integrated into CI/CD pipelines via GitHub Actions.

As of April 2026, Claude Code has also received desktop computer-use capability, allowing it to interact with any application on the workstation — extending its reach beyond the terminal.

**Key capabilities (and attack surface):**
- Full terminal access with developer user-level permissions
- Shell command execution (arbitrary, within permissions)
- Filesystem read/write across any accessible path
- GitHub repository access via OAuth token or PAT
- MCP server integrations (same ecosystem as CoWork)
- CI/CD pipeline integration via GitHub Actions
- Desktop computer use (April 2026)
- Hooks — predefined actions at specific lifecycle points

---

## CVE and Vulnerability History

Claude Code has a significant CVE track record for a product less than 12 months old. All vulnerabilities share a common pattern: **repository-controlled configuration files treated as trusted execution material**.

### CVE-2025-59536 (CVSS 8.7) — RCE via Hooks and MCP Config (Check Point, Oct 2025)
**Patched:** Version 1.0.111 (October 2025)
**Attack vector — Hooks:** Attacker adds malicious Hook commands to `.claude/settings.json` in a repository. When any developer opens the project, the hooks execute arbitrary shell commands automatically — before the trust dialog appears, with no user consent. Check Point demonstrated a working reverse shell payload.

**Attack vector — MCP servers:** Same config file can define malicious MCP server entries. Commands execute before the trust dialog, bypassing the consent mechanism entirely.

**Supply chain impact:** Single malicious commit to a shared repository fires on every affected developer. Compromised templates, starter repos, or popular open-source projects can weaponise many downstream users simultaneously.

### CVE-2026-21852 (CVSS 5.3) — API Key Exfiltration via ANTHROPIC_BASE_URL (Check Point, Jan 2026)
**Patched:** Version 2.0.65 (January 2026)
**Attack vector:** Attacker sets `ANTHROPIC_BASE_URL` in `.claude/settings.json` to an attacker-controlled endpoint. When Claude Code initialises in the malicious repository, it issues API requests — including the full authentication header with the API key — to the attacker's server before showing the trust prompt. Zero user interaction required beyond cloning the repository.

**Anthropic Workspaces amplification:** A stolen API key in a shared Workspace environment grants access to all workspace-scoped files and resources, potentially exposing team-wide data, not just the individual developer's.

### Source Code Leak — March 31, 2026
**Severity:** Significant — not a CVE but operationally relevant
Anthropic accidentally exposed the full Claude Code source (~513,000 lines of TypeScript across 1,906 files) via a JavaScript source map bundled in the public npm package `@anthropic-ai/claude-code` version 2.1.88. The file was downloaded and mirrored publicly within hours. Threat actors now have full visibility into hook execution logic, permission checks, and internal trust mechanisms — making future exploitation of similar patterns significantly easier to craft precisely.

The leak coincided with a malicious Axios npm supply chain attack (March 31, 2026) — creating compounded risk for developers who updated Claude Code via npm that day.

### AGENTS.md Indirect Injection (NVIDIA AI Red Team, April 2026)
**Severity:** Medium (requires compromised dependency as prerequisite)
A malicious dependency injects instructions into `AGENTS.md` — Claude Code's agent instruction file — directing the agent to conceal its actions and take privileged steps in CI/CD pipelines. The attack is invisible in normal PR review and may execute in GitHub Actions before detection.

### PromptPwnd Class (Aikido Security, Dec 2025)
Applies to Claude Code in CI/CD contexts. Untrusted user input (PR descriptions, issue bodies) injected into Claude Code prompts causes the agent to execute privileged GitHub Actions with `$GITHUB_TOKEN`. The write-permission default protection can be disabled — doing so creates a near-certain token leak vector. At least 5 Fortune 500 companies affected.

---

## Risk Assessment for This Environment

### Environment Profile Factors
- E5 Microsoft tenant — not primarily a software development environment
- Hybrid AD with Entra Connect — service principal abuse current active threat
- Active Iranian APT targeting M365 and identity infrastructure
- ~150 endpoints; WDAC deployment in progress
- Security operations workstation has access to Sentinel, MDE, Entra, Intune portals
- KQL development and detection engineering is a core workflow (relevant use case)
- No significant software development CI/CD pipeline in use

### Risk Factors

| Risk | Rating | Notes |
|------|--------|-------|
| **RCE via malicious repository config** | 🔴 High | CVE-2025-59536 — patched, but source code leak (March 2026) gives threat actors a precision roadmap for new variants. Never open untrusted repositories with Claude Code. |
| **API key exfiltration** | 🔴 High | CVE-2026-21852 — patched in 2.0.65+. Requires version discipline. If version management is not enforced, risk returns. |
| **Shell command execution scope** | 🟡 High | Claude Code executes arbitrary shell commands with developer-level permissions. On a security workstation, this means Sentinel API calls, MDE API calls, Entra operations, and file system access to security tooling configs. |
| **Supply chain via npm** | 🟡 High | Claude Code is distributed via npm. The March 2026 source leak + simultaneous Axios supply chain attack demonstrates real npm-based risk. Always verify package integrity and pin versions. |
| **Desktop computer use (April 2026)** | 🟡 High | Same capability as CoWork — direct desktop control on the real machine. On a security workstation with portals open, blast radius is significant. |
| **WDAC interaction** | 🟡 Medium | Claude Code's dynamic shell execution model requires careful WDAC policy design. Risk of either blocking legitimate use or creating over-broad allow rules that undermine the WDAC deployment. |
| **Prompt injection via codebase** | 🟡 Medium | Malicious content in files Claude Code reads (comments, strings, config files) can inject instructions. In a security context, code that processes external input (log parsers, alert handlers) is a viable injection surface. |
| **CI/CD pipeline integration** | 🟡 Medium | Not a current workflow, but if considered: PromptPwnd applies. Write-permission gating must be enforced; never disable it. |
| **MCP server scope** | 🟡 Medium | Same MCP ecosystem as CoWork. Connected MCP servers extend Claude Code's action scope beyond the terminal. Audit and restrict. |

---

## Use Case Analysis

### Recommended — Lower Risk
| Use Case | Notes |
|----------|-------|
| KQL query development and testing | Prompt-only, no codebase access; primary security engineering use case |
| Local script development in isolated working directory | No sensitive credentials in scope; dedicated folder only |
| Code review assistance (read-only posture) | Avoid using on repos with untrusted contributors or external dependencies |
| Detection engineering — query iteration | High value, low risk when scoped to query files only |

### Conditional — Requires Controls
| Use Case | Controls Required |
|----------|-----------------|
| Vault automation scripting (router, exporter) | Isolated working directory; no production credential access; pin version |
| Internal repository work | Repository must have branch protection; no external contributor access to `.claude/` config; review `AGENTS.md` for injection |
| Security tooling development | Isolated dev environment; no production MDE/Sentinel/Entra API keys in scope |

### Not Recommended
| Use Case | Reason |
|----------|--------|
| Any untrusted or external repository | CVE-2025-59536 attack class — even patched, source code leak makes new variants more precise |
| CI/CD pipeline integration | PromptPwnd — not a current workflow; don't introduce without full security review |
| Desktop computer use on security workstation | Portal access + desktop control = significant blast radius |
| Production credentials in terminal environment | Any active API key or token is in exfiltration scope |

---

## Controls Required

- [ ] **Version pinning** — pin to ≥ 2.0.65 minimum. Track current version via MDE software inventory. Update promptly on new CVE disclosures.
- [ ] **No production credentials in scope** — Claude Code sessions must not have access to production Sentinel/MDE/Entra API keys, GitHub PATs with org scope, or any credential with blast radius beyond the local workstation
- [ ] **Trusted repositories only** — never run Claude Code in a cloned repository from an untrusted or unknown source. Treat external repos as untrusted even if they appear legitimate.
- [ ] **Review .claude/settings.json and AGENTS.md** — before running Claude Code in any repository, inspect these files manually for unexpected Hook commands, MCP entries, or ANTHROPIC_BASE_URL overrides
- [ ] **Dedicated working directory** — scope Claude Code file access to a dedicated folder; do not run from the home directory or any path containing credential stores
- [ ] **Disable desktop computer use** — if Claude Code is used for terminal-only workflows (KQL development, scripting), desktop control provides no benefit and material risk. Disable via settings.
- [ ] **WDAC policy validation** — audit WDAC policies for Claude Code's execution model before deployment. Claude Code spawns child processes dynamically; confirm this doesn't require over-broad allow rules.
- [ ] **npm integrity** — verify package integrity when installing or updating. Use `npm audit` after installation. Monitor for supply chain compromise notifications.
- [ ] **MCP connector audit** — if MCP servers are connected, audit scope and restrict to minimum necessary. Run `claudit-sec` after installation.
- [ ] **No CI/CD integration** — do not integrate Claude Code into GitHub Actions or other pipelines without a full security review including PromptPwnd assessment.

---

## Detection Recommendations

### KQL — Claude Code Execution and Child Process Spawning

```kql
// Hunt: Claude Code terminal execution and suspicious child processes
// Schema: Advanced Hunting (MDE)
// Tables: DeviceProcessEvents
DeviceProcessEvents
| where InitiatingProcessFileName =~ "claude"
    or InitiatingProcessCommandLine has "@anthropic-ai/claude-code"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash.exe", "sh.exe", "curl.exe", "wget.exe",
    "certutil.exe", "net.exe", "whoami.exe"
    )
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### KQL — .claude/settings.json Creation or Modification

```kql
// Hunt: Claude Code config file created or modified
// .claude/settings.json is the primary attack surface for CVE-2025-59536 class
// Schema: Advanced Hunting (MDE)
// Tables: DeviceFileEvents
DeviceFileEvents
| where FileName =~ "settings.json"
| where FolderPath has ".claude"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, AccountName,
    FolderPath, FileName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

### KQL — Outbound API Traffic from Claude Code Process

```kql
// Hunt: Outbound connections to non-Anthropic endpoints from Claude Code
// ANTHROPIC_BASE_URL override exfiltrates to attacker infrastructure
// Schema: Advanced Hunting (MDE)
// Tables: DeviceNetworkEvents
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "claude"
    or InitiatingProcessCommandLine has "claude-code"
| where RemoteUrl !has "anthropic.com"
    and RemoteUrl !has "claude.ai"
    and not (RemoteUrl startswith "127.")
    and not (RemoteUrl startswith "localhost")
| project Timestamp, DeviceName, AccountName,
    RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## Validated Columns

- [ ] `DeviceProcessEvents.InitiatingProcessFileName` — confirm Claude Code binary name (`claude` on macOS/Linux; `claude.exe` on Windows)
- [ ] `DeviceNetworkEvents.RemoteUrl` — confirm column availability and format
- [ ] `DeviceFileEvents.FolderPath` — `.claude/` path location varies by OS; validate on test system

---

## Overall Recommendation

**Claude Code is permitted with mandatory controls for specific use cases in this environment.**

Unlike CoWork, Claude Code has a legitimate and high-value use case in your workflow — KQL development, detection engineering scripting, and vault automation. The risk is manageable when scoped correctly: trusted repositories only, no production credentials in scope, version pinned to ≥ 2.0.65, desktop computer use disabled, and no CI/CD integration.

The source code leak (March 2026) elevates the ongoing risk profile — threat actors now have a precision roadmap for future config-injection variants. Version discipline and repository trust hygiene are the primary ongoing controls.

**Highest-value permitted use:** KQL query iteration and detection engineering — prompt-only, no repository or filesystem access required. This is the lowest-risk, highest-value use case and should be the primary mode of operation for security engineering work.

---

## Comparison: Claude Code vs CoWork

| Dimension | Claude Code | CoWork |
|-----------|-------------|--------|
| Target user | Developer / analyst | Non-technical user |
| Execution model | Terminal (+ desktop April 2026) | VM + desktop (April 2026) |
| Audit trail | Partial (MDE telemetry) | None (explicitly excluded from Audit Logs) |
| CVE history | 2 CVEs — both patched | Shared architecture + day-2 exfiltration demo |
| Primary risk | Supply chain / repo config injection | Prompt injection → file exfiltration |
| CI/CD risk | Yes (PromptPwnd applies) | No (not designed for CI/CD) |
| Environment fit | ✅ Conditional | ❌ Not recommended |

---

## Related Notes

- [[Research/Articles/RESEARCH-Claude-CoWork-Risk-Profile]] — CoWork assessment
- [[Research/Articles/RESEARCH-OpenAI-Codex-Risk-Profile]] — Codex assessment
- [[Research/Tools/TOOL-claudit-sec-Claude-Desktop-MCP-Audit]] — MCP audit tooling
- [[Projects/WDAC-Deployment/]] — WDAC interaction with Claude Code execution model
- [[Projects/M365-Hardening/]] — credential governance relevant to API key risk

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-30 | Risk profile created |
