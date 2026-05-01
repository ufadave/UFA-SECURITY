---
title: RESEARCH-OpenAI-Codex-Risk-Profile
date: 2026-04-30
type: risk-assessment
tags:
  - "#resource"
  - "#cloud"
  - "#endpoint"
  - "#identity"
  - "#supply-chain"
  - "#status/review"
  - "#action-required"
  - "#exported"
---

# OpenAI Codex — Risk Profile for Environment Use

**Date:** 2026-04-30
**Analyst:** Security Operations
**Product:** OpenAI Codex (Cloud Agent + CLI + IDE Extensions)
**Current Version:** GPT-5.2-Codex (as of April 2026)
**Risk Rating:** 🔴 HIGH — conditional on controls

---

## What Codex Is (As of April 2026)

Codex began as an AI coding autocomplete tool (April 2025) and has crossed into full agentic territory as of the April 16, 2026 desktop release. It now operates as an autonomous agent that can:

- Write, edit, refactor, and test code across entire codebases
- Propose and create pull requests
- Run shell commands and interact with the filesystem
- Control the desktop (as of April 2026 update)
- Access GitHub repositories via OAuth tokens in sandboxed containers (Cloud mode)
- Execute tasks in parallel across multiple repositories

**Available surfaces:**
- Codex Cloud (ChatGPT web interface — sandboxed containers)
- Codex CLI (local execution, full system access)
- IDE extensions (VS Code, JetBrains, etc.)
- Desktop app (Windows, macOS — agentic desktop control)
- Codex Security (application security agent — research preview, March 2026)

This is not a suggestion engine. Codex takes real actions against real systems. The attack surface scales with the level of access granted.

---

## CVE and Vulnerability History

Codex has a material vulnerability track record for a product less than 12 months old. All three disclosed CVEs share a common root cause: **user-controllable input passed into shell execution without sanitisation**.

### CVE-2025-61260 — MCP Config Command Injection (Check Point, Aug 2025)
**Severity:** Critical
**Patched:** Codex CLI v0.23.0
**Attack vector:** Attacker with commit access to a repository adds a malicious `.codex/config.toml` and `.env` file. When any developer clones the repo and runs Codex, arbitrary shell commands execute silently — including reverse shells. No user interaction beyond normal workflow. An initially benign config can be swapped post-merge, creating a stealthy standing backdoor. CI/CD pipelines running Codex against new branches are automatically affected.

**Impact:** Full developer endpoint compromise, credential exfiltration, CI/CD pipeline backdoor, lateral movement.

### CVE-2026 (BeyondTrust Phantom Labs, Dec 2025) — GitHub Token Theft via Branch Name
**Severity:** Critical
**Patched:** February 5, 2026 (50+ days after disclosure)
**Attack vector:** Malicious commands embedded in a GitHub branch name. When Codex processed the branch during container setup, the unsanitised branch name was passed directly into shell scripts, executing the payload and exfiltrating the GitHub OAuth token. Automatable at scale — a single malicious branch in a shared repo fires on every Codex user who touches it, each yielding a fresh token. Short-lived tokens ≠ safe: a Codex task window is sufficient to clone repositories, read secrets from commit history, enumerate org structure, and modify workflow files.

**Impact:** GitHub OAuth token theft at scale, repository access, CI/CD pipeline compromise, downstream supply chain.

### AGENTS.md Indirect Injection (NVIDIA AI Red Team, April 2026)
**Severity:** Medium (requires compromised dependency as prerequisite)
**Patched:** Under review
**Attack vector:** A malicious dependency injects instructions into `AGENTS.md` — Codex's agent instruction file — that redirect the agent's behaviour. The agent follows injected configuration directives, including instructions to conceal its own actions. Even if the malicious PR looks benign, the agent can execute privileged actions in CI/CD pipelines, including writing to workflows, before the attack is detected.

**Impact:** Stealthy CI/CD compromise, supply chain backdoor, agent behaviour hijacking.

### PromptPwnd Class (Aikido Security, Dec 2025)
**Not a Codex-specific CVE — applies to Codex, Claude Code, Gemini CLI in CI/CD contexts**
Untrusted user input (PR descriptions, issue bodies, commit messages) injected into AI agent prompts, causing the agent to execute privileged actions. At least 5 Fortune 500 companies affected. Codex's default protection (only runs for users with write permissions) can be disabled — doing so creates a near-certain `$GITHUB_TOKEN` leak vector.

---

## Risk Assessment for This Environment

### Environment Profile
- E5 Microsoft tenant — MDE, Sentinel, Entra ID, Intune, MDO, MCAS
- Hybrid AD — Active Directory + Entra ID (Entra Connect)
- ~150 endpoints including POS terminals
- Recently acquired OT/SCADA plant — Rockwell/Allen-Bradley PLCs
- Active threat: Iranian APT (Handala/CL-STA-1128) targeting Entra ID and OT
- Active threat: Service principal abuse (CVE patched April 9, 2026)
- WDAC deployment in progress

### Risk Factors

| Risk | Rating | Notes |
|------|--------|-------|
| **Credential exposure via CLI** | 🔴 High | Codex CLI runs with full user-level access. Developer workstation typically holds cloud tokens, SSH keys, Entra credentials, MDE API keys. A compromised Codex session exfiltrates all of it. |
| **GitHub OAuth token theft** | 🔴 High | If GitHub is connected to Codex (Cloud or CLI), OAuth tokens are in scope for the branch-name injection class. Short-lived ≠ safe — window is sufficient for repo access and secrets exfiltration. |
| **Supply chain via shared repos** | 🔴 High | If any shared or open-source repositories are used in your environment, malicious `.codex/config.toml` injection is a standing risk unless repo access is tightly controlled. |
| **CI/CD pipeline compromise** | 🔴 High | If Codex is integrated into GitHub Actions or similar pipelines, PromptPwnd and branch-name injection classes apply. Write-permission default can be disabled, opening broad attack surface. |
| **WDAC bypass surface** | 🟡 Medium | Codex CLI executes arbitrary shell commands from AI-generated output. WDAC policies designed around known-good executables may need explicit rules for Codex's execution model. |
| **Prompt injection via codebase** | 🟡 Medium | Malicious content embedded in files Codex reads (comments, strings, config files) can inject instructions redirecting agent behaviour. In a security operations context, this applies to any code Codex touches that processes external input. |
| **Data exfiltration / DLP** | 🟡 Medium | Codex Cloud sends repository content to OpenAI infrastructure. Data residency for Canadian organisations is not explicitly documented. For code containing sensitive logic, credentials, or configuration — this is a DLP concern. |
| **OT/SCADA adjacency** | 🟡 Medium | Not a direct risk — Codex does not connect to OT systems. Indirect risk: if Codex is used on workstations with network access to the OT network and the CLI is compromised, it becomes a lateral movement staging point. |
| **Desktop control (April 2026)** | 🟡 Medium | The April 16 desktop update enables full desktop control. On a workstation with access to Sentinel, MDE, Entra, and Intune portals, a compromised Codex Desktop session is a significant privilege escalation path. |
| **Insider / accidental data exposure** | 🟡 Medium | Developers (or security analysts using Codex) may inadvertently paste sensitive configuration, credentials, or internal architecture into Codex prompts — sent to OpenAI infrastructure. |

---

## Use Case Analysis

### Permitted — Low Risk with Controls
| Use Case | Risk | Controls Required |
|----------|------|-------------------|
| Codex Cloud for personal/isolated code projects | Low | No sensitive repos; no credential-bearing config files |
| KQL query development assistance | Low | No codebase access; prompt-only use |
| Codex Security (vulnerability scanning) | Low-Medium | Sandbox environment only; review findings before actioning |

### Conditional — Requires Governance
| Use Case | Risk | Controls Required |
|----------|------|-------------------|
| Codex CLI on managed workstation | Medium | Pinned version ≥ 0.23.0; WDAC rules reviewed; no production credential access |
| Codex integrated into internal repositories | Medium-High | Repository access controls audited; no `.codex/` config from untrusted contributors; branch protection enforced |
| Codex for security tooling development | Medium-High | Isolated dev environment; no production MDE/Sentinel API keys in scope |

### Not Recommended
| Use Case | Risk | Notes |
|----------|------|-------|
| Codex CLI on workstations with OT network access | High | Compromised CLI is a lateral movement staging point toward OT |
| Codex in CI/CD pipelines without write-permission enforcement | Critical | PromptPwnd class — near-certain `$GITHUB_TOKEN` leak if misconfigured |
| Codex Desktop with Entra/MDE/Intune portal access open | High | Desktop control agent + privileged portal access = significant blast radius |
| Codex with production credentials in environment | Critical | Any production token in the shell environment is in scope for credential theft |

---

## Controls Required for Permitted Use

If Codex is approved for use in your environment, the following controls are non-negotiable:

- [ ] **Version pinning** — Codex CLI must be pinned to ≥ 0.23.0 and updated promptly on new CVE disclosures. Track via MDE software inventory.
- [ ] **No production credentials in Codex environments** — enforce via policy. Codex sessions must not have access to production MDE API keys, Entra service principal secrets, or GitHub tokens with org-level scope.
- [ ] **Repository access controls** — if Codex connects to GitHub, apply branch protection rules and restrict who can commit `.codex/` config files. Treat `.codex/config.toml` as a security-sensitive file.
- [ ] **Write-permission enforcement in CI/CD** — if Codex is integrated into any pipeline, confirm write-permission gating is enabled and has not been disabled.
- [ ] **WDAC review** — audit WDAC policies for Codex CLI execution model. Codex spawns child processes dynamically; confirm policies accommodate this without creating blanket allow rules.
- [ ] **Data residency assessment** — confirm where Codex Cloud processes and stores repository content before connecting any sensitive codebase. Canadian data residency status is unconfirmed.
- [ ] **Workstation segmentation** — Codex CLI must not be used on workstations with direct network access to the OT/SCADA network.
- [ ] **claudit-sec audit** — run `claudit-sec` after any Codex CLI installation to verify MCP server configuration and permissions (see `TOOL-claudit-sec-Claude-Desktop-MCP-Audit`).

---

## Detection Recommendations

### KQL — Codex CLI Execution on Managed Endpoints

```kql
// Hunt: Codex CLI execution on managed endpoints
// Schema: Advanced Hunting (MDE)
// Tables: DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "codex.exe"
    or ProcessCommandLine has "codex"
    and InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe")
| where FileName !in~ ("vscodex.exe") // exclude VS Code if needed
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
```

### KQL — Suspicious Child Processes Spawned by Codex

```kql
// Hunt: Unexpected child processes from Codex CLI - potential command injection
// Schema: Advanced Hunting (MDE)
// Tables: DeviceProcessEvents
DeviceProcessEvents
| where InitiatingProcessFileName =~ "codex.exe"
    or InitiatingProcessCommandLine has "codex"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash.exe", "sh.exe", "wscript.exe", "cscript.exe",
    "curl.exe", "wget.exe", "certutil.exe", "mshta.exe"
    )
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### KQL — Codex Config File Creation / Modification

```kql
// Hunt: .codex/config.toml created or modified - supply chain injection indicator
// Schema: Advanced Hunting (MDE)
// Tables: DeviceFileEvents
DeviceFileEvents
| where FileName =~ "config.toml"
| where FolderPath has ".codex"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, AccountName,
    FolderPath, FileName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## Validated Columns

- [ ] `DeviceProcessEvents.FileName` — confirm `codex.exe` is the correct binary name for CLI on Windows; macOS binary name may differ
- [ ] `DeviceFileEvents.FolderPath` — `.codex` path varies by OS; validate on a test system

---

## Overall Recommendation

**Codex is not recommended for unrestricted use in this environment at this time.**

The combination of a material CVE track record (3 significant disclosures in under 12 months), the active Iranian APT threat targeting your Entra ID and service principal attack surface, the ongoing WDAC deployment, and the OT/SCADA adjacency creates an elevated risk profile that current controls do not fully address.

**Codex Security** (the vulnerability scanning variant, research preview) warrants evaluation as a lower-risk use case — sandboxed, read-only scanning posture, directly relevant to your security engineering workflow. If you want to evaluate it, do so in an isolated environment without production credentials.

**Codex Cloud for personal isolated projects** (no sensitive repos, no credential exposure) is a lower-risk use case and can proceed with awareness of data residency concerns.

Revisit full deployment approval once: WDAC deployment is complete, the data residency question is answered, and a formal AI tooling governance policy is in place.

---

## Related Notes

- [[Research/Articles/INFO-OpenAI-Cybersecurity-Intelligence-Age-Action-Plan]] — OpenAI TAC programme context
- [[Research/Vendors/VENDOR-Novee-AI-Pentest-Evaluation]] — AI security tooling context
- [[Projects/WDAC-Deployment/]] — WDAC controls relevant to Codex CLI
- [[Projects/M365-Hardening/]] — Service principal and OAuth scope governance
- [[Research/Tools/TOOL-claudit-sec-Claude-Desktop-MCP-Audit]] — MCP audit tooling

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-30 | Risk profile created |
