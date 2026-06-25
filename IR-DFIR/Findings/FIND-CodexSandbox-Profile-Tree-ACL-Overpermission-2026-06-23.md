---
title: "FIND-CodexSandbox-Profile-Tree-ACL-Overpermission-2026-06-23"
date: 2026-06-23
case_id: 
alert_id: 
severity: Medium
status: open
tags:
  - "#ir"
  - "#finding"
  - "#status/draft"
  - "#endpoint"
  - "#cloud"
  - "#supply-chain"
  - "#action-required"
---

# FIND — Codex Windows Sandbox: Overpermissive Profile Tree ACL Grant

**Date:** 2026-06-23
**Analyst:** Dave
**Severity:** Medium
**Status:** Open

---

## Source

| Field | Value |
|-------|-------|
| Alert / Signal | MDE Custom Detection — PowerShell with Start-Sleep spawned by `codex-command-runner-0.142.0.exe` as `codexsandboxoffline` |
| Platform | MDE |
| Affected Asset(s) | lt10263 (agyori), lt12582 (bsmistad) |
| Affected User(s) | agyori, bret.smistad@ufa.com |
| Detection Time | 2026-06-23 11:07 AM (lt10263); 2026-06-22 3:33 PM (lt12582) |
| Triage Time | 2026-06-23 |

---

## Observation

MDE custom detection fired on PowerShell processes containing `Start-Sleep` spawned by the Codex Windows sandbox runner. Investigation confirmed both events are legitimate Codex agentic activity — Codex CLI/desktop app running in native Windows sandbox mode on developer laptops. The initiating process identity (`codexsandboxoffline`) led to review of the Codex Windows sandbox architecture, which revealed a material security concern: Codex grants `CodexSandboxOffline` and `CodexSandboxOnline` ACL read permissions across the **entire user profile tree** (`C:\Users\<user>\`) rather than scoping access to the active workspace only. This is documented in GitHub issue [#12343](https://github.com/openai/codex/issues/12343) and is a known, unfixed behaviour.

Two users are confirmed running Codex on managed endpoints. A third concern is that `bret.smistad` (lt12582) is running via `codex.exe app-server` mode under his own identity rather than the `codexsandboxoffline` token — suggesting the sandbox may not be fully initialised on that device.

---

## Investigation Notes

### Codex Sandbox Architecture (Windows)

When Codex installs on Windows, it creates two local user accounts:
- `CodexSandboxOffline` — targeted by WFP/Windows Firewall rules to block all outbound network access
- `CodexSandboxOnline` — permitted network access

Child processes spawned by `codex-command-runner.exe` run under restricted tokens associated with these identities (WRITE_RESTRICTED). This is the expected execution model and provides meaningful write isolation.

**The gap:** To allow Codex to read files as the real user would, the sandbox setup process grants `CodexSandboxOffline` and `CodexSandboxOnline` **read ACLs on the full user profile directory**, not just the active workspace. This is by design per OpenAI's sandbox writeup but is broader than the principle of least privilege requires.

### Exposure Surface on Affected Devices

Developer profile directories on managed endpoints typically contain:

| Location | Contents |
|----------|----------|
| `~\.ssh\` | SSH private keys |
| `~\.azure\` | Azure CLI cached tokens |
| `~\.gitconfig` + credential helpers | Git credentials |
| `~\AppData\Local\Microsoft\Edge\User Data\` | Edge credential store (see INTEL note on Edge cleartext passwords) |
| `~\.codex\` | Codex config, any stored tokens |
| `~\AppData\Roaming\Microsoft\Credentials\` | DPAPI-protected Windows credential blobs |

A compromised command executing under `CodexSandboxOffline` could read all of the above. The restricted write token limits damage to the file system but does not limit reads from the profile tree.

### Stale SID Residue

On uninstall, `CodexSandboxOffline` and `CodexSandboxOnline` local accounts are removed but orphaned SIDs remain in ACL entries on the profile tree. This complicates forensic ACL audits and may persist indefinitely without manual remediation.

### lt12582 — Sandbox Identity Anomaly

`bret.smistad` (lt12582) initiated PowerShell from `codex.exe` app-server mode running under his own identity, not `codexsandboxoffline`. This may indicate:
- Sandbox setup did not complete successfully (missing elevation / UAC not completed)
- Running in an unelevated sandbox fallback mode
- Sandbox deliberately bypassed (e.g. `--dangerously-bypass-approvals-and-sandbox` / `--yolo` flag)

Requires investigation on lt12582 to confirm sandbox status.

### Detection Rule — Exclusion Gap

The triggering custom detection excludes `codex-command-runner.exe` by exact filename, but the actual binary is versioned (`codex-command-runner-0.142.0.exe`). The exclusion is not firing. Requires update to `startswith` match.

### KQL Pivots

```kql
// Confirm CodexSandboxUsers local group membership and sandbox account presence
// Table: DeviceEvents — Schema: Advanced Hunting (MDE)
DeviceEvents
| where ActionType == "UserAccountCreated"
| where AccountName has_any ("CodexSandboxOffline", "CodexSandboxOnline")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName
```

```kql
// Identify all processes running as codexsandboxoffline or codexsandboxonline
// Table: DeviceProcessEvents — Schema: Advanced Hunting (MDE)
DeviceProcessEvents
| where InitiatingProcessAccountName has_any ("codexsandboxoffline", "codexsandboxonline")
    or AccountName has_any ("codexsandboxoffline", "codexsandboxonline")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

```kql
// Check for network activity attributed to CodexSandboxOffline (should be zero — firewall blocks)
// Table: DeviceNetworkEvents — Schema: Advanced Hunting (MDE)
DeviceNetworkEvents
| where InitiatingProcessAccountName =~ "codexsandboxoffline"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// Identify all devices with codex-command-runner in process history (fleet-wide scope)
// Table: DeviceProcessEvents — Schema: Advanced Hunting (MDE)
DeviceProcessEvents
| where InitiatingProcessFileName startswith "codex-command-runner"
    or FileName startswith "codex-command-runner"
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Users = make_set(InitiatingProcessAccountName)
    by DeviceName, InitiatingProcessFileName
| sort by LastSeen desc
```

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-06-22 15:33 | lt12582 — PowerShell Start-Sleep 60s spawned by `codex.exe` as `bsmistad` |
| 2026-06-23 11:07 | lt10263 — PowerShell Start-Sleep 10s + Get-Process dotnet spawned by `codex-command-runner-0.142.0.exe` as `codexsandboxoffline` |
| 2026-06-23 | Triage — identified CodexSandbox profile tree ACL issue via GitHub #12343 |

---

## Assessment

**Verdict:** Benign (process activity) / Finding (structural security concern)

The individual process events are expected Codex agentic behaviour — not malicious. The finding is the underlying sandbox architecture: overpermissive profile tree ACL grant creates a meaningful read attack surface on developer endpoints if a compromised prompt or supply-chain payload executes under the sandbox identity. Combined with the known Edge cleartext credential exposure (see related notes), a credential sweep from `codexsandboxoffline` is a credible attack path. Not exploited; requires remediation and governance controls.

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | Credential Access, Collection |
| Technique | T1552 — Unsecured Credentials |
| Sub-technique | T1552.001 — Credentials In Files |

---

## Actions Taken

- [ ] Audit ACLs on `C:\Users\agyori\` and `C:\Users\bsmistad\` for `CodexSandboxOffline` / `CodexSandboxOnline` / `CodexSandboxUsers` group entries
- [ ] Investigate lt12582 — confirm whether sandbox is properly initialised (sandbox identity should be `codexsandboxoffline`, not `bsmistad`)
- [ ] Run fleet-wide KQL to identify any additional devices with Codex installed beyond lt10263 and lt12582
- [ ] Update custom detection exclusion: change `InitiatingProcessFileName != "codex-command-runner.exe"` to `not(InitiatingProcessFileName startswith "codex-command-runner")`
- [ ] Confirm Codex version across affected devices (lt10263 confirmed 0.142.0 — compliant with ≥ 0.23.0 requirement per risk profile)
- [ ] Confirm both users are covered under AI AUP acknowledgement before next policy review cycle
- [ ] Review `RESEARCH-OpenAI-Codex-Risk-Profile` for any remediation guidance on profile tree ACL scope — consider raising with OpenAI as a governance gap if no workaround exists
- [ ] Flag to developers: do not store production API keys, Entra service principal secrets, or SSH keys in user profile paths while Codex is installed and active

---

## Escalate to Case?

- [ ] Yes — create `IR-` case note: [[]]
- [x] No — treating as governance finding; escalate only if lt12582 sandbox bypass is confirmed or network activity detected from `codexsandboxoffline`

---

## Related Notes

- [[RESEARCH-OpenAI-Codex-Risk-Profile]]
- [[INTEL-MS-Edge-Cleartext-Passwords-Process-Memory]]
- [[FIND-ChatGPT-Tenant-Wide-Admin-Consent-Mail-Teams-Read-2026-04-23]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-23 | Finding created — triage of Codex sandbox alert on lt10263 and lt12582 |
