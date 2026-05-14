---
title: FIND-VSCode-Remote-Tunnels-Active-No-Policy-Control-2026-05-12
date: 2026-05-12
case_id:
alert_id:
severity: Medium
status: open
tags:
  - "#ir"
  - "#finding"
  - "#status/active"
  - "#endpoint"
  - "#cloud"
  - "#action-required"
---

# FIND — VS Code Remote Tunnels Active, No Policy Control (2026-05-12)

**Date:** 2026-05-12
**Analyst:** Dave
**Severity:** Medium
**Status:** Open

---

## Source

| Field | Value |
|-------|-------|
| **Alert / Signal** | Proactive hunt — VS Code tunnel activity investigation following Stop-Process detection tuning |
| **Platform** | MDE Advanced Hunting |
| **Affected Asset(s)** | lt12865, lt10297, lt13209, lt13389, lt12629, lt11966, lt10259 |
| **Affected User(s)** | dpavlaki, nchriste, mhabib, nbhan, glawson, admin-mrieger, mrieger, joishi |
| **Detection Time** | 2026-05-12 |
| **Triage Time** | 2026-05-12 |

---

## Observation

During tuning of a PowerShell `Stop-Process` detection query, `code-tunnel.exe` was identified as an existing exclusion. Investigation into the scope of VS Code Remote Tunnel activity across the estate returned 10 events of `code-tunnel.exe tunnel status` across 7 machines and 8 user accounts. The tunnel feature is installed and running on these hosts with no organisational policy controlling its use. A follow-on network connectivity query for outbound connections to `tunnels.api.visualstudio.com` returned 0 rows — no active tunnel sessions have been established.

---

## What VS Code Remote Tunnels Does

VS Code Remote Tunnels (`code-tunnel.exe`) allows a user to expose their local machine as a remote development environment accessible from any browser or VS Code client anywhere on the internet, authenticated via a Microsoft or GitHub account. The tunnel is established as a persistent outbound connection to Microsoft's relay infrastructure (`tunnels.api.visualstudio.com`, `global.rel.tunnels.api.visualstudio.com`) — it does not require any inbound firewall rules, bypassing perimeter controls entirely.

Once a tunnel is active, a remote party can:
- Open a full VS Code session in the remote machine's filesystem context
- Execute arbitrary code with the privileges of the account that established the tunnel
- Access any network resource reachable from the tunnelled host (internal shares, domain controllers, other endpoints)
- Read, write, copy, or exfiltrate any file accessible to that account
- Install extensions, modify configuration, or persist tooling on the host

The tunnel persists as a background service and survives reboots if registered as a service (`code-tunnel.exe service install`). Authentication is via Microsoft/GitHub OAuth — the tunnel owner's personal account controls access, outside of organisational Conditional Access policy unless specifically scoped.

**Risk in context of this environment:**

| Risk                | Detail                                                                                                                                                            |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Perimeter bypass    | Outbound tunnel to Microsoft relay requires no inbound port; bypasses firewall and network segmentation controls                                                  |
| CA policy bypass    | Tunnel access is authenticated to a personal Microsoft/GitHub account, not the Entra ID tenant — Conditional Access policies do not apply to tunnel sessions      |
| Credential exposure | If a tunnel is established under `admin-mrieger` (admin account confirmed active on lt13389), the remote party receives admin-level filesystem and network access |
| Data exfiltration   | Full filesystem access via tunnel provides a high-bandwidth exfiltration channel with no DLP visibility                                                           |
| Lateral movement    | Tunnel host has full access to internal network; a compromised tunnel session provides a pivot point into the environment                                         |
| Persistence         | `code-tunnel.exe service install` registers the tunnel as a persistent service surviving reboots — no ongoing user interaction required                           |
| Supply chain        | VS Code extension marketplace is a known supply chain risk; tunnel extensions installed by users are not vetted by the organisation                               |
| Account takeover    | If a user's personal GitHub or Microsoft account is compromised, the attacker gains tunnel access without any organisational authentication                       |

---

## Investigation Notes

### Hunt 1 — code-tunnel.exe execution

```kql
DeviceProcessEvents
| where FileName =~ "code-tunnel.exe" or FileName =~ "code.exe"
| where ProcessCommandLine has_any ("tunnel", "code-tunnel", "--tunnel")
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

**Result:** 10 rows. All `code-tunnel.exe tunnel status` spawned by `Code.exe` Node.js utility subprocess. Passive status checks confirming tunnel feature is installed and active. No active tunnel establishment commands observed.

| Device | Account | Command | Timestamp |
|--------|---------|---------|-----------|
| lt12865 | dpavlaki | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt12865 | dpavlaki | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt10297 | nchriste | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt10297 | nchriste | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt13209 | mhabib | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt13209 | nbhan | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt13389 | admin-mrieger | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt12629 | mrieger | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt11966 | glawson | `code-tunnel.exe tunnel status` | 2026-05-12 |
| lt10259 | joishi | `code-tunnel.exe tunnel status` | 2026-05-12 |

**Note:** `admin-mrieger` and `mrieger` appear to be the same individual using both a standard and admin account. The admin account running VS Code with the tunnel feature active is an elevated risk — see Actions.

### Hunt 2 — Tunnel service registration

```kql
DeviceRegistryEvents
| where RegistryKey has_any ("code-tunnel", "vscode-tunnel")
| project Timestamp, DeviceName, ActionType, RegistryKey,
    RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Result:** Not yet run — pending.

### Hunt 3 — Active tunnel network connectivity

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("code.exe", "code-tunnel.exe", "node.exe")
| where RemoteUrl has_any (
    "tunnels.api.visualstudio.com",
    "global.rel.tunnels.api.visualstudio.com"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Result:** 0 rows. No active tunnel sessions confirmed. Tunnel feature is installed and running but no outbound relay connections observed in the query window.

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-05-12 | Stop-Process detection tuning identifies code-tunnel.exe as existing exclusion |
| 2026-05-12 | Hunt 1 confirms tunnel feature active on 7 machines, 8 accounts |
| 2026-05-12 | Hunt 3 returns 0 rows — no active tunnel sessions in MDE window |
| | Hunt 2 (registry persistence check) — pending |

---

## Assessment

**Verdict:** Benign (current state) — Policy Gap (structural risk)

No active tunnel sessions have been established based on MDE network telemetry. The immediate threat is not confirmed exploitation but an uncontrolled feature providing a significant attack surface with no organisational visibility or policy enforcement. The risk is:

1. Any of the 8 affected users could establish an active tunnel at any time with no detection or alerting
2. `admin-mrieger` running the tunnel feature under an admin account represents a critical exposure if a tunnel is ever established
3. No Conditional Access, DLP, or network policy currently applies to tunnel sessions
4. The existing `code-tunnel.exe` exclusion in the Stop-Process detection was masking visibility into the scope of this activity

---

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic | Command and Control / Exfiltration |
| Technique | T1572 — Protocol Tunneling |
| Sub-technique | T1048 — Exfiltration Over Alternative Protocol |

---

## Actions Taken

- [x] Hunt 1 executed — tunnel feature confirmed active on 7 machines
- [x] Hunt 3 executed — no active sessions confirmed
- [ ] Hunt 2 — run registry persistence query to check for tunnel service registration
- [ ] **Policy decision required** — disable VS Code Remote Tunnels via Intune configuration profile or explicitly document approved use case with named users
- [ ] **Disable tunnel feature via VS Code policy** — push the following via Intune Settings Catalog or custom OMA-URI:
  ```json
  {
    "remote.tunnels.access.preventSleep": true,
    "remote-tunnels.access": "off"
  }
  ```
  Alternatively, blocklist `code-tunnel.exe` execution via Intune or WDAC
- [ ] **Address admin-mrieger / lt13389** — admin account should not be running VS Code interactively; review whether admin-mrieger is using the admin account for day-to-day work and remediate if so
- [ ] **Communicate to affected users** — if tunnels are not an approved use case, notify dpavlaki, nchriste, mhabib, nbhan, glawson, mrieger, joishi that the feature will be disabled
- [ ] **Remove code-tunnel.exe exclusion from Stop-Process detection** once policy control is confirmed — the exclusion was added to suppress noise but removes visibility into tunnel activity

---

## Escalate to Case?

- [ ] Yes — if Hunt 2 returns active tunnel service registrations, or if active tunnel sessions are confirmed
- [x] No — current state is policy gap, not active compromise. Track remediation via actions above

---

## Related Notes

- [[KQL-VSCode-Tunnel-Activity-Monitoring]] — detection stub if policy enforcement is deferred
- [[Hardening/Controls/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created — proactive hunt, no active sessions confirmed, policy gap identified |
