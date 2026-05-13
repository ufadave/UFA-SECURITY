---
date: 2026-05-13
title: Linux Kernel Module Alert Triage
type: playbook
status: Active
trigger: "MDE Custom Detection — Linux Kernel Module Anomaly DirtyFrag"
mitre:
  - "T1215"
  - "T1068"
tags:
  - "#ir"
  - "#status/active"
  - "#endpoint"
---

# Playbook — Linux Kernel Module Alert Triage

**Trigger:** MDE Custom Detection alert — `Linux Kernel Module Anomaly DirtyFrag`
**Scope:** Linux hosts with MDE agent; `modprobe`, `insmod`, or `rmmod` targeting `esp4`, `esp6`, `rxrpc`, or `xfrm`
**Primary MITRE:** T1215 — Kernel Modules and Extensions | T1068 — Exploitation for Privilege Escalation
**Related Detection:** [[RULE-Linux-Kernel-Module-Anomaly-DirtyFrag]]
**Related Hunt:** [[HUNTING-Linux-Unexpected-Privilege-Escalation]]

---

## Step 1 — Initial Triage (< 5 minutes)

### 1.1 — Identify the operation direction

This is the single most important question. Pull `FileName` and `ProcessCommandLine` from the alert.

| Binary | Module arg | Meaning | Severity |
|--------|-----------|---------|----------|
| `rmmod` | `esp4` / `esp6` / `rxrpc` | Mitigation being applied — unloading vulnerable module | Low unless timing/account is unexpected |
| `modprobe` / `insmod` | `esp4` / `esp6` / `rxrpc` | Module being **loaded** — re-enabling vulnerable code path | **High — treat as hostile until confirmed otherwise** |
| Any | `xfrm` | IPsec transform framework manipulation | Medium — context-dependent, see Step 1.3 |

> **If the operation is a load (`modprobe` or `insmod`) on a host where the module was previously removed: isolate immediately and skip to Step 3.**

### 1.2 — Check account and timing

- Is the `AccountName` a known admin for this host?
- Is the timestamp within business hours or a known maintenance window?
- Is there a change ticket covering this host today?

If all three are yes and the operation is `rmmod` (unload/mitigation): likely a sysadmin applying Dirty Frag mitigation. Confirm with the admin and close. Document in the case note.

If any answer is no: continue to Step 2.

### 1.3 — `xfrm` context check

`xfrm` is the IPsec transform framework. Manipulation without accompanying `esp4`/`esp6` context warrants additional checks:

- Does the host run VPN or IPsec tunnel configuration?
- Is the command consistent with VPN maintenance (e.g. restarting strongSwan or similar)?

If no VPN context exists and `xfrm` is being manipulated: treat as suspicious and continue to Step 2.

---

## Step 2 — Pivot Investigation

Run these queries in MDE Advanced Hunting. Scope each to the affected `DeviceName` and a window of **T-30 minutes to T+15 minutes** around the alert timestamp.

### 2.1 — Process tree — what ran before the module event?

```kql
// Scope: affected host, 30 min before alert
DeviceProcessEvents
| where DeviceName == "<affected-host>"
| where Timestamp between (datetime(<alert-time> - 30min) .. datetime(<alert-time> + 5min))
| project Timestamp, AccountName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Look for:**
- Unexpected shell spawn from a non-shell parent (web process, backup agent, interpreter)
- `chmod`, `cp`, or `touch` targeting `/tmp` — binary staging pattern (seen with Veeam; also common post-exploitation)
- `whoami`, `id`, `uname -m` — reconnaissance commands preceding escalation
- Any process chain leading to `modprobe`/`insmod` that doesn't originate from an interactive admin shell

### 2.2 — Privilege escalation signal — did the LPE detection also fire?

```kql
// Check if the hunting query signal is present on this host
let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceName;
DeviceProcessEvents
| where DeviceName == "<affected-host>"
| where Timestamp between (datetime(<alert-time> - 60min) .. datetime(<alert-time>))
| where AccountName == "root"
| where InitiatingProcessAccountName != "root"
    and InitiatingProcessAccountName != ""
| where InitiatingProcessFileName !in~ (
    "sudo", "su", "pkexec", "doas",
    "solarwinds.adm.agentplugin",
    "solarwinds.agent.jobengine.plugin",
    "solarwinds.agent.discovery.plugin"
)
| where not (
    InitiatingProcessAccountName in~ ("veeamazure", "localadmin")
    and ProcessCommandLine has_any ("veeam", "VeeamApp", "veeamagentconfig")
)
| project Timestamp, AccountName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

> If this query returns results in the window before the module event, you likely have an LPE sequence followed by module manipulation. Escalate to Step 3.

### 2.3 — Remote logons — was anyone on the box?

```kql
DeviceLogonEvents
| where DeviceName == "<affected-host>"
| where Timestamp between (datetime(<alert-time> - 60min) .. datetime(<alert-time> + 15min))
| project Timestamp, ActionType, LogonType, AccountName,
    InitiatingProcessAccountName, InitiatingProcessFileName,
    RemoteIP, RemoteDeviceName
| order by Timestamp asc
```

**Look for:**
- xrdp sessions (initiating process `xrdp-sesman`) — interactive GUI session on the host
- SSH logons from unexpected source IPs
- Logon from an account that doesn't match the process tree account

### 2.4 — Network activity — any outbound connections?

```kql
DeviceNetworkEvents
| where DeviceName == "<affected-host>"
| where Timestamp between (datetime(<alert-time> - 30min) .. datetime(<alert-time> + 15min))
| where RemoteIPType != "Private"
| project Timestamp, ActionType, InitiatingProcessAccountName,
    InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

**Look for:**
- Outbound connections to public IPs from unexpected processes (especially interpreters, shells, or `/tmp`-resident binaries)
- C2 beacon patterns — regular short-interval connections
- DNS lookups to unusual domains immediately preceding or following the module event

---

## Step 3 — Containment

> **Trigger Step 3 if any of the following are true:**
> - Module is being **loaded** (`modprobe`/`insmod`) on a host where it was previously unloaded
> - LPE signal (Step 2.2) is present before the module event
> - Unexpected initiating process in the module event (not a known admin shell)
> - Outbound connection to public IP from an unusual process in the window
> - Account does not match any known admin for the host

### 3.1 — Isolate the host

Isolate via MDE (the rule is set to Alert only — this must be done manually):

MDE Portal → Device page → **Isolate device**

Document isolation timestamp in the case note.

### 3.2 — Preserve volatile state

If the host can be accessed before isolation completes, or via an out-of-band management channel:

```bash
# Capture running processes
ps auxf > /tmp/ir-ps-$(date +%Y%m%d%H%M%S).txt

# Capture loaded kernel modules
lsmod > /tmp/ir-lsmod-$(date +%Y%m%d%H%M%S).txt

# Capture active network connections
ss -tulnp > /tmp/ir-netstat-$(date +%Y%m%d%H%M%S).txt

# Capture current logged-in users
who > /tmp/ir-who-$(date +%Y%m%d%H%M%S).txt
last -20 >> /tmp/ir-who-$(date +%Y%m%d%H%M%S).txt
```

Retrieve these files before rebooting or reimaging.

### 3.3 — Open a case note

Create an `IR-` case note: [[]]

Populate:
- Affected host, `AccountName`, alert timestamp
- Operation direction (load vs unload)
- Results of Steps 2.1–2.4
- Isolation timestamp

### 3.4 — SAP HANA hosts — additional considerations

`saphdb1`, `saphdb3b`, and any other HANA hosts are production database systems. Isolation will impact SAP availability. Before isolating a HANA host:

- Notify the SAP DBA immediately — do not isolate without notification unless active exploitation is confirmed
- Determine whether the HANA instance can be gracefully shut down before isolation
- Confirm whether the host is part of an HA pair — if so, identify the standby node status before pulling the primary

---

## Step 4 — Escalation Criteria

| Condition | Action |
|-----------|--------|
| Module load confirmed on a previously mitigated host | Treat as active exploitation — escalate to senior analyst / management immediately |
| LPE signal + module manipulation on same host within 60 min | Treat as confirmed TTP chain — open major incident |
| Outbound C2 pattern identified | Treat as active intrusion — open major incident |
| SAP HANA host involved | Notify SAP DBA and management regardless of verdict |
| No suspicious context found — unload by known admin | Close as FP; document admin and change ticket reference |

---

## Step 5 — Post-Incident

- [ ] Confirm whether all Linux hosts have had `esp4`, `esp6`, `rxrpc` unloaded as mitigation
- [ ] Verify kernel version on affected host — confirm whether it falls within the Dirty Frag vulnerable range
- [ ] Review `lsmod` output (if captured) for any other unexpected modules
- [ ] Update SAP HANA host asset notes with any new `{SID}adm` accounts discovered during investigation — add to hunting query exclusions: [[HUNTING-Linux-Unexpected-Privilege-Escalation]]
- [ ] If FP: document account and context in this playbook's Known FP Baseline section below

---

## Known FP Baseline

Document confirmed false positive patterns here as they are encountered. Use this to fast-path triage on repeat patterns.

| Date | Host | Account | Context | Disposition |
|------|------|---------|---------|-------------|
| | | | | |

---

## Related Notes

- [[RULE-Linux-Kernel-Module-Anomaly-DirtyFrag]]
- [[HUNTING-Linux-Unexpected-Privilege-Escalation]]
- [[HUNTING-Linux-SUID-Binary-Execution]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-13 | Created — first Linux IR playbook; covers Dirty Frag kernel module alert triage |
