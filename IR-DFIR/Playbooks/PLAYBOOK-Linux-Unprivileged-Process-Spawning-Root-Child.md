---
date: 2026-05-11
title: Linux Unprivileged Process Spawning Root Child
type: detection-response
detection_source: "KQL-Linux-Unprivileged-Process-Spawning-Root-Child"
mitre:
  - "T1068"
  - "T1611"
severity_default: "High"
status: "Active"
tags:
  - "#playbook"
  - "#status/active"
  - "#endpoint"
  - "#ot-scada"
---

# Playbook — Linux Unprivileged Process Spawning Root Child

---

## Purpose

Response procedure for alerts fired by `KQL-Linux-Unprivileged-Process-Spawning-Root-Child`. The detection surfaces Linux process events where `AccountName == "root"` but `InitiatingProcessAccountName` is a non-root, non-service-account user — indicating a non-privileged process has spawned a root-level child without going through an expected escalation path (`sudo`, `su`, `pkexec`).

Primary threat context: post-exploitation privilege escalation consistent with Dirty Frag (CVE-2026-43284 / CVE-2026-43500) or similar Linux LPE techniques. Direct relevance to OT/SCADA Linux hosts at the fertilizer plant.

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1068 | Exploitation for Privilege Escalation |
| T1611 | Escape to Host |

---

## Step 1 — Confirm the alert is not an exclusion gap

Before any investigation, verify the alert didn't slip through a tuning gap. Compare `InitiatingProcessAccountName`, `InitiatingProcessCommandLine`, and `InitiatingProcessParentFileName` against the known exclusion list below.

| Pattern | Expected Behaviour | Action |
|---------|-------------------|--------|
| `InitiatingProcessCommandLine == "-bash"` and `FileName == "bash"` | Veeam Linux agent opening nightly root login shell session on `ufaut220` | Tune query, close as benign |
| `InitiatingProcessCommandLine has_all ("sudo", "-S", "-k", "-p")` | Veeam agent sudo command invocations | Tune query, close as benign |
| `InitiatingProcessAccountName == "hd4adm"` and `FileName == "systemd"` | SAP HANA admin service spawning systemd user session on `saphdb4a` | Tune query, close as benign |
| `InitiatingProcessFileName == "smbd"` and `InitiatingProcessAccountName == "nobody"` | Samba worker process fork — normal privilege separation | Tune query, close as benign |
| `InitiatingProcessFileName in ("apt","apt-get","dpkg","yum","dnf","rpm")` | Package manager running as root child of sudo | Tune query, close as benign |

If it matches a known exclusion pattern, document it in the query changelog and close. If it's a new recurring pattern from a known-legitimate source, evaluate whether it warrants a new exclusion entry.

---

## Step 2 — Characterise the initiating process

The initiating process is the primary pivot. A root child spawned by `localadmin` running `-bash` at 11:30 PM nightly is Veeam. A root child spawned by `jsmith` running `python3` at 14:00 on a workday is a different investigation.

Answer these questions before proceeding:

**Who initiated it?**
- Is `InitiatingProcessAccountName` a service account or a named human account?
- Is the account expected to be active on this host?
- Is the time of activity consistent with normal use?

**What spawned it?**
- `InitiatingProcessParentFileName == "sshd"` → interactive SSH session; someone is logged in
- `InitiatingProcessParentFileName == "bash"` → shell chain; look further up the tree
- `InitiatingProcessParentFileName == <daemon>` → spawned by a service; assess the service

**Is there an interactive terminal attached?**

Check `AdditionalFields.InitiatingProcessPosixAttachedTerminal` in the raw event. A value of `/dev/pts/N` means an interactive pseudo-terminal is attached — a human or tool with an active session. No terminal means fully automated.

**What did the initiating process run?**

Review `InitiatingProcessCommandLine` in full. Does it look like tooling, a scheduled job, or something ad hoc and unexpected?

---

## Step 3 — Pivot on post-escalation activity

If Step 2 doesn't explain the alert, pull all root process activity on the host in the window around the alert. Post-LPE activity typically follows within minutes.

```kql
// Replace AlertTime and AlertDevice before running
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceProcessEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 5m) .. (AlertTime + 15m))
| where AccountName == "root"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**High-signal post-LPE indicators to look for:**

| Indicator | Significance |
|-----------|-------------|
| Read of `/etc/shadow`, `/etc/passwd` | Credential harvesting |
| Write or execute from `/tmp`, `/dev/shm`, `/var/tmp` | Dropper / payload staging |
| `chmod u+s` or `chmod 4755` on any binary | SUID persistence |
| New entry in `/etc/cron*`, `/etc/systemd/system/`, `~/.bashrc`, `~/.profile` | Persistence mechanism |
| Write to `~/.ssh/authorized_keys` | SSH backdoor |
| Execution of `nc`, `ncat`, `socat`, `curl`, `wget` | C2 connectivity / exfil |
| `whoami`, `id`, `uname -a`, `hostname` in rapid sequence | Post-exploit enumeration |

> **Dirty Frag note:** This exploit operates entirely in page cache — no on-disk file modification occurs during privilege escalation itself. Filesystem integrity monitoring will not catch the LPE step. Focus detection on post-escalation process activity, not file writes.

---

## Step 4 — Check for persistence and lateral movement

If Step 3 surfaces suspicious activity, broaden the scope to file and network events.

**File events — persistence locations:**

```kql
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceFileEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 2m) .. (AlertTime + 15m))
| where InitiatingProcessAccountName == "root" or AccountName == "root"
| where FolderPath has_any (
    "/tmp", "/dev/shm", "/var/tmp",
    "/etc/cron", "/etc/systemd",
    "/.ssh", "/etc/passwd", "/etc/shadow",
    "/root/.bashrc", "/root/.profile"
)
| project Timestamp, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Network events — outbound from root process:**

```kql
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceNetworkEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 2m) .. (AlertTime + 15m))
| where InitiatingProcessAccountName == "root"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Lateral movement — check for outbound SSH or new connections from the host:**

```kql
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceNetworkEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 2m) .. (AlertTime + 30m))
| where RemotePort in (22, 23, 3389, 445, 5985, 5986)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName,
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## Step 5 — OT/SCADA context check

If the alert fired on a host at the fertilizer plant, apply additional scrutiny regardless of Step 2 findings:

- [ ] Confirm the host's role — HMI, historian, engineering workstation, or assessment tooling (Nmap/OpenVAS)
- [ ] Verify kernel patch status for CVE-2026-43284 / CVE-2026-43500 — patch is not confirmed applied until the host is audited
- [ ] Check for any recent changes to PLC-connected processes or OT-facing network connections
- [ ] Confirm MDE for Linux agent is active and reporting — alert may represent degraded coverage if agent was recently installed
- [ ] Notify OT asset owner before any containment action — unilateral isolation of an OT host may disrupt industrial processes

---

## Step 6 — Disposition

**Benign — close**
The process chain is explainable: legitimate admin activity, known tooling, scheduled job with a new pattern not yet in the exclusion list. Document the finding, add an exclusion to the KQL note if it's recurring, and close.

**Suspicious — hold pending investigation**
Unusual account, unusual time, no clear business justification, but no confirmed post-LPE activity. Engage the asset owner to confirm whether the activity is expected. Treat as suspicious until explained. Do not close — keep open as a Finding note.

**Confirmed malicious — escalate to IR**

- [ ] Create `IR-` case note: [[IR-DFIR/Cases/]]
- [ ] Isolate the host in MDE (Defender XDR → Device page → Isolate device) — **confirm OT impact before isolating plant hosts** (see Step 5)
- [ ] Collect investigation package from MDE before isolation if time allows
- [ ] Preserve volatile state if accessible: running processes, active network connections, mounted filesystems
- [ ] Identify the initial access vector — how did the unprivileged account get a foothold?
- [ ] Assess lateral movement risk — was the account used on other Linux hosts?
- [ ] Rotate credentials for the affected account
- [ ] Verify kernel patch status for CVE-2026-43284/CVE-2026-43500 across all Linux hosts in the estate
- [ ] Notify management per IR communication plan

---

## Related Notes

- [[KQL-Linux-Unprivileged-Process-Spawning-Root-Child]]
- [[INTEL-Dirty-Frag-Linux-LPE-CVE-2026-43284-CVE-2026-43500]]
- [[OT-SCADA/Assets/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-11 | Created — initial version based on query tuning session and Dirty Frag intel note |
