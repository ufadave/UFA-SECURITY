---
date: 2026-05-11
title: Linux SUID SGID chmod Detection
type: detection-response
detection_source: "KQL-Linux-SUID-SGID-chmod-Detection"
mitre:
  - "T1548.001"
tactic: "Privilege Escalation"
technique: "Setuid and Setgid"
severity_default: "High"
status: "Active"
tags:
  - "#playbook"
  - "#status/active"
  - "#endpoint"
  - "#ot-scada"
---

# Playbook -- Linux SUID SGID chmod Detection

---

## Purpose

Response procedure for alerts fired by `KQL-Linux-SUID-SGID-chmod-Detection`. The detection fires when `chmod` sets a SUID or SGID bit on any file or directory outside of a package manager context (dpkg postinst or RPM scriptlet). Package manager activity is excluded wholesale -- any remaining alert represents a runtime SUID/SGID change with no legitimate packaging explanation.

Primary threat context: post-exploitation persistence following Linux LPE. After achieving root via Dirty Frag (CVE-2026-43284/CVE-2026-43500) or similar, adversaries commonly set SUID on a backdoor binary to maintain root access across privilege drops.

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid |

---

## Step 1 -- Confirm the alert is not an exclusion gap

Before investigating, verify the event is not a legitimate package manager operation that slipped through a tuning gap.

| Check | Expected | Action |
|-------|---------|--------|
| `InitiatingProcessCommandLine startswith "/bin/sh /var/lib/dpkg/info/"` | dpkg postinst -- should be excluded | Tune query, close as benign |
| `InitiatingProcessCommandLine matches /bin/sh /var/tmp/rpm-tmp.*` | RPM scriptlet -- should be excluded | Tune query, close as benign |
| `InitiatingProcessCommandLine has_all ("sudo", "-S", "-k", "-p")` | Veeam agent -- should be excluded | Tune query, close as benign |

If it matches any of the above but still fired, add the specific pattern to the exclusion logic and document in the KQL note changelog.

---

## Step 2 -- Assess the chmod event itself

Review the alert fields directly before pivoting.

**What binary or directory had its permissions changed?**
- `ProcessCommandLine` contains the full `chmod` invocation including the target path
- A path under `/tmp`, `/dev/shm`, `/var/tmp`, or `/home/` is high suspicion -- legitimate SUID binaries live under `/usr/bin/`, `/usr/sbin/`, or `/usr/lib/`
- A UUID-named file (e.g. `/tmp/abc123...`) is immediately suspicious

**What set the SUID bit?**
- `InitiatingProcessFileName` and `InitiatingProcessCommandLine` -- what process ran `chmod`?
- `InitiatingProcessAccountName` -- who owns the initiating process?
- `InitiatingProcessParentFileName` -- what spawned the initiating process?

**Is there an interactive terminal?**
Check `AdditionalFields.InitiatingProcessPosixAttachedTerminal` in the raw event -- `/dev/pts/N` means an active interactive session.

---

## Step 3 -- Pivot on the target binary

The target path from `ProcessCommandLine` is the primary pivot. Pull all activity touching that path in the surrounding window.

```kql
// Replace TargetPath, AlertDevice, and AlertTime before running
let TargetPath = "/tmp/suspicious-binary";
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceFileEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 10m) .. (AlertTime + 10m))
| where FolderPath has TargetPath or FileName has TargetPath
| project Timestamp, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessAccountName,
    InitiatingProcessCommandLine, SHA256
| order by Timestamp asc
```

Key questions:
- Was the file written just before `chmod` was called? (`ActionType == "FileCreated"` immediately preceding the alert) -- classic dropper pattern: write binary, set SUID, execute
- What is the SHA256? Search in VirusTotal or your TI platform
- Was it executed after `chmod`?

```kql
let TargetFile = "suspicious-binary";
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceProcessEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 2m) .. (AlertTime + 15m))
| where FileName has TargetFile or ProcessCommandLine has TargetFile
| project Timestamp, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessAccountName, InitiatingProcessFileName
| order by Timestamp asc
```

---

## Step 4 -- Check what happened before the chmod

Work backwards. The SUID chmod is mid-chain -- something created the binary, something else will execute it. Pull full root process activity in the 10 minutes before the alert.

```kql
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceProcessEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 10m) .. (AlertTime + 5m))
| where AccountName == "root"
| project Timestamp, FileName, ProcessCommandLine,
    InitiatingProcessAccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

**Pre-chmod indicators that confirm exploitation:**

| Indicator | Significance |
|-----------|-------------|
| Execution from `/tmp`, `/dev/shm`, `/var/tmp` | Dropper / payload staging |
| `whoami`, `id`, `uname -a` in rapid succession | Post-exploit enumeration |
| Write to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | Credential or privilege persistence |
| New cron entry or systemd unit | Persistence mechanism |

---

## Step 5 -- Check for network activity

```kql
let AlertTime = datetime(YYYY-MM-DD HH:MM:SS);
let AlertDevice = "devicename";
DeviceNetworkEvents
| where DeviceName == AlertDevice
| where Timestamp between ((AlertTime - 5m) .. (AlertTime + 15m))
| where InitiatingProcessAccountName == "root"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Outbound connections on non-standard ports or to unexpected IPs following a SUID change is a strong C2 indicator.

---

## Step 6 -- OT/SCADA context check

If the alert fired on a host at the fertilizer plant:

- [ ] Confirm the host role -- HMI, historian, engineering workstation, or assessment tooling
- [ ] Verify kernel patch status for CVE-2026-43284/CVE-2026-43500 -- a SUID change on an unpatched host is a strong indicator of active Dirty Frag exploitation
- [ ] Check for any process activity touching PLC-connected interfaces or OT-facing network segments
- [ ] Notify OT asset owner before any containment action -- isolation of OT hosts may disrupt plant operations

---

## Step 7 -- Disposition

**Benign -- close**
Initiating process is a known administrative tool, target is a recognised system binary in a standard path, no surrounding suspicious activity. Document and close.

**Suspicious -- hold pending investigation**
Target path is unusual or initiating process is unexpected, but no confirmed post-exploitation activity. Engage asset owner. Keep open as a Finding note pending explanation.

**Confirmed malicious -- escalate to IR**

- [ ] Create `IR-` case note: [[IR-DFIR/Cases/]]
- [ ] Hash the target binary -- collect SHA256 from `DeviceFileEvents` or MDE file page
- [ ] Submit hash to VirusTotal or internal TI platform
- [ ] Isolate the host in MDE -- **confirm OT impact before isolating plant hosts** (see Step 6)
- [ ] Collect investigation package from MDE before isolation if time allows
- [ ] Identify the full attack chain -- how was root obtained? Cross-reference [[PLAYBOOK-Linux-Unprivileged-Process-Spawning-Root-Child]]
- [ ] Audit all other Linux hosts for the same binary hash or SUID change pattern
- [ ] Verify kernel patch status for CVE-2026-43284/CVE-2026-43500 across all Linux hosts
- [ ] Rotate credentials for any accounts active on the host in the surrounding window
- [ ] Notify management per IR communication plan

---

## Related Notes

- [[KQL-Linux-SUID-SGID-chmod-Detection]]
- [[KQL-Linux-Unprivileged-Process-Spawning-Root-Child]]
- [[PLAYBOOK-Linux-Unprivileged-Process-Spawning-Root-Child]]
- [[INTEL-Dirty-Frag-Linux-LPE-CVE-2026-43284-CVE-2026-43500]]
- [[OT-SCADA/Assets/]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-11 | Created |
