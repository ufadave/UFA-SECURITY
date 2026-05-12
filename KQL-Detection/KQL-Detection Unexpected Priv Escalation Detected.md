---
date: 2026-05-11
title: KQL-Detection Unexpected Priv Escalation Detected
table: DeviceProcessEvents joined to DeviceInfo
schema: MDE
mitre: ""
tactic: Privledge Excalation
technique: T1068,T1611
status: deployed
promoted_to_rule: true
mde_rule_id: Custom Detection Unexpected Priv Escalation Detected
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#status/active"
---

# KQL — Custom Detection Unexpected Priv Escalation Detected

---

**Table:** | **Schema:** Advanced Hunting
**MITRE ATT&CK:** | **Tactic:**Privledge Escalation | **Technique:**"T1068,T1611"
**Created:** 2026-05-11 | **Status:** Deployed

---

## Purpose


---

## Query

```kql
// Table: DeviceProcessEvents joined to DeviceInfo
// Schema: Advanced Hunting (MDE)
// Purpose: Detect unexpected privilege escalation — low-privilege process spawning root-level children on Linux hosts
// NOTE: MDE for Linux required on target hosts
// SCHEMA VALIDATION REQUIRED: AccountName, InitiatingProcessAccountName population on Linux MDE agents
let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
let ExcludedInitiatingAccounts = dynamic([
    "root", "swiagent", "veeamazure",
    "hd0adm","hd3adm","hd4adm",    // SAP HANA admin service account
    "nobody"     // Samba smbd worker fork — privilege separation before client handoff
]);

let ExcludedInitiatingProcesses = dynamic([
    "sudo", "su", "pkexec", "doas",
    "apt", "apt-get", "dpkg",    // Debian/Ubuntu package managers
    "yum", "dnf", "rpm"          // RHEL/CentOS package managers
]);
DeviceProcessEvents
| where DeviceId in (LinuxDevices)
| where AccountName == "root"
| where InitiatingProcessAccountName !in (ExcludedInitiatingAccounts)
    and InitiatingProcessAccountName != ""
| where InitiatingProcessFileName !in (ExcludedInitiatingProcesses)
// Exclude Veeam sudo command invocations — -S -k -p flag pattern is Veeam-specific
| where not (InitiatingProcessCommandLine has_all ("sudo", "-S", "-k", "-p"))
// Exclude Veeam login shell escalation — agent opens a root -bash session nightly
// Parent is bash, initiating cmd is "-bash" (login shell), spawned process is also bash
| where not (InitiatingProcessCommandLine == "-bash" and FileName == "bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Validated Columns
- [x] 
- [x] 

---

## Test Results
Was a bit noisy at first due to Veeam and some SAP accounts


---

## Deployment

> Default path is MDE Custom Detection. Only use Sentinel Analytics Rule for signals that do not exist in Advanced Hunting — identity (SigninLogs, AuditLogs), cloud (CloudAppEvents), and email (EmailEvents).

### MDE Custom Detection Rule
<!-- Default for all device-based detections — DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, etc. -->
- **Rule Name:** Custom Detection Unexpected Priv Escalation Detected
- **Frequency:**every hour
- **Lookback:** 1 hour
	- **Severity:**Medium
- **Actions:** `<!-- Alert only -->`
  **Deployed:** [ yes]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->



---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]
	## Intel Source: [[INTEL-Dirty-Frag-Linux-LPE-CVE-2026-43284-CVE-2026-43500]]
## PlayBook: [[PLAYBOOK-Linux-Unprivileged-Process-Spawning-Root-Child]]

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-11 | Created |
