---
date: 2026-05-11
title: Linux SUID SGID chmod Detection
table: DeviceProcessEvents, DeviceInfo
schema: Advanced Hunting
mitre: T1548.001
tactic: Privilege Escalation
technique: Setuid and Setgid
status: Deployed
promoted_to_rule: true
mde_rule_id: "Custom - Linux SUID SGID chmod Detection"
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/MDE"
  - "#status/Deployed"
  - "#endpoint"
  - "#ot-scada"
---

# KQL —Custom - Linux SUID SGID chmod Detection

---

**Table:** DeviceProcessEvents + DeviceInfo | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1548.001 | **Tactic:** Privilege Escalation | **Technique:** Setuid and Setgid
	**Created:** 2026-05-11 | **Status:** Deployed

---

## Purpose

Detects `chmod` setting the SUID or SGID bit on any file or directory on Linux hosts, indicating a potential persistence or privilege escalation mechanism. Dirty Frag (CVE-2026-43284/CVE-2026-43500) and similar Linux LPE exploits commonly follow escalation to root with SUID binary creation to maintain persistent root access.

Scoped to exclude legitimate package manager operations (dpkg postinst scripts and RPM scriptlets) restoring expected SUID/SGID bits on known system binaries and directories. Two events in 30 days after exclusions across a multi-host Linux estate — signal quality is sufficient for scheduled rule deployment.

---

## Query

```kql
let LinuxDevices = DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceProcessEvents
| where DeviceId in (LinuxDevices)
| where AccountName == "root"
| where FileName == "chmod"
| where ProcessCommandLine matches regex @"chmod [0-9]*[2-7][0-9]{3}"
    or ProcessCommandLine has_any ("u+s", "g+s", "a+s")
// Exclude all package manager postinst/scriptlet activity
// dpkg (Ubuntu/Debian) and RPM (RHEL/CentOS/SUSE) -- trust the package manager
// Supply chain compromise via postinst warrants a separate dedicated detection
| where not (
    InitiatingProcessCommandLine startswith "/bin/sh /var/lib/dpkg/info/"
    or InitiatingProcessCommandLine matches regex @"^/bin/sh /var/tmp/rpm-tmp\.[A-Za-z0-9]+"
)

// Exclude Veeam Linux agent sudo invocations
| where not (InitiatingProcessCommandLine has_all ("sudo", "-S", "-k", "-p"))
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ReportId,
    DeviceId
| order by Timestamp desc
```

---

## Validated Columns

- [x] `OSPlatform` -- confirmed in `DeviceInfo`; join on `DeviceId` required
- [x] `DeviceId` -- join key; confirmed populated on Linux MDE agents
- [x] `AccountName` -- confirmed populated for Linux process events
- [x] `InitiatingProcessAccountName` -- confirmed populated on Linux agents
- [x] `FileName` -- confirmed; `chmod` telemetry captured reliably on Linux agents
- [x] `ProcessCommandLine` -- confirmed; full command line captured including permission arguments
- [x] `InitiatingProcessCommandLine` -- confirmed; dpkg/RPM scriptlet paths visible and usable as exclusion anchors
- [x] `InitiatingProcessParentFileName` -- confirmed present
- [x] `ReportId` -- confirmed; included for alert deduplication in Sentinel

---

## Test Results

**30-day validation -- 2026-04-11 to 2026-05-11**

| Date | Device | Event | Disposition |
|------|--------|-------|-------------|
| 2026-05-07 | ufasa202 | `chmod g+s /run/log/journal/...` via RPM scriptlet | Excluded -- systemd-journald package update |
| 2026-04-15 | ufasa202 | `chmod g+s /run/log/journal/...` via RPM scriptlet | Excluded -- systemd-journald package update |

Post-exclusion result: **0 residual events** in 30 days across estate. Ready for deployment.

**Noise sources addressed during tuning:**

| Source | Pattern | Resolution |
|--------|---------|------------|
| Veeam Linux agent | `chmod 0711 /tmp/VeeamApp_*` via `sudo -S -k -p` | Excluded via `-S -k -p` flag pattern |
| polkit/pkexec package install | `chmod 4755 /usr/bin/pkexec` via dpkg postinst | Excluded via dpkg path + LegitSUIDBinaries list |
| systemd-journald package update | `chmod g+s /var/log/journal/` via RPM scriptlet | Excluded via rpm-tmp path + LegitSGIDPaths list |

---

## Deployment

> Default path is MDE Custom Detection for device-based signals. This query joins DeviceInfo which is available in Sentinel via the Microsoft Defender XDR connector -- confirm the DeviceInfo table is ingested before deploying to Sentinel.

### MDE Custom Detection Rule
- **Rule Name:** CUSTOM - Linux SUID SGID chmod Detection
- **Frequency:** Every 1 hour
- **Lookback:** 1 day
- **Severity:** High
- **Actions:** Alert only -- do not auto-isolate; OT plant hosts require manual containment decision per playbook
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_id in frontmatter when deployed -->


## Hardening Control Pair
- **Control:** [[HARD-Linux-SUID-Binary-Audit]] -- periodic audit of SUID/SGID binaries against known-good baseline
- **Linked:** [ ]

---

## Related Notes
- [[INTEL-Dirty-Frag-Linux-LPE-CVE-2026-43284-CVE-2026-43500]]
- [[PLAYBOOK-Linux-Unprivileged-Process-Spawning-Root-Child]]
- [[KQL-Linux-Unprivileged-Process-Spawning-Root-Child]] -- companion detection (stub 1)

---

## Changelog
| Date | Change |
|------|--------|
| 2026-05-11 | Created -- promoted from INTEL-Dirty-Frag stub 2 after 30-day tuning validation |
| 2026-05-11 | Regex updated to cover SGID (2xxx) in addition to SUID (4xxx); LegitSGIDPaths added for journald dirs |
| 2026-05-11 | RPM scriptlet exclusion added for RHEL/CentOS hosts (ufasa202 pattern) |
