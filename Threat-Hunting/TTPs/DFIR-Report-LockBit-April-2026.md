# Intel — DFIR Report: LockBit Ransomware — ActiveMQ Exploit & PDQ Deploy Abuse

**Source:** https://thedfirreport.com/reports/
**Tweet:** https://x.com/thedfirreport/status/2046966648444264638
**Date:** 2026-04-23
**MITRE ATT&CK:** T1190, T1570, T1486, T1567.002 | **Tactic:** Initial Access, Lateral Movement, Impact, Exfiltration
**Detection Candidate:** Yes

---

## Summary
The DFIR Report's most recent LockBit case documents an intrusion starting with exploitation of CVE-2023-46604 on an internet-facing Apache ActiveMQ server, followed by Metasploit/Meterpreter post-exploitation, LSASS dumping, and lateral RDP movement. LockBit was deployed using PDQ Deploy — a legitimate enterprise software deployment tool — to automate ransomware distribution across the fleet via SMB. Data was exfiltrated using Rclone to MEGA.io cloud storage. A second notable case involved an intrusion with a 2-hour Time to Ransomware after initial access via RDP with compromised credentials.

---

## Relevance to UFA
UFA's Intune-managed Windows fleet with ~150+ endpoints across AB, BC, and SK is directly in scope for this TTP pattern. PDQ Deploy is a common enterprise tool — if any variant is deployed in your environment, or if similar software deployment tooling exists, it represents a high-value detection target. RDP lateral movement and Rclone exfiltration are both detectable with your existing MDE/Sentinel stack.

---

## Detection Notes
High priority KQL candidates for your environment:

**1. PDQ Deploy or similar tool executing binaries**
- `DeviceProcessEvents` — parent process `PDQDeployRunner.exe` spawning unexpected children
- Flag execution of `.exe` or `.bat` from `C:\Temp` or `C:\Windows\Temp` via deployment tools

**2. Rclone exfiltration to MEGA**
- `DeviceNetworkEvents` — outbound connections to `*.mega.io`, `*.mega.nz`
- `DeviceProcessEvents` — `rclone.exe` execution with `copy` or `sync` args

**3. LSASS access**
- `DeviceEvents` — `ProcessCreated` where `FileName == "lsass.exe"` accessed by non-system processes
- Already partially covered by your LSA Protection (RunAsPPL) control

**4. VSS deletion / ransomware precursors**
- `DeviceProcessEvents` — `vssadmin.exe delete shadows`, `bcdedit /set recoveryenabled no`

---

## Actions
- [ ] Build KQL for Rclone + MEGA exfiltration — see [[Detection-KQL/Hunting-Queries/]]
- [ ] Hunt for PDQ Deploy or equivalent deployment tool in fleet — check Intune software inventory
- [ ] Verify VSS deletion detection is covered in existing Sentinel analytics rules
- [ ] Review CVE-2023-46604 — confirm no internet-exposed ActiveMQ in environment

---

## Tags
#intel #ransomware #lockbit #dfir-report #t1486 #t1567 #rclone #pdq-deploy #lateral-movement #investigate-further #status/ #action-required 

---
**Comments**
We don't use Apache and we have blocked MEGA, but it would be good to revisit these
## Changelog
| Date | Change |
|------|--------|
| 2026-04-23 | Created |
