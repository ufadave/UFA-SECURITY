# Intel — Unit 42: Iran OT/ICS Escalation — CL-STA-1128 (Cyber Av3ngers / Storm-0784)

**Source:** https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/
**Tweet:** https://x.com/unit42_intel/status/2047797833965724004
**Date:** 2026-04-25
**MITRE ATT&CK:** T0855, T0866 | **Tactic:** Impair Process Control, Exploitation of Remote Services
**Detection Candidate:** Yes

---

## Summary
Unit 42 is tracking a new threat cluster designated CL-STA-1128 (also known as Cyber Av3ngers and Storm-0784) targeting OT/ICS equipment, specifically Rockwell Automation FactoryTalk and Allen-Bradley PLCs. This represents a tactical shift from the cluster's historical focus on internet-connected Unitronics PLCs. Unit 42 assesses with moderate confidence that the attacker installed Rockwell Automation's FactoryTalk software on VPS infrastructure to stage exploitation. The activity is assessed as Iranian state-directed, occurring in the context of significant Iran-Israel-US conflict escalation beginning February 2026.

---

## Relevance to UFA
UFA's recently acquired fertilizer plant contains OT/SCADA assets that may include Rockwell Automation equipment — this threat cluster directly targets that technology stack. With the plant network currently assessed as inadequately segmented, internet-exposed OT assets represent a credible risk vector that warrants immediate asset inventory review and verification of internet exposure.

---

## Detection Notes
Detection candidates for this threat:

**1. Internet-exposed Rockwell/Allen-Bradley devices**
- Check for outbound connections from OT network to unknown external IPs
- Look for FactoryTalk process execution from unexpected hosts

**2. VPS-origin inbound connections to OT segment**
- Flag inbound connections from hosting provider ASNs (AS16509 AWS, AS14618, DigitalOcean, Vultr etc.) to OT network

**3. Wiper/destructive activity precursors**
- Sudden large-scale file deletion or volume shadow copy deletion
- Unexpected `wevtutil`, `vssadmin`, or `bcdedit` execution on OT-adjacent hosts

> KQL opportunities: `DeviceNetworkEvents` for OT subnet outbound, `DeviceProcessEvents` for destructive tooling on OT-adjacent Windows hosts

---

## IOCs / Indicators
> Check Unit 42 GitHub repo for latest IOC files:
> https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel

- Rockwell Automation FactoryTalk on VPS infrastructure
- Unitronics PLC exploitation (historical)
- Handala Hack persona (MOIS-linked) — data exfiltration + wiper operations
- Associated groups: Void Manticore, COBALT MYSTIQUE, Storm-1084, Storm-0842

---

## Actions
- [x] Review OT asset inventory at fertilizer plant — confirm Rockwell/Allen-Bradley presence
- [x] Check Nmap/OpenVAS scan results for internet-exposed OT services
- [x] Verify network segmentation status between IT and OT at plant
- [x] Review Illumio microsegmentation evaluation status — this is exactly the use case
- [x] Check Cortex Xpanse equivalent in E5 for exposed OT/ICS services

---

## Related Notes
- [[OT-SCADA/Assets/|Plant Asset Inventory]]
- [[OT-SCADA/Compliance/|Regulatory Compliance]]
- [[Threat-Hunting/TTPs/|MITRE ATT&CK ICS Techniques]]

---

## Tags
#intel #ot-scada #iran #threat-hunting #unit42 #rockwell #ics #t0855 #t0866 #cl-sta-1128 #status/done

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created — sourced from Unit 42 tweet and threat bulletin |

> **Note:** X/Twitter blocked direct content fetch. Note based on Unit 42 threat bulletin at unit42.paloaltonetworks.com/iranian-cyberattacks-2026 and March 2026 threat bulletin. Verify against original tweet for any additional IOCs.
