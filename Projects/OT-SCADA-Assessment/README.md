# Project — OT/SCADA Assessment

**Status:** In Progress | **Started:** 2026
**Owner:** Dave

---

## Objective
Assess and secure OT/SCADA assets at the recently acquired fertilizer plant. Establish network segmentation, asset inventory, and regulatory compliance posture.

---

## Scope
- Asset discovery (Nmap, OpenVAS/Greenbone, Wazuh)
- Network segmentation (Illumio evaluation)
- Regulatory compliance (CFIA Fertilizers Act, Explosives Act, TDG)
- Threat exposure (Iranian APT targeting Rockwell/Allen-Bradley PLCs)

---

## Linked Vault Notes
- [[OT-SCADA/Assets/|Asset Inventory]]
- [[OT-SCADA/Vulnerabilities/|Vulnerabilities]]
- [[OT-SCADA/Compliance/|Compliance]]
- [[Threat-Hunting/TTPs/CISA-Iranian-APT-PLC-Exploitation-AA26-097A|CISA Iranian APT Advisory]]
- [[Threat-Hunting/TTPs/Unit42-Iran-OT-Escalation-CL-STA-1128|Unit 42 CL-STA-1128]]

---

## Actions
- [ ] Confirm internet-exposed Rockwell/Allen-Bradley PLCs
- [ ] Complete Illumio microsegmentation evaluation
- [ ] Apply Rockwell SD1771 hardening guidance

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
