# Novee Meeting

**Date:** 2026-04-30| **Time:** 15:00
**Type:** Vendor
	**Attendees:** Me, Jacob Larsen Account Executive, Shravan, John Bradshaw Demo guy, Ben Ogle, Jitaksha, Gavin
Facilitator:** Novee

---

## Agenda
1. Demo
2. 
3. 

---

## Notes
Can do white,grey and black box testing
will have infrastructure testing later in the year. 

Use multiple Frontier models.
Models: Novee, OpenAi, Antropic, Google


# QUESTIONS:


1. **"What APTS compliance tier do you claim, and do you have a conformance claim document?"** — If they're unaware of APTS, ask how they govern scope enforcement and audit trails for autonomous operations. 
2. **"Walk me through your hard deny list implementation — can it be modified mid-engagement, and does it automatically include safety-critical systems?"** — APTS-SE Tier 1 requirement. Non-negotiable for an OT environment.
3. **"What is your kill switch response time, and how is it demonstrated?"** — APTS defines this as a behavioural requirement that must be hands-on verified, not just documented.
 [[RESEARCH-OWASP-APTS-Autonomous-Pentest-Standard]]
4. What is your scope coverage for hybrid and on-premises environments?**  
The website is focused on web applications and external attack surface. Your environment is hybrid — Entra ID, on-prem AD, Intune-managed endpoints, and a recently acquired OT/SCADA network. Before any evaluation can be taken seriously, you need to understand whether Novee can test internal network paths, not just external-facing applications.
 5. Where is customer data processed and stored — and do you have a Canadian data residency option?**  
Given your regulatory environment (CFIA, Explosives Act, TDG) and the sensitivity of pentest findings (which effectively document your exploitable attack surface), data residency is non-negotiable. An Israeli-founded company with no explicit data residency statement is a yellow flag until confirmed.

**3. How do findings flow into Microsoft Sentinel or MDE — or is the platform entirely standalone?**  
You run a Sentinel-native SOC. A platform that generates findings in its own dashboard with no SIEM integration creates workflow friction. Ask whether they have a Sentinel data connector, API export, or SOAR integration. If not, understand what the remediation handoff process looks like in practice.

**5. You're less than a year old — what does your enterprise support model look like, and can you provide a Canadian reference customer?**  
Novee's founding team is credible and the research output is real, but operational maturity at enterprise scale is unproven. Ask about SLA commitments, dedicated support, escalation paths, and whether they have any Canadian enterprise or regulated-industry customers who can serve as references.


---

## Decisions Made
- 
- 

---

## Action Items
| Action | Owner | Due |
|--------|-------|-----|
|  |  |  |
|  |  |  |

---

## Next Meeting
**Date:** | **Topic:**

---

## Tags
#meeting #vendor

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-29 | Created |
