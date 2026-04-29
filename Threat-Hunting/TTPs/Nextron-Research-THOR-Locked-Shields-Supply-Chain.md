# Intel — Nextron Research: THOR at Locked Shields + NPM/PyPI Supply Chain YARA Rules

**Source:** https://www.nextron-systems.com/2026/04/22/nextron-locked-shields-thor-apt-scanner/
**Tweet:** https://x.com/nextronresearch/status/2046666197412839578
**Date:** 2026-04-23
**MITRE ATT&CK:** T1195.001, T1195.002 | **Tactic:** Supply Chain Compromise
**Detection Candidate:** Yes — supply chain rules

---

## Summary
Nextron published two relevant items around this period. First, their involvement in Locked Shields 2026 using THOR APT Scanner for compromise assessment — highlighting THOR's value in detecting attacker artifacts missed by EDR at rest. Second, Valhalla YARA rules now cover two active supply chain attacks: the Axios NPM compromise (March 30, 2026 — malicious versions 1.14.1 and 0.30.4 delivering a cross-platform RAT via `plain-crypto-js@4.2.1`) and the LiteLLM PyPI attack (March 2026 — versions 1.82.7/1.82.8 exfiltrating credentials and installing a persistent C2 backdoor attributed to TeamPCP).

---

## Relevance to UFA
If any UFA developer systems or build pipelines use npm or Python packages, the Axios and LiteLLM supply chain compromises are directly relevant. Given you're also exploring Claude/Claude Code usage detection across the fleet, LiteLLM in particular is a dependency that could appear in AI tooling. The THOR scanner is also worth evaluating for periodic compromise assessment across your Windows fleet.

---

## Detection Notes
**Axios NPM supply chain (plain-crypto-js):**
- `DeviceProcessEvents` — `cscript.exe` spawned by node/npm install processes
- `DeviceNetworkEvents` — outbound from `npm install` processes to unknown C2
- `DeviceFileEvents` — `package.json` modification post-install

**LiteLLM PyPI supply chain (TeamPCP):**
- `DeviceProcessEvents` — Python process spawning credential harvesting tools
- `DeviceFileEvents` — persistence files written after `pip install litellm`
- Look for `litellm` versions 1.82.7 or 1.82.8 in pip freeze output across developer endpoints

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "python.exe", "pip.exe")
| where ProcessCommandLine has_any ("cscript", "curl", "powershell", "cmd /c")
| where InitiatingProcessCommandLine has_any ("install", "pip install")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

---

## Actions
- [x] Check developer endpoints for Axios npm versions 1.14.1 or 0.30.4
- [ ] Check for LiteLLM versions 1.82.7 or 1.82.8 in Python environments
- [ ] Evaluate THOR Lite for periodic compromise assessment on key servers
- [ ] Review Valhalla free rules for supply chain YARA signatures

---

## Tags
#intel #supply-chain #npm #pypi #axios #litellm #nextron #yara #t1195 #teamPCP #action-required #staus/active

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-23 | Created |
