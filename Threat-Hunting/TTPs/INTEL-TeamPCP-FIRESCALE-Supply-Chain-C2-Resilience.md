---
title: INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience
date: 2026-05-18
source: "https://hunt.io/blog/teampcp-python-toolkit-firescale-github-c2-takedown"
author: "Hunt.io / The Hacker News"
mitre:
  - "T1195.001 — Supply Chain Compromise: Compromise Software Dependencies"
  - "T1567.001 — Exfiltration Over Web Service: GitHub"
  - "T1008 — Fallback Channels"
  - "T1552.001 — Unsecured Credentials: Credentials in Files"
  - "T1083 — File and Directory Discovery"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#cloud"
  - "#supply-chain"
  - "#action-required"
---

# INTEL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://hunt.io/blog/teampcp-python-toolkit-firescale-github-c2-takedown |
| **Author** | Hunt.io / The Hacker News (secondary source) |
| **Date Observed** | 2026-05-18 |
| **Date Published** | 2026-05-15 (updated 2026-05-16) |
| **Patch Available** | N/A — supply chain / OPSEC issue |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1195.001 | Supply Chain Compromise: Software Dependencies |
| T1567.001 | Exfiltration Over Web Service: GitHub |
| T1008 | Fallback Channels (FIRESCALE dead-drop redirect) |
| T1552.001 | Unsecured Credentials: Credentials in Files |
| T1083 | File and Directory Discovery (home dir walk, dotenv, SSH keys) |

---

## Summary

TeamPCP (also tracked as UNC6780) is a financially motivated threat actor behind a modular Python malware toolkit delivered via supply chain compromise of PyPI/npm packages. Their C2 architecture uses a hard-coded primary server with a fallback mechanism called FIRESCALE, which acts as a dead-drop redirector when the primary C2 is taken down. A third exfiltration path abuses the victim's own GitHub account as a data staging location — making takedown of any single channel insufficient. The toolkit is highly capable: it captures all environment variables, reads SSH keys and configs, walks the entire home directory for `.env` files, pulls credentials from running Docker containers, and includes a credential stealer targeting CI/CD runner secrets, a crypto miner, and VECT ransomware. Hunt.io attributed at least four distinct payloads to this infrastructure across campaigns from December 2025 through March 2026.

---

## Relevance to Environment

Moderate-to-high relevance. While direct PyPI/npm supply chain compromise primarily affects developer and CI/CD environments, your environment does have developer workstations and potentially GitHub Actions or Azure DevOps pipelines that could be affected. The credential harvesting focus (`.env` files, Docker secrets, SSH keys, CI/CD secrets) is relevant wherever developers or DevOps pipelines exist in your estate. The VECT ransomware payload at the end of the chain is directly relevant as a business impact. The use of victim GitHub accounts for exfiltration is a novel detection evasion angle — outbound GitHub traffic is rarely blocked. Also note overlap with TeamPCP activity tied to the LiteLLM compromise (May 2026) which targeted AI API credentials — relevant if any teams use AI API integrations.

---

## Detection Notes

> `detection_candidate: true`

### KQL Stubs

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect Python-based malware reading .env files and SSH configuration — FIRESCALE/TeamPCP credential harvesting pattern

DeviceProcessEvents
| where FileName in~ ("python.exe", "python3", "python")
| where ProcessCommandLine has_any (".env", "id_rsa", "id_ed25519", ".ssh/config", "docker.sock")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect outbound connections from Python processes to GitHub API — potential exfiltration via victim's own GitHub account

DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("python.exe", "python3", "pythonw.exe")
| where RemoteUrl has "api.github.com" or RemoteUrl has "raw.githubusercontent.com"
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Validated Columns
- [ ] `ProcessCommandLine` — DeviceProcessEvents, confirm available in AH schema
- [ ] `RemoteUrl` — DeviceNetworkEvents, confirm available
- [ ] `RemoteIPType` — DeviceNetworkEvents

---

## Hardening Actions

- [ ] Audit GitHub Actions / Azure DevOps pipeline secrets — ensure secrets are stored in vault (Key Vault / GitHub Secrets) not in `.env` files committed to repos
- [ ] Review PyPI/npm package dependencies in any developer-facing projects — check for guardrails-ai, mistralai, LiteLLM versions pinned prior to March 2026 compromise
- [ ] Consider blocking or alerting on outbound GitHub API calls from non-developer endpoints via MCAS

---

## Related Notes

- [[]]
- [[KQL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience-Device]]

---

## Tags

#supply-chain #endpoint #cloud

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-18 | Created |
| 2026-05-18 | Generated 2 companion KQL notes: [[KQL-TeamPCP-FIRESCALE-Supply-Chain-C2-Resilience-Device]] |
