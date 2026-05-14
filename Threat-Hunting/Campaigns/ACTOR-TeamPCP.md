---
title: TeamPCP
date: 2026-05-14
type: threat-actor
aliases:
  - "Mini Shai-Hulud operators"
origin: "Unknown"
motivation: "Financial — ransom, credential theft, downstream supply chain access"
active_since: "2026-03"
last_observed: "2026-05-11"
mitre:
  - "T1195.001"
  - "T1059.007"
  - "T1552.001"
  - "T1078.004"
tags:
  - "#hunt"
  - "#status/active"
  - "#supply-chain"
---

# Threat Actor — TeamPCP

---

## Overview

| Field | Detail |
|-------|--------|
| **Also Known As** | Mini Shai-Hulud operators |
| **Origin** | Unknown |
| **Motivation** | Financial — credential theft, downstream supply chain access, ransom threat |
| **Active Since** | March 2026 |
| **Last Observed** | 2026-05-11 (TanStack wave) |
| **Targeting** | Open source software maintainers and CI/CD pipelines with npm/PyPI publish permissions; primarily targets JavaScript and Python ecosystem projects with broad downstream adoption |

---

## TTPs Observed

| Technique ID | Name | First Seen | Source |
|---|---|---|---|
| T1195.001 | Supply Chain Compromise: Software Dependencies | 2026-03 | Aqua Trivy campaign |
| T1059.007 | JavaScript execution | 2026-03 | router_init.js payload via npm prepare hook |
| T1552.001 | Credentials in Files | 2026-03 | Harvest of GitHub tokens, npm tokens, SSH keys, cloud credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | 2026-03 | OIDC token theft from GitHub Actions runners for authenticated npm publish |
| T1650 | Acquire Access | 2026-05 | Pwn Request via pull_request_target workflow abuse |
| T1584.001 | Compromise Infrastructure: Domains | 2026-03 | C2 domains — filev2.getsession.org, api.masscan.cloud, git-tanstack.com |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1195.001 — Supply Chain Compromise |
| Execution | T1059.007 — JavaScript (npm lifecycle hook) |
| Credential Access | T1552.001 — Credentials in Files |
| Persistence | T1078.004 — Valid Cloud Accounts (OIDC token reuse) |
| Command and Control | T1584.001 — Compromised Infrastructure (C2 domains) |

---

## IOCs

| Type | Value | First Seen | Source |
|------|-------|------------|--------|
| Domain | `filev2.getsession.org` | 2026-03 | Aqua Trivy campaign |
| Domain | `api.masscan.cloud` | 2026-03 | Aqua Trivy campaign |
| Domain | `git-tanstack.com` | 2026-05-11 | TanStack campaign |
| SHA256 | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` | 2026-05-11 | router_init.js — TanStack wave |
| String | `thebeautifulmarchoftime` | 2026-03 | C2 beacon commit string |
| String | `thebeautifulsandsoftime` | 2026-03 | C2 beacon commit string (variant) |

---

## Detection Coverage

| KQL Note | Table | Status |
|----------|-------|--------|
| [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]] — stub 1 | DeviceNetworkEvents | Draft — C2 IOC detection |
| [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]] — stub 2 | DeviceFileEvents | Draft — router_init.js SHA256 |
| [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]] — stub 3 | DeviceProcessEvents | Draft — npm lifecycle hook child process |

---

## Campaign History

| Campaign | Period | Summary | Note |
|----------|--------|---------|------|
| Aqua Trivy | 2026-03 | Compromised Aqua Security Trivy scanner packages via GitHub Actions abuse | — |
| Bitwarden CLI | 2026-04 | Compromised Bitwarden CLI npm package; credential manager supply chain concern | — |
| TanStack / Mistral / UiPath / OpenSearch | 2026-05-11 | Largest wave to date — 84 malicious versions across 42 @tanstack/* packages; 170+ packages total across npm and PyPI in coordinated multi-org attack | [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]] |

---

## Attack Chain

TeamPCP uses a consistent three-step GitHub Actions abuse chain across all observed campaigns:

1. **Pwn Request** — pull_request_target workflow abuse to gain CI execution context on the target repo
2. **Cache poisoning** — cross-fork Actions cache poisoning via renamed fork to inject malicious pnpm store
3. **OIDC token extraction** — steal GitHub Actions OIDC token from runner process, use to authenticate npm/PyPI publish as the legitimate package maintainer

The resulting malicious packages carry valid Sigstore attestations and are published from the real release workflow on the real main branch — SLSA provenance does not protect against this technique.

**Payload behaviour (router_init.js):**
- Installs via npm `prepare` lifecycle hook — executes at `npm install` time, before the developer sees any output
- Steals: GitHub tokens, npm tokens, AWS/GCP/Kubernetes credentials, SSH keys, `.env` files, CI/CD secret store contents
- Exfiltrates to C2 via HTTPS
- Self-propagating: stolen OIDC tokens used to publish compromised versions of victim's own packages
- Ransom threat: contact and demand sent to victim org before or upon token revocation attempt — **do not revoke tokens before imaging**

---

## Intel Feed

> Accumulated summaries from linked INTEL notes — newest first.

### 2026-05-11 — INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321
> TeamPCP's largest wave — 84 malicious @tanstack/* npm packages in a 6-minute window, expanding to 170+ packages across npm and PyPI via worm propagation. CVE-2026-45321, CVSS 9.6. Exposure assessment active. [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]]

---

## Hardening Actions

- [ ] Pin npm/PyPI dependencies to exact hashes in lock files — SLSA attestations do not protect against this attack class
- [ ] Audit GitHub Actions workflows for `pull_request_target` usage — restrict permissions to minimum required
- [ ] Scope OIDC token permissions in CI/CD pipelines — limit npm publish tokens to specific packages only
- [ ] Monitor DeviceNetworkEvents for C2 domain connectivity — `filev2.getsession.org`, `api.masscan.cloud`, `git-tanstack.com`
- [ ] Search internal repos for beacon strings: `thebeautifulmarchoftime`, `thebeautifulsandsoftime`

---

## Related Notes

- [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]]
- [[FIND-Mini-Shai-Hulud-TanStack-Exposure-Assessment-2026-05-12]]
- [[IR-Mini-Shai-Hulud-TanStack-Compromise-2026-05-12]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-14 | Created — pre-populated from three confirmed campaigns (Aqua Trivy, Bitwarden CLI, TanStack wave) |
