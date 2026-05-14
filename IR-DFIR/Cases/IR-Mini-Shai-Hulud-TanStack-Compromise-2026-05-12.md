---
date: 2026-05-12 00:00
case_id: INC-2026-051200000
severity: "Critical"
type: "Supply Chain Compromise / Credential Theft"
status: "Draft"
closed: ""
tags:
  - "#ir"
  - "#status/draft"
  - "#supply-chain"
  - "#endpoint"
  - "#cloud"
---

# Incident — Mini Shai-Hulud TanStack Supply Chain Compromise

> **Status:** Draft — open only if exposure is confirmed via FIND-Mini-Shai-Hulud findings.
> If all five hunts in the Finding return clean, do not activate this case.

---

## Summary

TeamPCP Mini Shai-Hulud worm campaign compromised 84 npm package versions across 42 @tanstack/* namespaces on 2026-05-11T19:20–19:26Z (CVE-2026-45321, CVSS 9.6). Malicious packages install a credential-stealing payload (`router_init.js`) via npm prepare lifecycle hook, exfiltrating GitHub tokens, cloud credentials, npm tokens, and SSH keys to C2 infrastructure (`filev2.getsession.org`, `api.masscan.cloud`). The worm self-propagates by using stolen OIDC tokens to publish compromised downstream packages.

This case is activated if any host in the environment is confirmed to have installed an affected @tanstack/* version during the compromise window.

---

## Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-05-11T19:20Z | TeamPCP begins publishing malicious @tanstack/* versions |
| 2026-05-11T19:26Z | Last malicious version published |
| 2026-05-11T19:46Z | External researcher (ashishkurmi/StepSecurity) detects compromise |
| 2026-05-12 | INTEL note created, proactive hunt initiated |
| | ← Populate from here if exposure confirmed |

---

## Affected Assets

| Host | User | Impact |
|------|------|--------|
| TBD | TBD | TBD |

---

## Evidence Log

| Artifact | Source | Hash / Reference |
|----------|--------|-----------------|
| router_init.js payload | npm tarball | SHA256: ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c |
| MDE investigation package | Device page | Collect before isolation |
| npm install logs | CI/CD pipeline | Collect from pipeline run logs |
| GitHub audit log | GitHub org settings | Review for post-install unexpected activity |
| Cloud provider audit log | AWS CloudTrail / Azure Activity Log | Review for credential abuse |

---

## Actions Taken

### Immediate containment
- [ ] **DO NOT revoke credentials before imaging** — worm includes ransom threat triggered by premature revocation
- [ ] Isolate affected host in MDE (Device page → Isolate device); confirm OT impact before isolating any plant hosts
- [ ] Collect MDE investigation package from device page
- [ ] Image the host (full forensic image)
- [ ] Suspend affected CI/CD pipelines and associated service accounts at pipeline level

### Blast radius assessment
- [ ] Identify all credentials accessible from the compromised host at time of install:
  - [ ] GitHub tokens / PATs — which repos and orgs had access?
  - [ ] npm tokens — document via `npm token list` from a clean machine
  - [ ] Cloud credentials (AWS access keys, Azure service principals, GCP service accounts)
  - [ ] SSH keys in `~/.ssh` — which hosts were accessible?
  - [ ] CI/CD secret store contents (Azure DevOps variable groups, GitHub Actions secrets)
- [ ] Review GitHub org audit log for unexpected activity post-install:
  - Unexpected workflow runs
  - Package publish events
  - Secret access events
- [ ] Review cloud provider audit logs for credential abuse post-install
- [ ] Check for downstream propagation — any packages published by the compromised pipeline after install may be compromised; pull pipeline publish logs

### Worm propagation check
- [ ] Search internal repos and GitHub Actions workflow runs for beacon strings:
  - `thebeautifulmarchoftime`
  - `thebeautifulsandsoftime`
- [ ] Review all npm publish events from CI/CD pipelines in the window after the install
- [ ] If internal packages were published during a compromised run: unpublish immediately, open a separate incident track

### Ransom demand check
- [ ] Check email accounts associated with affected GitHub org and npm account for contact from TeamPCP
- [ ] If a demand has arrived: **escalate to legal before any further action** — criminal matter

### Credential rotation (after imaging, in order)
- [ ] GitHub tokens and PATs for affected account
- [ ] npm tokens
- [ ] Cloud credentials (AWS access keys, Azure service principals)
- [ ] SSH keys stored on host or in CI/CD secret stores
- [ ] Any secrets in `.env` files or environment variables accessible from the pipeline

---

## Root Cause

To be determined — pending confirmation of affected package version installed and attack chain reconstruction.

Expected: npm install of @tanstack/* package during compromise window (2026-05-11T19:20Z–patch) triggered prepare lifecycle hook executing router_init.js payload.

---

## Lessons Learned

To be completed post-incident. Likely themes:
- Dependency pinning (exact hash in lock files) vs trust-based resolution
- SLSA provenance limitations — valid attestations present on malicious packages
- CI/CD secret scope minimisation — OIDC token permissions and npm publish access

---

## Linked Notes

- [[FIND-Mini-Shai-Hulud-TanStack-Exposure-Assessment-2026-05-12]]
- [[INTEL-Mini-Shai-Hulud-TanStack-npm-Supply-Chain-CVE-2026-45321]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-12 | Created as draft — activate only if Finding confirms exposure |
