# Obsidian Tag Taxonomy

> Reference for consistent tagging across the Security vault.
> Rule: every note gets at minimum one **type tag** and one **status tag**.

---

## Type Tags — What kind of note is it?

| Tag | Used For |
|-----|---------|
| `#intel` | Threat intelligence, active campaigns, advisories |
| `#detection` | KQL queries, analytics rules, hunting queries |
| `#hardening` | Hardening controls and policies |
| `#project` | Project notes and phase documents |
| `#ir` | Incident cases, playbooks, templates |
| `#hunt` | Threat hunting campaigns |
| `#resource` | Tools, training, articles, reference material |
| `#meeting` | Meeting notes |
| `#daily` | Daily notes |
| `#weekly` | Weekly notes |
| `#training` | Personal training session logs (Personal Vault) |

---

## Status Tags — What state is the note in?

| Tag | Meaning |
|-----|---------|
| `#status/draft` | Work in progress — not ready to use |
| `#status/active` | Currently being worked / in progress |
| `#status/done` | Complete and validated |
| `#status/review` | Needs review before filing |

---

## Security Domain Tags — What area does it cover?

| Tag | Used For |
|-----|---------|
| `#identity` | Entra ID, Active Directory, authentication |
| `#endpoint` | MDE, Intune, Windows hardening |
| `#email` | MDO, phishing, BEC |
| `#cloud` | Azure, M365, MCAS |
| `#ot-scada` | OT/ICS, plant assets |
| `#network` | SMB, NTLM, lateral movement |
| `#wdac` | WDAC/AppControl specific |

---

## Threat Actor / Source Tags

| Tag | Used For |
|-----|---------|
| `#iran` | Iranian APT activity (Handala, CL-STA-1128 etc.) |
| `#north-korea` | DPRK activity (Jasper Sleet etc.) |
| `#ransomware` | Ransomware TTPs and campaigns |
| `#infostealer` | Credential theft via infostealers |
| `#supply-chain` | Supply chain attacks |

---

## Utility Tags — Action required?

| Tag | Used For |
|-----|---------|
| `#export` | Ready to convert to .docx — remove after export |
| `#action-required` | Something needs doing — remove when done |
| `#pending-review` | Content needs manual completion (e.g. X/Twitter links) |

---

## Tagging Rules

1. **Every note gets at minimum:** one type tag + one status tag
2. **Intel notes get:** `#intel` + status + domain + threat actor if known
3. **Detection notes get:** `#detection` + status + domain
4. **Project notes get:** `#project` + status
5. **Remove utility tags when done** — `#export` and `#action-required` are transient
6. **`#pending-review`** — add when X/Twitter content couldn't be fetched; remove when manually completed

## Example Tags Line

```
## Tags
#intel #status/done #identity #iran #infostealer
```

```
## Tags
#detection #status/draft #endpoint #wdac
```

```
## Tags
#project #status/active #wdac
```

---

## Tags
#resource #obsidian #taxonomy

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
