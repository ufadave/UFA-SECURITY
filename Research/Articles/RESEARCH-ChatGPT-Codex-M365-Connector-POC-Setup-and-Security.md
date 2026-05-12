---
title: RESEARCH-ChatGPT-Codex-M365-Connector-POC-Setup-and-Security
date: 2026-05-08
source: "https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-in-apps-enterprise-edu-and-business | https://cyberdom.blog/the-hidden-risks-inside-chatgpt-in-entra-id/ | https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/discover-and-govern-chatgpt-and-other-ai-apps-accessing-microsoft-365-with-defender/4433435"
author: "OpenAI Help Center / CyberDom / Microsoft TechCommunity"
detection_candidate: true
tags:
  - "#resource"
  - "#status/done"
  - "#identity"
  - "#cloud"
  - "#email"
---

# RESEARCH — ChatGPT / Codex M365 Connector POC — Setup Plan & Security Monitoring

**Date:** 2026-05-08
**Owner:** Dave
**Status:** Active — POC in progress, dev team onboarding

---

## Context

Dev team is evaluating the **ChatGPT/Codex connector for Teams and Outlook** as a productivity POC. This is an **OpenAI product** — not a Microsoft-native Copilot feature — and it connects to your M365 tenant via OAuth delegated permissions through Microsoft Entra ID. Data flows to OpenAI infrastructure. This is the higher-risk integration pattern.

The connector is the same OAuth app underpinning ChatGPT's Microsoft 365 integrations (Outlook, Teams, SharePoint). Codex plugins run on top of this. Treat this as a third-party OAuth app with broad Graph API delegated permissions.

**ChatGPT M365 App ID (known):** `e0476654-c1d5-430b-ab80-70cbd947616a`
> Confirm this in Entra ID > Enterprise Applications after consent is granted.

---

## What "Scope" Actually Means — Dev Team Briefing

Developers consistently trip on this. Explain it concisely before they touch anything:

**OAuth scopes** are explicit permissions that ChatGPT/Codex requests from Microsoft Graph when a user (or admin) consents. They define exactly what data the app can access.

The M365 connectors request delegated scopes — meaning they act **on behalf of the authenticated user**, limited to what that user can already access. They do not get tenant-wide admin access unless an admin consent grant is made.

**Key scopes requested by the ChatGPT M365 connectors (verify in Entra ID):**

| Scope | What It Grants |
|-------|---------------|
| `User.Read` | Basic identity/profile of the consenting user |
| `Mail.Read` | Read all emails in the user's mailbox |
| `Mail.ReadWrite` | Read + create/modify draft emails (write action — disabled by default, requires admin enable) |
| `Calendars.Read` | Read calendar events |
| `Files.Read.All` | Read all files in OneDrive/SharePoint the user has access to |
| `Sites.Read.All` | Cross-site SharePoint read — any site the user can access |
| `Chat.Read` | Read Teams chat messages |
| `ChannelMessage.Read.All` | Read Teams channel messages across all channels user is in |

> **Note:** As of March 2026, OpenAI updated scopes for Outlook, Teams, and SharePoint apps to support write actions. These are **disabled by default** but Entra admins must review and approve the updated scope request. New users may hit connection failures until this is done.

**The risk in plain language:** A single OAuth consent mints a service principal in your tenant and issues refresh tokens. If a user with broad Exchange/SharePoint access consents, ChatGPT can read everything that user can read — emails, files, calendar — and this persists via refresh token until explicitly revoked.

---

## Pre-POC Prerequisites

Complete these **before** any dev touches the connector:

- [ ] **Scope this to the POC group only** — create a dedicated Entra ID security group (e.g., `SG-Codex-POC`) and restrict admin consent to members only. Do NOT allow tenant-wide user consent.
- [ ] **Disable user consent** for OAuth apps tenant-wide if not already done: Entra ID > Enterprise Applications > Consent and Permissions > User consent settings → Set to "Do not allow user consent" or restrict to verified publishers only.
- [ ] **Require admin consent workflow**: Entra ID > Enterprise Applications > Admin consent settings → Enable "Users can request admin consent" with reviewer = you.
- [ ] **Confirm data residency:** ChatGPT Enterprise has contractual data-handling commitments. ChatGPT Business/Team tier may use data for model improvement unless opted out. **Confirm the account tier with the dev team owner before proceeding.**
- [ ] **Confirm the OpenAI workspace type** (Enterprise vs Business vs Team) and validate that "Do not train on data" is enforced in OpenAI Workspace Settings.
- [ ] **Document which actions are enabled:** In OpenAI Workspace Settings > Apps — confirm write actions (Mail.ReadWrite, draft email) are disabled for the POC. Read-only scope only for Phase 1.
- [ ] **Notify your privacy/legal function** — M365 data including emails and Teams messages will transit to OpenAI infrastructure. This may have implications under PIPEDA and your org's data classification policy.

---

## Setup Steps — Controlled POC

### Step 1 — Entra ID Prep

1. In **Entra ID > Enterprise Applications > Consent and Permissions**:
   - Confirm user consent is restricted (not "Allow consent for all apps")
   - Enable admin consent request workflow
2. Create security group `SG-Codex-POC` with only the approved dev participants
3. Note the current state of any existing admin consent grants for the ChatGPT app ID — if it's already been consented previously, a service principal already exists. Run the audit KQL below immediately.

### Step 2 — OpenAI Workspace Configuration

1. The dev team **workspace admin** must log into `platform.openai.com` or the ChatGPT Business/Enterprise admin panel
2. Navigate to **Workspace Settings > Apps**
3. Enable only the connectors needed for the POC: Outlook and/or Teams
4. For each enabled app, click **Manage Actions** and confirm:
   - Read actions: OK for POC
   - Write actions (draft email, create calendar events): **Disable for Phase 1**
5. Use RBAC to restrict app access to `SG-Codex-POC` members only

### Step 3 — Entra ID Admin Consent Grant

When a user in the POC group first connects:
- They will see an OAuth consent prompt
- **An admin must grant consent** on behalf of the org, OR the user initiates a consent request that you approve
- After consent, a **service principal** for the ChatGPT app will appear in Entra ID > Enterprise Applications
- Record the service principal Object ID and the App ID — needed for ongoing monitoring

### Step 4 — Token Scope Validation

After first consent:
1. Go to Entra ID > Enterprise Applications > [ChatGPT app] > **Permissions**
2. Review the granted delegated permissions — confirm no permissions beyond what was expected are present
3. Document the granted scope list as your baseline

### Step 5 — Monitoring Baseline

Before users start actively using the connector, run the KQL queries in the linked detection note to establish a clean baseline of:
- Service principal creation event
- Initial consent grant
- First Graph API token issuance (SigninLogs)

---

## Security Watch Items During POC

### 🔴 High — Monitor Immediately

| Risk | What to Watch |
|------|--------------|
| **Overly broad consent granted** | Admin consent granted with `Files.Read.All` + `Sites.Read.All` — verify scope matches expectation |
| **Write actions silently enabled** | OpenAI updated scopes in March 2026; new Entra consent may silently include write scopes. Audit after every OpenAI release note cycle. |
| **Refresh token persistence** | OAuth refresh tokens for this app persist until revoked. If a dev leaves the POC or the org, revoke their tokens explicitly. |
| **Non-POC users consenting** | If user consent is not locked down, any user can independently connect their account — you will not know unless you're watching AuditLogs |
| **Service principal scope creep** | App updates can request new scopes; Entra admins see a re-consent prompt. Devs may click through without reading. |

### 🟡 Medium — Monitor Weekly During POC

| Risk | What to Watch |
|------|--------------|
| **Sensitive mailbox access** | Exec mailboxes, HR, Finance accounts — ensure POC group members do not include high-privilege users |
| **Teams channel message exfiltration** | Channel read access is broad — ensure no sensitive channels (IR, SCADA, Legal) are accessible to POC accounts |
| **SharePoint data crawl** | If `Sites.Read.All` is granted and a dev asks broad questions, Codex can enumerate across all sites that user can access |
| **Prompt injection via email/Teams content** | Codex reads email/Teams content and reasons over it. Malicious content in those surfaces could attempt to manipulate Codex responses or actions. |

### 🟢 Low — Review at POC Close

| Risk | What to Watch |
|------|--------------|
| Data retention at OpenAI | Confirm retention policy via OpenAI admin settings at POC close |
| Audit log completeness | Verify M365 Unified Audit Log was capturing during POC for post-hoc review |

---

## Hardening Actions

- [ ] Restrict user consent to verified publishers only (Entra ID > Enterprise Apps > Consent and Permissions)
- [ ] Enable admin consent workflow so unapproved apps are flagged to you before tokens are issued
- [ ] Configure a MCAS / Defender for Cloud Apps policy to alert on new OAuth app consents with `Files.Read.All` or `Mail.Read` scope
- [ ] Scope the ChatGPT service principal to the POC group via Conditional Access or app assignment (Entra ID > Enterprise Apps > [App] > Users and Groups — set "Assignment required" to Yes, add only POC group)
- [ ] Set a POC end date — schedule token revocation and service principal removal at POC close
- [ ] Review OpenAI release notes monthly — scope changes require re-consent; Entra admins must review and approve

---

## MITRE ATT&CK

| Technique | Name | Notes |
|-----------|------|-------|
| T1550.001 | Use Alternate Authentication Material: Application Access Token | OAuth token issued to ChatGPT app |
| T1530 | Data from Cloud Storage | Codex reading SharePoint/OneDrive via `Files.Read.All` |
| T1114.002 | Email Collection: Remote Email Collection | Outlook connector reading mailbox via `Mail.Read` |
| T1078.004 | Valid Accounts: Cloud Accounts | Service principal in Entra ID with delegated Graph permissions |

---

## Related Notes

- [[KQL-ChatGPT-Codex-OAuth-App-Monitoring]]
- [[Hardening/Controls/HARD-OAuth-App-Consent-Controls]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-08 | Created — POC in progress, dev team onboarding |
