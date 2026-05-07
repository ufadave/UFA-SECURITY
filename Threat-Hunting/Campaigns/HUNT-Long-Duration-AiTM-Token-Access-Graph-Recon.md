---
date: 2026-05-05
title: Long Duration AiTM Token Access Graph API Reconnaissance
analyst: Dave
mitre: "T1528, T1539, T1087.004, T1114.002, T1530, T1137.005, T1136.003, T1078.004"
tactic: "Persistence, Collection, Discovery, Defence Evasion"
technique: "Steal Application Access Token, Steal Web Session Cookie, Cloud Account Discovery, Remote Email Collection, Data from Cloud Storage, Cloud Account Persistence"
status: "Active"
tags:
  - "#hunt"
  - "#status/active"
  - "#identity"
  - "#cloud"
  - "#email"
  - "#action-required"
---

# Hunt Campaign — Long Duration AiTM Token Access Graph API Reconnaissance

---

## Hypothesis

> "I believe a threat actor has maintained persistent access to a compromised M365 account via a stolen AiTM session token since approximately December 2025 — approximately 5 months prior to the confirmed Graph API enumeration event on 2026-05-05 — and has been conducting low-frequency, low-volume reconnaissance against mailbox contents, SharePoint documents, Teams conversations, and the directory during that window. I can test this by hunting for anomalous sign-in patterns, off-hours mailbox access, Graph API endpoint calls consistent with staged reconnaissance, guest account creation, and app registration changes attributable to the compromised account object ID over the full suspected access window."

**Triggering event:** Confirmed Graph API user enumeration from Sweden Central on 2026-05-05 02:21:56 UTC. HTTP 200 returned. Stolen Outlook token (App ID: `5d661950-3475-41cd-a2c3-d671a3162bc1`). Account Object ID: `5d28b71f-3fb6-48eb-9aea-b1011d09535b`. Probable platform: Tycoon2FA / Storm-1747. See [[FIND-Graph-API-User-Enumeration-Sweden-Central]].

**Why 5 months:** Intelligence assessment based on Tycoon2FA operator behaviour — token parking, low-frequency silent refresh, and BEC preparation timelines. The May 5 bulk user enumeration is consistent with operational preparation rather than initial reconnaissance, suggesting the attacker had already gathered sufficient mailbox intelligence to begin targeting.

---

## Scope

- **Environment:** M365 tenant — Exchange Online, SharePoint Online, OneDrive, Teams, Entra ID
- **Timeframe:** 2025-12-01 → 2026-05-05T02:21:56Z
- **Compromised Account Object ID:** `5d28b71f-3fb6-48eb-9aea-b1011d09535b`
- **Compromised UPN:** `REPLACE-WITH-UPN` (resolve from SigninLogs pivot first)
- **Suspected Platform:** Tycoon2FA (M247 Europe SRL / AS9009 IPv6 — confirm via IP lookup)
- **Data Sources:**
  - `SigninLogs` (Sentinel)
  - `AuditLogs` (Sentinel)
  - `OfficeActivity` (Sentinel)
  - `CloudAppEvents` (Advanced Hunting / Defender XDR)
  - `UrlClickEvents` (Advanced Hunting)
  - `EmailEvents` (Advanced Hunting)
  - Microsoft Purview Audit (Premium) — if Sentinel retention insufficient

> ⚠️ **Retention check required before running queries.** Default Sentinel Log Analytics retention is 90 days for most tables. Advanced Hunting (CloudAppEvents, EmailEvents, UrlClickEvents) defaults to 30 days, up to 180 days with add-on. If compromise started December 2025, data may be partially or fully rolled off. Check: `Log Analytics workspace > Usage and estimated costs > Data Retention` before proceeding. If data is unavailable in Sentinel, query Purview Audit (Premium) directly via the compliance portal — E5 licensing provides up to 1 year retention on key audit events.

---

## Pre-Hunt Checklist

- [x] Confirm UPN behind Account Object ID `5d28b71f-3fb6-48eb-9aea-b1011d09535b` via SigninLogs
- [x] Check Sentinel workspace retention setting — confirm how far back data exists
- [x] Check Advanced Hunting retention setting in Defender XDR portal
- [ ] Confirm Purview Audit Premium is enabled for the compromised user
- [ ] Confirm `SearchQueryInitiatedExchange` events are available (requires Purview Audit Premium)
- [ ] Run ASN lookup on sign-in IP from the Outlook auth event — check for M247 Europe SRL (AS9009) to confirm Tycoon2FA attribution
- [ ] Confirm `CloudAppEvents` is receiving MCAS-sourced Graph API events in your environment

---

## Queries

### Query 1 — Establish Full Sign-in Timeline (Run First)

```kql
// Table: SigninLogs

// Schema: Sentinel / Log Analytics
// Purpose: Build complete sign-in timeline for compromised account over 5-month window

SigninLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| where ResultType == 0
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend DeviceOS = tostring(DeviceDetailParsed.operatingSystem)
| extend IsCompliant = tostring(DeviceDetailParsed.isCompliant)
| extend IsManaged = tostring(DeviceDetailParsed.isManaged)
| extend TrustType = tostring(DeviceDetailParsed.trustType)
| extend DeviceId = tostring(DeviceDetailParsed.deviceId)
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 14 or HourOfDay > 24
| extend Weekend = DayOfWeek == 0d or DayOfWeek == 6d
| sort by TimeGenerated asc
| serialize
| extend HoursSincePrev = datetime_diff("hour", TimeGenerated, prev(TimeGenerated))
| project
    TimeGenerated,
    UserDisplayName,
    UserPrincipalName,
    AppDisplayName,
    ClientAppUsed,
    IPAddress,
    Location,
    HourOfDay,
    OutsideBusinessHours,
    Weekend,
    HoursSincePrev,
    IsCompliant,
    IsManaged,
    TrustType,
    DeviceId,
    DeviceOS,
    RiskLevelDuringSignIn,
    RiskDetail,
    ConditionalAccessStatus,
    AuthenticationDetails
| order by TimeGenerated asc
```

> ⚠️ **Schema note:** `prev()` function operates on the current query result set sorted ascending — validate ordering is correct before interpreting `HoursSincePrev`. `DeviceDetail` fields are nested JSON — boolean vs string handling for `isCompliant` may vary.

**What to look for:**
- Sign-ins from IPs inconsistent with the user's normal work location
- Regular `HoursSincePrev` intervals — automated refresh often occurs every 60–72 hours on a schedule
- `OutsideBusinessHours == true` combined with `IsCompliant != true`
- Location jumps that are geographically impossible in the time elapsed
- Sweden Central / Azure datacenter IP ranges appearing before May 5

---

### Query 2 — Guest Account Invitations (Priority 1 — Survives Remediation)

```kql
// Table: AuditLogs

// Schema: Sentinel / Log Analytics

// Purpose: Detect guest accounts invited by the compromised account during access window

AuditLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-06T00:00:00Z))
| where OperationName in (
    "Invite external user",
    "Add user",
    "Redeem external user invite",
    "Add member to group"
  )
| extend InitiatedByParsed = parse_json(InitiatedBy)
| extend TargetResourcesParsed = parse_json(TargetResources)
| extend InitiatorId = tostring(InitiatedByParsed.user.id)
| extend InitiatorUPN = tostring(InitiatedByParsed.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedByParsed.app.displayName)
| extend TargetUPN = tostring(TargetResourcesParsed[0].userPrincipalName)
| extend TargetType = tostring(TargetResourcesParsed[0].type)
| where InitiatorId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
      or InitiatorUPN == "adam.mussack@barwpetroleum"

| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatorUPN,
    InitiatorId,
    InitiatorApp,
    TargetUPN,
    TargetType,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

> ⚠️ **Schema note:** `InitiatedBy` path differs for user-initiated vs app-initiated events. `TargetResources[0]` — array indexing; validate single vs multi-target events in your environment.

**Disposition:** Any result here is `Confirmed TTP` until proven otherwise. Guest accounts created during this window that are not operationally justified must be disabled immediately and investigated separately — they are a persistence mechanism that survives all other remediation.
Advanced Hunting rule Created

---

### Query 3 — App Registration and OAuth Changes (Priority 2 — Survives Remediation)

```kql
// Table: AuditLogs
// Schema: Sentinel / Log Analytics
// Purpose: Detect app registrations, service principal changes, and OAuth consent grants
//          made by the compromised account during the access window
AuditLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-06T00:00:00Z))
| where OperationName in (
    "Add application",
    "Update application",
    "Add service principal",
    "Update service principal",
    "Add OAuth2PermissionGrant",
    "Add app role assignment to service principal",
    "Consent to application",
    "Add owner to application",
    "Add client secret to application",
    "Add certificate to application"
  )
| extend InitiatedByParsed = parse_json(InitiatedBy)
| extend TargetResourcesParsed = parse_json(TargetResources)
| extend InitiatorId = tostring(InitiatedByParsed.user.id)
| extend InitiatorUPN = tostring(InitiatedByParsed.user.userPrincipalName)
| extend TargetApp = tostring(TargetResourcesParsed[0].displayName)
| extend TargetId = tostring(TargetResourcesParsed[0].id)
| where InitiatorId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
      or InitiatorUPN == "adam.mussack@barwpetroleum.com"
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatorUPN,
    InitiatorId,
    TargetApp,
    TargetId,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

**Disposition:** Any app registration or OAuth grant created by the compromised account during this window is `Confirmed TTP`. Disable the app and revoke the grant immediately, then investigate what permissions it had and whether it has been used independently since creation.
Advanced Hunting rule created. 


---

### Query 4 — Silent Token Refresh Pattern Detection

```kql
// Table: SigninLogs
// Schema: Sentinel / Log Analytics
// Purpose: Summarise sign-in pattern by week to surface automated token refresh cadence
// Note SigninLogs is interactive signins only.
SigninLogs
| where TimeGenerated between (datetime(2025-11-24T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| where ResultType == 0
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend IsCompliant = tostring(DeviceDetailParsed.isCompliant)
| extend HourOfDay = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 14 or HourOfDay > 24
| extend WeekNumber = week_of_year(TimeGenerated)
| summarize
    SignInsThisWeek = count(),
    OutsideHoursCount = countif(OutsideBusinessHours == true),
    NonCompliantCount = countif(IsCompliant != "true"),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    UniqueApps = dcount(AppDisplayName),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by WeekNumber
| extend OutsideHoursPct = round(100.0 * OutsideHoursCount / SignInsThisWeek, 1)
| extend NonCompliantPct = round(100.0 * NonCompliantCount / SignInsThisWeek, 1)
| order by WeekNumber asc
```

**What to look for:** Weeks where `OutsideHoursPct` is high, `NonCompliantPct` is high, and `UniqueIPs` is low but different from the user's normal work IP. A legitimate user will have variable sign-in patterns; an automated token refresh will be unnervingly consistent.

---

### Query 5 — Mailbox Access — Finance and Payment Keywords

```kql
// Table: OfficeActivity
// Schema: Sentinel / Log Analytics
// Purpose: Detect targeted mailbox searches using finance and payment keywords
//          over the full 5-month window — BEC actors read email at low frequency
//          to map payment workflows, vendor relationships, and approval chains
//          SearchQueryInitiatedExchange requires Purview Audit Premium (E5)
let FinanceKeywords = dynamic([
    "invoice", "wire", "transfer", "payment", "banking",
    "remittance", "swift", "routing", "payroll", "salary",
    "budget", "vendor", "supplier", "account number",
    "deposit", "eft", "direct deposit", "bank", "interac"
]);
OfficeActivity
| where TimeGenerated between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "REPLACE-WITH-COMPROMISED-UPN"
| where Operation in (
    "MailItemsAccessed",
    "SearchQueryInitiatedExchange"
  )
| extend HourOfDay = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 7 or HourOfDay > 19
| extend SearchQuery = tostring(parse_json(tostring(OperationProperties))[0].Value)
| extend FinanceHit = SearchQuery has_any (FinanceKeywords)
| project
    TimeGenerated,
    Operation,
    UserId,
    ClientIP,
    MailboxOwnerUPN,
    OutsideBusinessHours,
    SearchQuery,
    FinanceHit,
    AffectedItems,
    OperationProperties
| order by TimeGenerated asc
```

> ⚠️ **Schema note:** `SearchQueryInitiatedExchange` requires Purview Audit Premium. `OperationProperties` array structure varies — validate SearchQuery extraction against a real event. `MailboxOwnerUPN` availability depends on audit plan tier.

---

### Query 6 — Low-Frequency Mailbox Access Pattern

```kql
// Table: OfficeActivity
// Schema: Sentinel / Log Analytics
// Purpose: Summarise mailbox access by week to surface low-frequency access pattern
//          Nation-state and patient BEC actors access small numbers of items per session
//          to avoid bulk-access anomaly detection — look for consistent low-volume
//          access rather than single large access events
OfficeActivity
| where TimeGenerated between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "REPLACE-WITH-COMPROMISED-UPN"
| where Operation in ("MailItemsAccessed", "Send", "SearchQueryInitiatedExchange")
| extend HourOfDay = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 7 or HourOfDay > 19
| extend WeekNumber = week_of_year(TimeGenerated)
| summarize
    AccessEvents = count(),
    OutsideHoursEvents = countif(OutsideBusinessHours == true),
    UniqueClientIPs = dcount(ClientIP),
    Operations = make_set(Operation)
    by WeekNumber
| order by WeekNumber asc
```

**What to look for:** Consistent low `AccessEvents` per week (1–5) from a single non-corporate IP outside business hours. Compare against the user's baseline from earlier months if data allows.

---

### Query 7 — SharePoint and OneDrive File Access

```kql
// Table: OfficeActivity
// Schema: Sentinel / Log Analytics
// Purpose: Detect sensitive document access over the full window
//          Outlook token had Files.ReadWrite.All — full SharePoint/OneDrive surface accessible
//          Attacker maps document libraries and downloads sensitive files at low frequency
let SensitiveTerms = dynamic([
    "payroll", "salary", "finance", "invoice", "wire",
    "transfer", "budget", "banking", "vendor", "contract",
    "password", "credential", "network", "vpn", "admin",
    "ammonium", "fertilizer", "scada", "plc", "ot"  // OT/plant documents also in scope
]);
OfficeActivity
| where TimeGenerated between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where UserId == "REPLACE-WITH-COMPROMISED-UPN"
| where RecordType in ("SharePointFileOperation", "OneDrive")
| where Operation in (
    "FileAccessed",
    "FileDownloaded",
    "FilePreviewed",
    "FileAccessedExtended",
    "FileSyncDownloadedFull",
    "FolderBrowsed",
    "SearchQueryInitiatedSharePoint"
  )
| extend HourOfDay = hourofday(TimeGenerated)
| extend OutsideBusinessHours = HourOfDay < 7 or HourOfDay > 19
| extend SensitiveFile = SourceFileName has_any (SensitiveTerms)
              or SourceRelativeUrl has_any (SensitiveTerms)
              or SiteUrl has_any (SensitiveTerms)
| project
    TimeGenerated,
    Operation,
    UserId,
    ClientIP,
    SourceFileName,
    SourceRelativeUrl,
    SiteUrl,
    OutsideBusinessHours,
    SensitiveFile
| order by TimeGenerated asc
```

> ⚠️ Note: OT/SCADA terms added to `SensitiveTerms` — if any plant documentation is stored in SharePoint, this surfaces access to it. Given the Iranian APT threat to your Rockwell/Allen-Bradley environment, flag any hits on OT-related documents immediately as `#action-required`.

---

### Query 8 — Per-User Graph API Deep Enumeration

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting
// Purpose: Detect per-user Graph API calls using object GUIDs from the initial enumeration
//          After bulk user search, attacker calls per-user endpoints for group membership,
//          org hierarchy, mailbox structure, drive contents, and calendar
CloudAppEvents
| where Timestamp between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where AccountId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| where Application has_any ("Microsoft Graph", "Office 365", "Exchange Online")
| extend RequestUri = tostring(parse_json(RawEventData).RequestUri)
| where RequestUri matches regex @"/v1\.0/users/[0-9a-f\-]{36}/(memberOf|manager|directReports|drives|mailFolders|messages|calendar|calendarView|contacts|events)"
      or RequestUri has_any (
          "/groups",
          "/directoryRoles",
          "/roleManagement",
          "/servicePrincipals",
          "/drives",
          "/sites",
          "transitiveMembers",
          "appRoleAssignments",
          "sensitiveTypes",
          "dataLossPreventionPolicies",
          "sensitivityLabels"
      )
| project
    Timestamp,
    AccountId,
    AccountDisplayName,
    IPAddress,
    CountryCode,
    ActionType,
    RequestUri,
    RawEventData
| order by Timestamp asc
```

> ⚠️ **Schema note:** `RawEventData.RequestUri` field availability in `CloudAppEvents` for Graph API calls depends on MCAS connector configuration. Validate field extraction in environment before relying on regex match.

---

### Query 9 — Teams and Calendar Access

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting
// Purpose: Detect Teams chat and calendar access — Chat.ReadWrite and
//          OnlineMeetings.Read were in the token scope
//          Attackers read Teams to harvest payment discussions and executive travel
//          schedules — travel windows are used to time BEC attempts when approvers
//          are unavailable or distracted
CloudAppEvents
| where Timestamp between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where AccountId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| where Application has_any ("Microsoft Teams", "Microsoft Graph")
| extend RequestUri = tostring(parse_json(RawEventData).RequestUri)
| where RequestUri has_any (
    "/chats",
    "/messages",
    "/calendar",
    "/events",
    "/calendarView",
    "/onlineMeetings"
  )
  or ActionType in (
    "ChatMessageRead",
    "ChatCreated",
    "TeamsSessionStarted",
    "MemberAdded"
  )
| project
    Timestamp,
    AccountId,
    IPAddress,
    CountryCode,
    ActionType,
    RequestUri,
    RawEventData
| order by Timestamp asc
```

---

### Query 10 — DLP and Sensitive Info Type Enumeration

```kql
// Table: CloudAppEvents
// Schema: Advanced Hunting
// Purpose: Detect enumeration of DLP policies and sensitive information type definitions
//          SensitiveInfoType.Read.All and DataLossPreventionPolicy.Evaluate were in scope
//          Attacker maps what data classifications exist to understand protection posture
//          and potentially to avoid triggering DLP rules during exfiltration
CloudAppEvents
| where Timestamp between (datetime(2025-12-01T00:00:00Z) .. datetime(2026-05-05T02:22:00Z))
| where AccountId == "5d28b71f-3fb6-48eb-9aea-b1011d09535b"
| extend RequestUri = tostring(parse_json(RawEventData).RequestUri)
| where RequestUri has_any (
    "sensitiveTypes",
    "dataLossPreventionPolicies",
    "informationProtection",
    "sensitivityLabels",
    "dlpPolicies",
    "protectionPolicies"
  )
| project
    Timestamp,
    AccountId,
    IPAddress,
    CountryCode,
    ActionType,
    RequestUri,
    RawEventData
| order by Timestamp asc
```

---

### Query 11 — Phishing Delivery Identification

```kql
// Table: EmailEvents + UrlClickEvents
// Schema: Advanced Hunting
// Purpose: Find the phishing email that initiated the AiTM compromise
//          Delivery domain is an actionable IOC for MDO block list and sector sharing
//          Look in the 7 days before earliest suspicious sign-in identified in Query 1
EmailEvents
| where Timestamp between (datetime(2025-11-24T00:00:00Z) .. datetime(2025-12-15T00:00:00Z))
| where RecipientEmailAddress == "REPLACE-WITH-COMPROMISED-UPN"
| where ThreatTypes != ""
      or DeliveryAction != "Delivered"
      or UrlCount > 0
| project
    Timestamp,
    SenderFromAddress,
    SenderIPv4,
    SenderDisplayName,
    Subject,
    ThreatTypes,
    DeliveryAction,
    UrlCount,
    AttachmentCount,
    AuthenticationDetails
| order by Timestamp desc
```

```kql
// Table: UrlClickEvents
// Schema: Advanced Hunting
// Purpose: Find the URL click that initiated the AiTM proxy session
//          The clicked URL is the phishing domain — extract for IOC blocking
UrlClickEvents
| where Timestamp between (datetime(2025-11-24T00:00:00Z) .. datetime(2025-12-15T00:00:00Z))
| where AccountUpn == "REPLACE-WITH-COMPROMISED-UPN"
| where IsClickedThrough == true
| extend UrlDomain = tostring(parse_url(Url).Host)
| project
    Timestamp,
    AccountUpn,
    Url,
    UrlDomain,
    ActionType,
    IsClickedThrough,
    IPAddress
| order by Timestamp desc
```

> ⚠️ **Schema note:** Adjust the timeframe once Query 1 identifies the earliest anomalous sign-in — search the 7 days before that date rather than the fixed window above. `IsClickedThrough` field — confirm boolean availability in your UrlClickEvents data.

---

## Findings

| Timestamp | Host | User | Observation | Disposition |
|-----------|------|------|-------------|-------------|
| 2026-05-05 02:21:56 UTC | N/A — Graph API | REPLACE-WITH-UPN | Graph API GET /v1.0/users?$search= returned HTTP 200. Bulk user enumeration of payroll/finance/HR/admin users. Sweden Central. | `Confirmed TTP` |
| | | | | |

---

## Query Execution Log

| Query | Run Date | Result | Notes |
|-------|----------|--------|-------|
| Q1 — Sign-in timeline | | | |
| Q2 — Guest invitations | | | |
| Q3 — App registration changes | | | |
| Q4 — Token refresh pattern | | | |
| Q5 — Mailbox keyword search | | | |
| Q6 — Low-frequency mailbox pattern | | | |
| Q7 — SharePoint/OneDrive file access | | | |
| Q8 — Per-user Graph deep enumeration | | | |
| Q9 — Teams and calendar access | | | |
| Q10 — DLP enumeration | | | |
| Q11 — Phishing delivery | | | |

---

## Conclusion

> Pending — update after queries are run. Key questions to answer:
> 1. What is the earliest anomalous sign-in attributable to the attacker?
> 2. Were any guest accounts or app registrations created during the window?
> 3. Was mailbox content accessed — specifically finance/payment keyword searches?
> 4. Was SharePoint/OneDrive accessed — specifically sensitive documents?
> 5. Was the phishing delivery email identified and the domain extracted?
> 6. Does the IP from the sign-in event resolve to M247 Europe SRL (AS9009) — confirming Tycoon2FA?

---

## Follow-on Actions

- [ ] Resolve UPN from Account Object ID `5d28b71f-3fb6-48eb-9aea-b1011d09535b` — required before running user-scoped queries
- [ ] Check Sentinel and Advanced Hunting retention settings before running extended window queries
- [ ] Run Q2 (guest invitations) and Q3 (app registrations) immediately — these are the only activities that survive remediation
- [ ] Run Q1 (sign-in timeline) to establish attacker access pattern and identify earliest compromise date
- [ ] Run Q11 (phishing delivery) once earliest sign-in date is known — adjust timeframe accordingly
- [ ] Extract phishing domain from UrlClickEvents and submit to MDO tenant block list
- [ ] Run IP from Outlook sign-in event through ASN lookup — check for M247 Europe SRL (AS9009)
- [ ] If Q5/Q6 return mailbox access hits — assess BEC risk and notify finance, payroll, and HR leads
- [ ] If Q7 returns SharePoint hits — identify specific documents accessed and assess sensitivity
- [ ] If Q2 returns any results — disable guest accounts immediately and escalate to IR case
- [ ] If Q3 returns any results — disable app registrations and revoke OAuth grants immediately
- [ ] Update [[FIND-Graph-API-User-Enumeration-Sweden-Central]] with findings
- [ ] Update [[INTEL-Tycoon2FA-AiTM-PhaaS-Platform]] with any attribution confirmation
- [ ] Consider external IR engagement if Q2, Q3, or Q5 return positive results — scope expands significantly

---

## Related Notes

- [[FIND-Graph-API-User-Enumeration-Sweden-Central]]
- [[HUNTING-Post-Graph-Enumeration-O365-Follow-On]]
- [[KQL-Graph-API-User-Enumeration-Detection]]
- [[INTEL-Tycoon2FA-AiTM-PhaaS-Platform]]
- [[HARD-Require-Compliant-Device-Office-365]]
- [[HARD-Token-Protection-Office-365]]
- [[HARD-Block-High-Risk-Sign-ins]]
- [[HARD-Contractor-CA-Policy-Unmanaged-Devices]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-05-05 | Created — extended scope hunt following 5-month access window hypothesis. Triggered by confirmed Graph API enumeration incident. Initial O365 follow-on queries (post-enumeration window only) in separate note: [[HUNTING-Post-Graph-Enumeration-O365-Follow-On]]. |
