# KQL — NTLMv2 Downgrade Detection

**Table:** `SecurityEvent`, `DeviceLogonEvents`
**Schema:** Sentinel (Log Analytics) / Advanced Hunting
**MITRE ATT&CK:** T1557.001 | **Tactic:** Credential Access | **Technique:** Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
**Created:** 2026-04-24 | **Status:** `Draft`

---

## Purpose
Detects NTLM authentication events where the negotiated version is NTLMv1 rather than NTLMv2, indicating either a misconfigured endpoint that has not received the NTLMv2 enforcement policy or an active downgrade attempt. Should be deployed alongside the NTLMv2 hardening control — any hits post-enforcement are high fidelity and worth investigating.

---

## Query

```kql
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| extend NTLMVersion = tostring(parse_json(tostring(EventData)).LmPackageName)
| where NTLMVersion has "LM" or NTLMVersion == "NTLM V1"
| project
    TimeGenerated,
    Computer,
    TargetUserName,
    TargetDomainName,
    IpAddress,
    WorkstationName,
    NTLMVersion,
    LogonType
| order by TimeGenerated desc
```

---

## Validated Columns

| Column Used               | Confirmed? | Notes                                                        |
| ------------------------- | ---------- | ------------------------------------------------------------ |
| EventID                   |  ⬜         | Standard SecurityEvent column                                |
| AuthenticationPackageName | ⬜          | Confirm present in your SecurityEvent table                  |
| EventData                 | ⬜          | XML blob — LmPackageName parsed from inside it               |
| TimeGenerated             | ⬜          | Standard                                                     |
| Computer                  | ⬜          | Standard                                                     |
| TargetUserName            | ⬜          | Standard SecurityEvent column                                |
| TargetDomainName          | ⬜          | Standard SecurityEvent column                                |
| IpAddress                 | ⬜          | Confirm — may appear as `IpAddress` or differ in your schema |
| WorkstationName           | ⬜          | Standard SecurityEvent column                                |
| LogonType                 | ⬜          | Standard SecurityEvent column                                |

> Run query and confirm column names before setting status to Tested. IpAddress in SecurityEvent is known to vary.

---

## Test Results
> Paste output here after first run. Note any unexpected columns, null values, or false positives.
> Expected: any endpoints that haven't received the NTLMv2 GPO/Intune policy, or legacy devices.

---

## Sentinel Analytics Rule
- **Rule Name:** NTLMv2 Downgrade — NTLMv1 Authentication Detected
- **Frequency:** Every 1 hour
- **Lookback:** Last 1 hour
- **Severity:** `Medium` (elevate to `High` post-enforcement deployment)
- **Deployed:** ❌

---

## Hardening Control Pair
[[Hardening/Controls/NTLMv2-Enforcement|NTLMv2 Enforcement Control]]

> Post-enforcement, any hits from this query are anomalous. Consider bumping severity to High once the control is confirmed deployed across fleet.

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-24 | Created |
