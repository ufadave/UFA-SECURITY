---
title: INTEL-DeskVB-RAT-Malspam-DoubleClick-In-Memory-Chain-2026-06
date: 2026-06-05
source: "https://www.huntress.com/blog/malspam-to-deskcvb-rat-delivery-chain-analysis"
author: "Huntress (Anna Pham, Adam Mooney)"
mitre:
  - "T1566.002"
  - "T1059.007"
  - "T1059.001"
  - "T1620"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
  - "#email"
---

# INTEL -- DeskVB RAT: Malspam to In-Memory RAT via DoubleClick Redirect

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://www.huntress.com/blog/malspam-to-deskcvb-rat-delivery-chain-analysis |
| **Author** | Huntress -- Anna Pham, Adam Mooney |
| **Date Observed** | 2026-06-05 |
| **Date Published** | 2026-06-03 |
| **First Seen ITW** | February 2026 |
| **Corroboration** | https://thehackernews.com/2026/06/google-doubleclick-abused-in-new.html |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1566.002 | Phishing: Spearphishing Link |
| T1059.007 | Command and Scripting Interpreter: JavaScript |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1620 | Reflective Code Loading (.NET reflection, in-memory) |

---

## Summary

DeskVB RAT (also rendered DesckVB) is a .NET-based remote access trojan active in the wild
since February 2026. In May 2026 the Huntress SOC responded to a DeskVB infection beginning
with malspam. The notable characteristics are the delivery chain and evasion approach rather
than the RAT capabilities themselves.

**Two standout techniques:**

1. **DoubleClick redirect for reputation laundering.** Before the malspam link reaches any
   attacker-controlled domain, it routes through `ad.doubleclick[.]net` -- a legitimate,
   high-reputation Google-owned domain that most email gateways and web proxies will not flag.
   The redirect chain uses Google's ad infrastructure as a trusted hop to bypass URL reputation
   filtering.

2. **Self-personalizing malspam kit.** The kit does not require per-target customization. It
   reads the victim's email address from the URL, rebuilds the phishing page on the fly, and
   pulls in the target company's logo live. No org-specific content is hardcoded -- making the
   operation scalable and cheap to run across many targets simultaneously.

**Five-stage in-memory chain:** HTML -> JScript -> PowerShell -> .NET loader -> RAT. The
attack leans heavily on in-memory execution and .NET reflection to avoid writing meaningful
artifacts to disk. The chain barely touches the filesystem.

**Key defensive insight from Huntress:** A gateway that inspects attachments *before* delivery
has an opportunity to break the chain at the start. This is a defense-in-depth reminder --
reputation-based URL filtering alone fails against the DoubleClick redirect.

---

## Relevance to Environment

Medium-High. This is a live, in-the-wild malspam campaign using a delivery technique
specifically designed to bypass email gateway URL reputation -- directly relevant to the
MDO-protected email estate. The DoubleClick redirect technique would evade Defender for
Office 365 Safe Links reputation checks since doubleclick.net is high-reputation.

The in-memory .NET reflection chain is the detection challenge -- minimal disk artifacts means
EDR behavioural detection (not file-based) is the primary control. MDE's in-memory and
AMSI-based detections are the relevant coverage.

---

## Detection Notes

### KQL Stubs

```kql
// Table: DeviceNetworkEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Surface web requests to doubleclick redirect followed quickly by connection
// to a low-prevalence domain -- the reputation-laundering redirect pattern.
// NOTE: doubleclick.net is extremely common in normal ad traffic -- this WILL be noisy.
// Tune by correlating with a subsequent script-host process spawn, not standalone.

let RedirectWindow = 2m;
let DoubleClickHits = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "ad.doubleclick.net"
| project RedirectTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName;
DoubleClickHits
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("wscript.exe", "cscript.exe", "powershell.exe", "mshta.exe")
) on DeviceId
| where Timestamp between (RedirectTime .. (RedirectTime + RedirectWindow))
| project RedirectTime, Timestamp, DeviceName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by RedirectTime desc
```

```kql
// Table: DeviceProcessEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Detect the script-chain handoff -- JScript/HTA spawning PowerShell
// which is the DeskVB stage 2->3 transition. Higher-fidelity than the redirect alone.

DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "mshta.exe")
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-e ", "FromBase64String",
    "DownloadString", "IEX", "Invoke-Expression", "reflection")
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine
| order by Timestamp desc
```

### Validated Columns
- [ ] `RemoteUrl` in DeviceNetworkEvents -- confirm doubleclick.net captured (likely high volume)
- [ ] Script-host -> PowerShell chain -- validate against normal admin scripting baseline

---

## Hardening Actions

- [ ] Confirm MDO Safe Attachments is inspecting attachments pre-delivery (Huntress key insight)
- [ ] Review whether ASR rule "Block JScript/VBScript from launching downloaded executable content" is enabled in Intune
- [ ] Confirm AMSI integration active for PowerShell in-memory script block logging
- [ ] Consider the script-chain stub (stub 2) for promotion -- higher fidelity than redirect detection

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-05 | Created -- Huntress DeskVB RAT analysis; DoubleClick redirect + in-memory chain; 2 KQL stubs |
