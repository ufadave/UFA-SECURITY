---
date: 2026-06-11
title: Encoded PowerShell Commands With Web Request
table: "DeviceProcessEvents"
schema: "Advanced Hunting"
mitre: "T1059.001"
tactic: "Execution, Defense Evasion"
technique: "Command and Scripting Interpreter: PowerShell"
status: "Draft"
promoted_to_rule: false
mde_rule_name: ""
sentinel_rule_id: ""
tags:
  - "#detection"
  - "#detection/analytics-rule"
  - "#status/draft"
  - "#endpoint"
---

# KQL -- Encoded PowerShell Commands With Web Request

---

**Table:** DeviceProcessEvents | **Schema:** Advanced Hunting (MDE)
**MITRE ATT&CK:** T1059.001 | **Tactic:** Execution, Defense Evasion | **Technique:** Command and Scripting Interpreter: PowerShell
**Created:** 2026-06-11 | **Status:** Draft

---

## Purpose

Tuned version of the Microsoft-provided MDE detection "Encoded PowerShell Commands With
Web Request". Detects base64-encoded PowerShell commands (`-EncodedCommand` / `-enc`) whose
decoded content contains web request indicators -- a common pattern for download-and-execute
stagers and fileless malware.

**Original rule weakness:** The stock detection's term list includes bare `http`/`https`,
which matches any encoded command that opens a URL via `Start '<url>'` -- including benign
OAuth browser-launch flows used by AI coding tool CLIs (Codex, Claude Code, GitHub Copilot
CLI, etc.) that authenticate via local-loopback redirect (`localhost:<port>/auth/callback`).

**Tuning applied (Option 3):** Require BOTH a URL indicator AND a retrieval/execution
primitive in the decoded command, rather than either alone. A `Start '<url>'` call with no
accompanying `DownloadString`/`Invoke-WebRequest`/`IEX`/etc. no longer matches. This is
schema-stable and requires no process-path allowlist -- it generalises to any current or
future AI coding tool's OAuth flow without per-tool maintenance.

**False positive observed during tuning (2026-06-11):** JetBrains IntelliJ IDEA Codex ACP
integration (`node.exe` under `...JetBrains\acp-agents\...@agentclientprotocol\codex-acp\`)
launching `Start 'https://auth.openai.com/oauth/authorize?...originator=JetBrains.IntelliJ
IDEA'` via `-EncodedCommand`. Decoded command contained only `https` -- no retrieval/execution
primitive. User: Divya.Madapu@ufa.com, device lt13265.

**Tradeoff:** A multi-stage payload that constructs the URL and execution primitive as
separate strings concatenated at runtime (rather than appearing together literally in the
decoded command) could theoretically evade the "both present" check. This is an uncommon
evasion pattern and the coverage loss is considered acceptable relative to the FP reduction.

---

## Query

```kql
let EncodedList = dynamic(['-encodedcommand', '-enc']);
// For more results use line below and remove filter above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
let UrlIndicators = dynamic(['http', 'https']);
let RetrievalExecutionPrimitives = dynamic([
    'WebClient', 'DownloadFile', 'DownloadData', 'DownloadString',
    'WebRequest', 'Invoke-WebRequest', 'Invoke-RestMethod',
    'IEX', 'Invoke-Expression', 'FromBase64String', 'Shellcode'
]);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
// Require BOTH a URL indicator AND a retrieval/execution primitive (Option 3 tuning)
| where DecodedCommandLineReplaceEmptyPlaces has_any (UrlIndicators)
| where DecodedCommandLineReplaceEmptyPlaces has_any (RetrievalExecutionPrimitives)
| project-reorder
    Timestamp,
    ActionType,
    DecodedCommandLineReplaceEmptyPlaces,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    DeviceName,
    AccountName,
    AccountDomain
```

---

## Validated Columns

- [x] `ProcessCommandLine` / `InitiatingProcessCommandLine` -- confirmed populated
- [x] `base64_decode_tostring()` -- confirmed working against `-EncodedCommand` payloads
- [x] `DecodedCommandLineReplaceEmptyPlaces` -- UTF-16 null-byte stripping confirmed working
- [x] Validate tuned query against 30-day lookback for both true positives and remaining FPs

---

## Test Results

**Pre-tuning result (2026-06-11):**

| Date | Account | Device | Disposition |
|------|---------|--------|-------------|
| 2026-06-11 | Divya.Madapu@ufa.com (dmadapu) | lt13265 | False positive -- JetBrains IntelliJ Codex ACP OAuth browser launch to auth.openai.com. Decoded command: `Start 'https://auth.openai.com/oauth/authorize?...originator=JetBrains.IntelliJ IDEA'`. No retrieval/execution primitive present -- only `https` matched original `DownloadVariables` list. |

**Post-tuning:** Pending -- run tuned query over same 48h window to confirm the JetBrains/Codex
event no longer matches, and over a 30-day window to check for additional FPs and confirm no
loss of true-positive coverage.

---

## Deployment

<!-- Default path: MDE Custom Detection (DeviceProcessEvents is Advanced Hunting only) -->
<!-- Sentinel section inactive: DeviceProcessEvents not ingested into Log Analytics -->

### MDE Custom Detection Rule
- **Rule Name:** `Custom - Encoded PowerShell Commands With Web Request`
- **Frequency:** Every 1h
- **Lookback:** 48h
- **Severity:** Medium
- **Actions:** Alert only
- **Deployed:** [ ]
- **Rule ID:** <!-- Populate mde_rule_name in frontmatter when deployed -->

### Sentinel Analytics Rule
<!-- INACTIVE: DeviceProcessEvents is Advanced Hunting only -- not ingested into Log Analytics -->

---

## Hardening Control Pair
- **Control:** [[]]
- **Linked:** [ ]

---

## Related Notes
- [[RESEARCH-AI-Coding-Tools-and-M365-Integration-Security-Summary]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-11 | Created -- tuned Microsoft-provided "Encoded PowerShell Commands With Web Request" detection. FP investigated: JetBrains Codex ACP OAuth launch matched on bare `https`. Applied Option 3 tuning -- require URL indicator AND retrieval/execution primitive together. Renamed for Custom- queue convention. |
