---
title: INTEL-PhantomCtx-Activation-Context-Hijacking-EDR-Evasion
date: 2026-06-24
source: "https://github.com/r3xmax/PhantomCtx"
author: "r3xmax"
mitre:
  - "T1574.002"
  - "T1562.001"
  - "T1055"
detection_candidate: true
tags:
  - "#intel"
  - "#status/draft"
  - "#endpoint"
---

# INTEL -- PhantomCtx: Activation Context Hijacking EDR Evasion Tool

---

## Source

| Field | Detail |
|-------|--------|
| **URL** | https://github.com/r3xmax/PhantomCtx |
| **Author** | r3xmax |
| **Date Observed** | 2026-06-24 |
| **Date Published** | 2026 (new, 24k+ stars per Trendshift) |
| **Category** | EDR evasion / defense evasion PoC |
| **Prior Art** | Kudaes/Eclipse (Activation Context Hijack, similar technique) |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1574.002 | Hijack Execution Flow: DLL Side-Loading |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1055 | Process Injection |

---

## Summary

PhantomCtx is a new (2026) open-source Windows evasion tool abusing the Windows
Activation Context (ActCtx) mechanism to bypass EDR hooks and telemetry. Activation
Contexts are a Windows feature (Side-by-Side / SxS assemblies) designed to allow
applications to use specific DLL versions without registry-based COM conflicts. The
mechanism determines which DLL implementations are loaded for a given process at
runtime based on XML manifests embedded in executables or provided as sidecar files.

**The abuse primitive:** By tampering with or hijacking the Activation Context, an
attacker can redirect how Windows resolves DLL loads inside a target process. This
enables:

1. **DLL substitution before EDR hooks land** -- EDR products inject their monitoring
   DLLs into processes and hook user-mode API calls (e.g. `NtAllocateVirtualMemory`,
   `NtCreateThread`) to observe behavior. Activation Context hijacking can intercept
   the DLL load chain *before* EDR hooks are placed, redirecting loads to attacker-
   controlled versions of system DLLs with hooks removed or neutralized.

2. **COM object hijacking without registry modification** -- ActCtx can instantiate
   COM objects without registry entries, providing a persistence/execution path that
   bypasses registry-monitoring detections.

3. **ETW telemetry interception** -- Related techniques (documented in Eclipse/Kudaes)
   show that by impersonating DLLs via this mechanism, all calls can be intercepted
   before entering kernel mode, effectively denying ETW telemetry to the EDR -- a
   more powerful bypass than standard ETW patching.

**Why it's notable:** PhantomCtx is a new 2026 tool with 24,000+ stars on Trendshift,
indicating rapid adoption in the offensive security community. User-mode EDR bypass
is increasingly commoditized, but the Activation Context hijacking angle is less
commonly defended against because it operates at a lower layer than most detection
logic expects, and leaves minimal forensic artifacts compared to BYOVD approaches.

**Threat context:** EDR evasion is now commoditized, with bypass tools selling on
underground forums for $300 to $10,000, making endpoint defense circumvention
accessible to low-skill threat actors. PhantomCtx adds a PoC to the public
toolkit that threat actors can operationalize.

---

## Relevance to Environment

Medium -- no confirmed ITW use in campaigns targeting the environment's sector (agriculture/
fertilizer/OT), but the technique class is directly relevant:

- MDE is the primary endpoint detection control across ~150 endpoints plus POS
  terminals. If PhantomCtx-class techniques are weaponized in malspam (like DeskVB RAT)
  or supply chain attacks (TeamPCP FIRESCALE), they could reduce MDE visibility.
- BYOVD (kernel-mode EDR kill) is the more common threat in the current ransomware
  landscape, but user-mode ActCtx hijacking is harder to detect because it doesn't
  require a vulnerable driver.
- ASR rules and WDAC (currently in planning) are the most effective compensating
  controls -- application allowlisting prevents the substituted DLL from loading in
  the first place, regardless of the ActCtx hijack.

---

## Detection Notes

This class of technique is genuinely difficult to detect post-execution because:
- No new process creation, no dropped file on disk, minimal ETW telemetry if the
  bypass succeeds
- The DLL that loads looks legitimate (same name as the real DLL)

**Most effective detection approaches:**

1. **Image Load events** -- `DeviceImageLoadEvents` in MDE captures DLL loads. A
   legitimate process loading a DLL from an unexpected path (not `System32` or a
   known application directory) is the primary signal. ActCtx-redirected DLLs may
   load from a user-writable path.

2. **WDAC / Application Control** -- if the substituted DLL isn't signed by a
   trusted publisher, WDAC in enforcement mode will block it. This is the most
   robust mitigation and aligns with the active WDAC deployment project.

3. **MDE Tamper Protection** -- ensure Tamper Protection is enabled; it protects
   MDE's own sensor DLLs against some substitution attempts.

### KQL Stubs

```kql
// Table: DeviceImageLoadEvents
// Schema: Advanced Hunting (MDE)
// Purpose: Surface DLL loads from unexpected/user-writable paths that may indicate
// ActCtx hijacking redirecting a system DLL to an attacker-controlled version.
// NOTE: This will be noisy -- requires a baseline of known legitimate DLL load paths
// for common system DLLs before deploying as a rule.

DeviceImageLoadEvents
| where Timestamp > ago(1d)
// Focus on common system DLLs that EDR products and the OS depend on
| where FileName in~ (
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
    "advapi32.dll", "ws2_32.dll", "user32.dll"
)
// Flag loads from outside System32 / SysWOW64 / known application paths
| where not(FolderPath has_any (
    @"C:\Windows\System32",
    @"C:\Windows\SysWOW64",
    @"C:\Windows\WinSxS"
))
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### Validated Columns
- [ ] `DeviceImageLoadEvents` -- confirm table is available and populated in tenant
- [ ] `FolderPath` -- confirm field name for DLL load path in this table
- [ ] Establish baseline of legitimate non-System32 DLL loads before deploying

---

## Hardening Actions

- [ ] **Confirm MDE Tamper Protection is enabled** on all managed endpoints (Intune
  policy) -- protects MDE sensor DLLs against substitution attempts
- [ ] **WDAC deployment** -- application allowlisting is the most robust control;
  unsigned or non-allowlisted DLLs cannot load regardless of ActCtx manipulation.
  Ties directly into active WDAC Phase 1 Audit project.
- [ ] **Review ASR rules** -- confirm "Block process creations originating from PSExec
  and WMI commands" and related rules are enforcing, as they reduce the attack surface
  for ActCtx-based injection chains

---

## Related Notes

- [[RULE-Encoded-PowerShell-Commands-With-Web-Request-Tuned]]
- [[PROJ-WDAC-Phase1-Audit]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-06-24 | Created -- new 2026 evasion tool, 24k+ stars; ActCtx hijacking explained; MDE image load detection stub; WDAC flagged as primary mitigation |
