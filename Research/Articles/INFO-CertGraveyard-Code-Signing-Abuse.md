# Resource — CertGraveyard: Code-Signing Certificate Abuse Tracking & Reporting

**Source:** https://certgraveyard.org/ | https://pkilab.certgraveyard.org/
**Blog:** https://squiblydoo.blog/2026/04/01/the-certgraveyard/
**Tweet:** https://x.com/squiblydooblog/status/2047662020602814848
**Via:** Gmail inbox April 25 2026
**Date:** 2026-04-25
**Type:** Tool + Research

---

## What It Is
CertGraveyard is a public database and reporting platform for abused code-signing certificates, built by researcher Squiblydoo. The core problem it addresses: unlike SSL/TLS certificates, there is no public transparency log for code-signing certificates. Malware authors routinely obtain EV (Extended Validation) code-signing certificates using fake or impersonated business identities — these certificates make malware appear legitimate to Windows SmartScreen and many AV/EDR solutions.

CertGraveyard fills the gap by tracking, documenting, and reporting abused certificates directly to Certificate Authorities for revocation. When a CA revokes a certificate, it disrupts the entire malware campaign that relied on it — and since multiple threat actors often share one certificate, a single revocation can impact multiple campaigns simultaneously.

The `pkilab.certgraveyard.org` URL is the lab/research component for deeper certificate analysis.

---

## Why It Matters for Detection
Signed malware is a significant WDAC and MDE blind spot. Code-signed binaries get elevated trust from Windows SmartScreen and can bypass controls that block unsigned executables. Key threat actor behaviour:

- EV certificates issued to impostor businesses used to sign malware
- Microsoft Trusted Signing service increasingly abused (3-day certificates)
- One certificate often shared across multiple malware families and threat actors
- Revoked certificates still valid for already-signed files unless explicitly blocked

---

## Detection Notes
**Detect execution of signed binaries with revoked certificates:**
```kql
DeviceProcessEvents
| where ProcessVersionInfoCompanyName != "" 
| where InitiatingProcessSignerType == "Signed" 
| where InitiatingProcessSignatureStatus == "Revoked"
| project TimeGenerated, DeviceName, FileName, 
    InitiatingProcessSignerType, InitiatingProcessSignatureStatus,
    ProcessVersionInfoCompanyName
```

**Detect Microsoft Trusted Signing short-lived certificates (3-day certs):**
```kql
DeviceProcessEvents
| where InitiatingProcessSignerType == "Signed"
| where InitiatingProcessSignerName has "Microsoft ID Verified"
| project TimeGenerated, DeviceName, FileName, 
    InitiatingProcessSignerName, ProcessCommandLine
```

> Both queries require validation against your MDE schema — column names may differ.

---

## Tools
- **certReport** — CLI tool for generating certificate abuse reports: https://github.com/Squiblydoo/certReport
- **CertGraveyard web form** — submit abused certificates for CA revocation: https://certgraveyard.org
- **pkilab** — certificate analysis lab: https://pkilab.certgraveyard.org
- **debloat** — removes junk bytes from artificially inflated/padded malware: https://github.com/Squiblydoo/debloat

---

## Actions
- [ ] Bookmark CertGraveyard as a reference when investigating signed malware
- [ ] Validate MDE column names for certificate status queries above
- [ ] Consider adding revoked certificate execution to Sentinel analytics rules
- [ ] Check if WDAC policies account for revoked certificate handling

---

## Tags
#resource #tool #code-signing #certificates #wdac #smartscreen #squiblydoo #certgraveyard #signed-malware

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created — covers both certgraveyard.org and pkilab.certgraveyard.org emails |
