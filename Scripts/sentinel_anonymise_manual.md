# sentinel_anonymise — User Manual

**Version:** 1.0 | **Date:** 2026-05-05 | **Author:** Dave

---

## Overview

`sentinel_anonymise` is a local anonymisation tool for CSV exports from Microsoft Sentinel and Defender XDR Advanced Hunting queries. It detects and redacts personally identifiable information (PII) before you share query results externally — with vendors, IR firms, colleagues in other tenants, or AI assistants.

Two versions are provided:

| File | Requires | Best For |
|------|----------|----------|
| `sentinel_anonymise.py` | Python 3.8+ + pandas | Primary — more robust |
| `sentinel_anonymise.ps1` | PowerShell 5.1+ (built into Windows) | Fallback if Python unavailable |

Both versions produce identical output. Use the Python version where possible.

---

## What It Anonymises

The tool uses **consistent hashing** — the same input value always produces the same anonymised token. This preserves analytical relationships across rows and files. If `adam.smith@contoso.com` appears in 12 rows, it becomes the same `user_9d2fc127@redacted.local` in all 12 — you can still identify that the same user was involved without knowing who they are.

| Data Type | Example Input | Example Output |
|-----------|--------------|----------------|
| Email / UPN | `adam.smith@contoso.com` | `user_9d2fc127@redacted.local` |
| IPv4 address | `91.234.56.78` | `91.234.xxx.xxx` |
| IPv6 address | `2a04:1234::5678` | `ipv6_8ab70652` |
| Entra object GUID | `5d28b71f-3fb6-48eb-9aea-b1011d09535b` | `id_8ab706521cd6` |
| Display name | `Jane Smith` | `Person_a194c79e` |
| URL | `https://evil.com/path/to/file` | `https://host_3f2a1b4c/path/to/file` |
| Free text / JSON | Any cell containing the above | Inline scrub of detected values |

### Columns Handled by Name

The tool recognises these column names from common Sentinel and Advanced Hunting tables and applies targeted anonymisation:

| Column | Source Table | Treatment |
|--------|-------------|-----------|
| `UserPrincipalName` | SigninLogs | Email anonymisation |
| `UserDisplayName` | SigninLogs | Display name anonymisation |
| `IPAddress` | SigninLogs, CloudAppEvents | IP anonymisation |
| `UserId` | SigninLogs, OfficeActivity | GUID anonymisation |
| `CorrelationId` | SigninLogs, AuditLogs | GUID anonymisation |
| `InitiatorUPN` | AuditLogs | Email anonymisation |
| `InitiatorId` | AuditLogs | GUID anonymisation |
| `TargetUPN` | AuditLogs | Email anonymisation |
| `TargetId` | AuditLogs | GUID anonymisation |
| `ClientIP` | OfficeActivity | IP anonymisation |
| `MailboxOwnerUPN` | OfficeActivity | Email anonymisation |
| `AccountId` | CloudAppEvents | GUID anonymisation |
| `AccountDisplayName` | CloudAppEvents | Display name anonymisation |
| `AccountUpn` | CloudAppEvents, UrlClickEvents | Email anonymisation |
| `RecipientEmailAddress` | EmailEvents | Email anonymisation |
| `SenderFromAddress` | EmailEvents | Email anonymisation |
| `SenderIPv4` | EmailEvents | IP anonymisation |
| `SenderDisplayName` | EmailEvents | Display name anonymisation |
| `Url` | UrlClickEvents | URL anonymisation |
| `RequestUri` | CloudAppEvents | URL anonymisation |

Any column not in this list receives an **inline scrub** — the tool scans the cell value for recognisable PII patterns (email, IP, GUID) and replaces them in place.

### Columns Dropped Entirely

The following columns contain raw JSON blobs that are too deeply nested to reliably anonymise with pattern matching. They are removed from the output entirely:

- `RawEventData`
- `AdditionalDetails`
- `TargetResources`
- `InitiatedBy`
- `AuthenticationDetails`
- `OperationProperties`

These fields are rarely needed when sharing results for analysis.

---

## Installation

### Python Version

#### Step 1 — Check if Python is Already Installed

Open PowerShell or Command Prompt and run:

```powershell
python --version
```

If a version number is returned (e.g. `Python 3.11.4`), skip to Step 3. Python 3.8 or later is required.

Also try these alternatives if `python` is not found:

```powershell
py --version
python3 --version
```

#### Step 2 — Install Python (if not present)

**Option A — winget (recommended, no admin rights required):**

```powershell
winget install Python.Python.3.11
```

Close and reopen PowerShell after installation completes, then verify:

```powershell
python --version
```

**Option B — Microsoft Store:**

1. Open Microsoft Store
2. Search for **Python 3.11**
3. Click **Install**
4. Reopen PowerShell and verify with `python --version`

**Option C — Direct download:**

1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download the latest Python 3.x Windows installer
3. Run the installer — **tick "Add Python to PATH"** before clicking Install
4. Reopen PowerShell and verify with `python --version`

#### Step 3 — Install pandas

```powershell
pip install pandas
```

If you are on macOS or Linux:

```bash
pip install pandas --break-system-packages
```

Verify the installation:

```powershell
python -c "import pandas; print('pandas OK:', pandas.__version__)"
```

#### Step 4 — Save the Script

Save `sentinel_anonymise.py` to a convenient location. A dedicated tools folder is recommended:

```
C:\Users\<you>\Documents\Security-Tools\sentinel_anonymise.py
```

Or on macOS:

```
~/Documents/Security-Tools/sentinel_anonymise.py
```

---

### PowerShell Version (No Installation Required)

The PowerShell script uses only built-in .NET libraries — no additional installation is needed. PowerShell 5.1 is included in Windows 10 and Windows 11.

Save `sentinel_anonymise.ps1` to the same location as the Python script.

**First-run only — execution policy:**

If PowerShell blocks script execution, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Or bypass the policy for a single run without changing the setting:

```powershell
powershell -ExecutionPolicy Bypass -File .\sentinel_anonymise.ps1 -InputFile .\export.csv
```

---

## Usage

### Typical Workflow

1. Run your KQL query in Sentinel or Defender XDR
2. Export results as CSV
3. Run the anonymisation script on the exported file
4. Share the `_anonymised.csv` output — not the original

### Python Version

**Basic — anonymise a single file:**

```bash
python sentinel_anonymise.py emailevents.csv
```

Output: `emailevents_anonymised.csv` in the same directory.

**Specify output path:**

```bash
python sentinel_anonymise.py signinlogs.csv --output clean_signinlogs.csv
```

**Preserve /24 subnet (keep third octet):**

```bash
python sentinel_anonymise.py export.csv --preserve-subnet 24
```

Default is `/16` — `x.x.xxx.xxx`. Use `/24` (`x.x.x.xxx`) if subnet context at the /24 level is useful for your analysis.

**Generate a mapping file:**

```bash
python sentinel_anonymise.py export.csv --show-mapping
```

Creates `export_anonymised_mapping.json` alongside the output. This file maps original values to their tokens — keep it private, do not share it alongside the anonymised CSV.

**Multiple files at once:**

```bash
python sentinel_anonymise.py signinlogs.csv emailevents.csv cloudappevents.csv
```

Each file gets its own `_anonymised.csv` output. Hashing is consistent across all files in the same run — the same email address in two different files will produce the same token.

**Verbose output (shows each column as processed):**

```bash
python sentinel_anonymise.py export.csv --verbose
```

**All options:**

```
python sentinel_anonymise.py <input> [options]

Arguments:
  input                   Input CSV file(s)

Options:
  --output, -o PATH       Output file path (single file only)
  --preserve-subnet 16|24 IPv4 subnet octets to preserve (default: 16)
  --show-mapping          Write mapping JSON file alongside output
  --verbose, -v           Print each column as it is processed
```

---

### PowerShell Version

**Basic:**

```powershell
.\sentinel_anonymise.ps1 -InputFile .\emailevents.csv
```

**Specify output path:**

```powershell
.\sentinel_anonymise.ps1 -InputFile .\signinlogs.csv -OutputFile .\clean.csv
```

**Preserve /24 subnet:**

```powershell
.\sentinel_anonymise.ps1 -InputFile .\export.csv -PreserveSubnet 24
```

**Generate mapping file:**

```powershell
.\sentinel_anonymise.ps1 -InputFile .\export.csv -ShowMapping
```

**Verbose output:**

```powershell
.\sentinel_anonymise.ps1 -InputFile .\export.csv -Verbose
```

**Bypass execution policy for single run:**

```powershell
powershell -ExecutionPolicy Bypass -File .\sentinel_anonymise.ps1 -InputFile .\export.csv
```

**All parameters:**

```
-InputFile      <string>   Input CSV file path. Required.
-OutputFile     <string>   Output file path. Default: <input>_anonymised.csv
-PreserveSubnet <16|24>    IPv4 subnet preservation. Default: 16
-ShowMapping               Write mapping JSON alongside output
-Verbose                   Print each column as processed
```

---

## Output Files

### Anonymised CSV (`_anonymised.csv`)

The primary output. Safe to share. Contains all original columns except dropped JSON blobs, with PII replaced by consistent tokens.

### Mapping File (`_anonymised_mapping.json`)

Only generated when `--show-mapping` / `-ShowMapping` is specified.

```json
{
  "adam.smith@contoso.com": "user_9d2fc127@redacted.local",
  "91.234.56.78": "91.234.xxx.xxx",
  "5d28b71f-3fb6-48eb-9aea-b1011d09535b": "id_8ab706521cd6"
}
```

**Keep this file private.** It contains the original values. Do not share it alongside the anonymised CSV — doing so defeats the purpose of anonymisation.

Use it to reverse-look up a token if you need to action a specific finding after sharing results externally.

---

## Examples

### Anonymising an EmailEvents Export

```powershell
# Export your query results from Defender XDR to emailevents.csv
# Then run:
python sentinel_anonymise.py emailevents.csv --show-mapping
```

**Before:**

| Timestamp | SenderFromAddress | SenderIPv4 | RecipientEmailAddress | Subject |
|-----------|------------------|------------|----------------------|---------|
| 2026-05-04T22:15Z | attacker@evil.com | 91.234.56.78 | adam.smith@contoso.com | Verify your account |
| 2026-05-04T23:01Z | noreply@phish.net | 185.220.101.45 | adam.smith@contoso.com | Shared document |

**After:**

| Timestamp | SenderFromAddress | SenderIPv4 | RecipientEmailAddress | Subject |
|-----------|------------------|------------|----------------------|---------|
| 2026-05-04T22:15Z | user_68a9fce1@redacted.local | 91.234.xxx.xxx | user_9d2fc127@redacted.local | Verify your account |
| 2026-05-04T23:01Z | user_f87435ca@redacted.local | 185.220.xxx.xxx | user_9d2fc127@redacted.local | Shared document |

Note: `user_9d2fc127@redacted.local` appears twice — consistent hashing confirms both rows involve the same recipient, preserving the analytical relationship.

### Anonymising Multiple Exports From the Same Investigation

```powershell
python sentinel_anonymise.py signinlogs.csv emailevents.csv officeactivity.csv
```

Because hashing is consistent within a session, the same UPN or IP appearing across all three files will produce the same token in each — you can correlate across the anonymised outputs without knowing the original values.

---

## Limitations

**What this tool does not handle:**

- **Content inside dropped columns** — `RawEventData`, `AdditionalDetails`, etc. are removed entirely. If you need the content of these fields, extract the specific nested values you need into separate columns using `parse_json()` in your KQL query before exporting.
- **Names in free-text fields** — display names in known columns are anonymised, but names embedded in email subject lines, body text, or unrecognised free-text columns may not be detected. Review subjects and body content columns manually before sharing.
- **Non-English names** — the pattern matching approach may not detect all name formats in non-Latin scripts.
- **Internal hostnames** — hostnames in the format `HOSTNAME\username` or `\\server\share` are not specifically detected. If your exports contain these, review manually or add them to the script's column routing tables.
- **Aggregate queries** — the tool is designed for row-level exports. Summarised query output (e.g. counts by user) should be reviewed manually as the column names may not match the expected patterns.

**Cross-session consistency:**

Hashing is deterministic — the same input always produces the same token regardless of when or where the script is run. `adam.smith@contoso.com` will always hash to `user_9d2fc127@redacted.local`. You can compare tokens across exports run on different days or machines.

---

## Customisation

Both scripts have clearly labelled column routing tables at the top of the file. To add support for a column not currently handled:

**Python — add to the appropriate set in the configuration block:**

```python
EMAIL_COLUMNS = {
    "userprincipalname", "initiatorupn",
    "yournewcolumn",      # ← add here
}
```

**PowerShell — add to the appropriate HashSet:**

```powershell
$EmailColumns = [System.Collections.Generic.HashSet[string]]@(
    "userprincipalname", "initiatorupn",
    "yournewcolumn"    # ← add here
)
```

Column names are normalised before matching — underscores, spaces, and capitalisation are ignored. `My_Column`, `mycolumn`, and `MYCOLUMN` all match `mycolumn` in the routing table.

---

## Troubleshooting

### Python — `ModuleNotFoundError: No module named 'pandas'`

```powershell
pip install pandas
```

If `pip` is not found:

```powershell
python -m pip install pandas
```

### Python — `python` not recognised after installation

Close and reopen PowerShell. If still not found, Python was not added to PATH during installation. Reinstall and tick **"Add Python to PATH"**, or use the full path:

```powershell
C:\Users\<you>\AppData\Local\Programs\Python\Python311\python.exe sentinel_anonymise.py export.csv
```

### PowerShell — `execution of scripts is disabled`

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Or for a one-time run:

```powershell
powershell -ExecutionPolicy Bypass -File .\sentinel_anonymise.ps1 -InputFile .\export.csv
```

### Output file is empty or has only headers

Check that your input CSV has data rows and that the column names match the expected format. Run with `--verbose` / `-Verbose` to see which columns are being processed and whether any are being dropped unexpectedly.

### A column containing PII is not being anonymised

The column name may not be in the routing table. Check the column name in your export, normalise it (remove underscores, lowercase), and add it to the appropriate routing table as described in the Customisation section above. Alternatively, report the column name for addition to a future version.

---

## File Locations

Recommended storage location on your Mac (personal work):

```
~/Documents/Security-Tools/
├── sentinel_anonymise.py
├── sentinel_anonymise.ps1
└── README.md   ← this file
```

On your Windows work machine:

```
C:\Users\<you>\Documents\Security-Tools\
├── sentinel_anonymise.py
├── sentinel_anonymise.ps1
└── README.md
```

---

## Changelog

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-05-05 | Initial release — Python and PowerShell versions. Triggered by AiTM incident investigation requiring safe sharing of Sentinel query exports. |
