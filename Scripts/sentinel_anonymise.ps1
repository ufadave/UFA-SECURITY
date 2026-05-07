<#
.SYNOPSIS
    Anonymises CSV exports from Microsoft Sentinel and Defender Advanced Hunting queries.

.DESCRIPTION
    Detects and redacts PII using consistent hashing — the same input value always
    produces the same anonymised token, preserving analytical relationships across
    rows and files.

    Handles:
        Email addresses     → user_<hash>@redacted.local
        IPv4 addresses      → preserves /16 subnet, redacts host (x.x.xxx.xxx)
        IPv6 addresses      → ipv6_<hash>
        Entra object GUIDs  → id_<hash>
        UPNs                → same as email handling
        Display names       → Person_<hash> (in known columns)
        URLs                → scheme://host_<hash>/path (GUIDs scrubbed from path)
        Free text / JSON    → inline regex scrub of all above types

    Targeted Sentinel / Advanced Hunting columns handled by name:
        SigninLogs:         UserPrincipalName, UserDisplayName, IPAddress,
                            UserId, CorrelationId, Location
        AuditLogs:          InitiatorUPN, InitiatorId, TargetUPN, TargetId,
                            CorrelationId
        OfficeActivity:     UserId, ClientIP, MailboxOwnerUPN
        CloudAppEvents:     AccountId, AccountDisplayName, AccountUpn, IPAddress
        EmailEvents:        RecipientEmailAddress, SenderFromAddress, SenderIPv4,
                            SenderDisplayName
        UrlClickEvents:     AccountUpn, IPAddress, Url

    Raw JSON blob columns (RawEventData, AdditionalDetails, TargetResources,
    InitiatedBy, AuthenticationDetails, OperationProperties) are dropped entirely
    as they are too nested to reliably anonymise with regex.

.PARAMETER InputFile
    Path to the input CSV file. Required.

.PARAMETER OutputFile
    Path for the anonymised output CSV. Defaults to <InputFile>_anonymised.csv
    in the same directory as the input file.

.PARAMETER PreserveSubnet
    How many IPv4 octets to preserve for subnet context.
    16  = x.x.xxx.xxx — preserves first two octets (default)
    24  = x.x.x.xxx   — preserves first three octets

.PARAMETER ShowMapping
    Write a JSON file mapping original values to anonymised tokens.
    Keep this file private — it contains the original PII values.
    Mapping file is written to <OutputFile>_mapping.json.

.PARAMETER Verbose
    Print each column name as it is processed.

.EXAMPLE
    .\sentinel_anonymise.ps1 -InputFile .\emailevents.csv

.EXAMPLE
    .\sentinel_anonymise.ps1 -InputFile .\signinlogs.csv -OutputFile .\clean.csv

.EXAMPLE
    .\sentinel_anonymise.ps1 -InputFile .\export.csv -PreserveSubnet 24 -ShowMapping

.NOTES
    No external dependencies — uses only built-in .NET and PowerShell.
    Requires PowerShell 5.1 or later (included in Windows 10/11).

    To run if execution policy blocks the script:
        powershell -ExecutionPolicy Bypass -File .\sentinel_anonymise.ps1 -InputFile .\export.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet("16", "24")]
    [string]$PreserveSubnet = "16",

    [Parameter(Mandatory = $false)]
    [switch]$ShowMapping
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Column routing tables
# Columns are matched case-insensitively with underscores and spaces stripped
# ---------------------------------------------------------------------------

$EmailColumns = [System.Collections.Generic.HashSet[string]]@(
    "userprincipalname", "initiatorupn", "targetupn", "userid",
    "recipientemailaddress", "senderfromaddress", "accountupn",
    "mailboxownerupn", "compromisedupn"
)

$DisplayNameColumns = [System.Collections.Generic.HashSet[string]]@(
    "userdisplayname", "accountdisplayname", "senderdisplayname",
    "displayname", "initiatorname"
)

$IpColumns = [System.Collections.Generic.HashSet[string]]@(
    "ipaddress", "clientip", "senderipv4", "senderipv6", "ipaddr", "ip"
)

$GuidColumns = [System.Collections.Generic.HashSet[string]]@(
    "userid", "initiatorid", "targetid", "accountid", "correlationid",
    "clientrequestid", "operationid", "accountobjectid", "objectid"
)

$UrlColumns = [System.Collections.Generic.HashSet[string]]@(
    "url", "requesturi", "urlchain"
)

$DropColumns = [System.Collections.Generic.HashSet[string]]@(
    "raweventdata", "additionaldetails", "targetresources", "initiatedby",
    "authenticationdetails", "operationproperties", "devicedetailparsed"
)

# Regex patterns compiled once for performance
$ReEmail = [regex]::new(
    '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$ReIPv4 = [regex]::new(
    '\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
$ReIPv6 = [regex]::new(
    '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' +
    '|(?:[0-9a-fA-F]{1,4}:){1,7}:' +
    '|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}' +
    '|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}'
)
$ReGuid = [regex]::new(
    '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)

# Global mapping table — original value → anonymised token
$script:Mapping = [ordered]@{}
$script:Sha256  = [System.Security.Cryptography.SHA256]::Create()

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

function Get-StableHash {
    <#
    .SYNOPSIS SHA-256 hash of a string, truncated to specified hex length. Deterministic. #>
    param(
        [string]$Value,
        [int]$Length = 8
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLower().Trim())
    $hash  = $script:Sha256.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-').ToLower().Substring(0, $Length)
}

function Register-Mapping {
    <#
    .SYNOPSIS Record original→anonymised mapping and return the anonymised value. #>
    param([string]$Original, [string]$Anonymised)
    if ($Original -and -not $script:Mapping.Contains($Original)) {
        $script:Mapping[$Original] = $Anonymised
    }
    return $Anonymised
}

function ConvertTo-AnonymisedEmail {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $token = "user_$(Get-StableHash $Value)@redacted.local"
    return Register-Mapping $Value $token
}

function ConvertTo-AnonymisedIP {
    param([string]$Value, [int]$SubnetPreserve = 16)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }

    # IPv4
    if ($Value -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $parts = $Value.Split('.')
        $token = if ($SubnetPreserve -eq 24) {
            "$($parts[0]).$($parts[1]).$($parts[2]).xxx"
        }
        else {
            "$($parts[0]).$($parts[1]).xxx.xxx"
        }
        return Register-Mapping $Value $token
    }

    # IPv6
    if ($Value -match ':') {
        $token = "ipv6_$(Get-StableHash $Value)"
        return Register-Mapping $Value $token
    }

    return $Value
}

function ConvertTo-AnonymisedGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($ReGuid.IsMatch($Value.Trim()) -and $Value.Trim().Length -eq 36) {
        $token = "id_$(Get-StableHash $Value 12)"
        return Register-Mapping $Value $token
    }
    return $Value
}

function ConvertTo-AnonymisedDisplayName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $token = "Person_$(Get-StableHash $Value)"
    return Register-Mapping $Value $token
}

function ConvertTo-AnonymisedUrl {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    try {
        $uri       = [System.Uri]$Value
        $hostToken = "host_$(Get-StableHash $uri.Host)"
        $path      = $uri.AbsolutePath

        # Scrub GUIDs from path
        $path = $ReGuid.Replace($path, {
            param($m)
            "id_$(Get-StableHash $m.Value 8)"
        })

        # Scrub emails from path
        $path = $ReEmail.Replace($path, {
            param($m)
            ConvertTo-AnonymisedEmail $m.Value
        })

        $token = "$($uri.Scheme)://$hostToken$path"
        return Register-Mapping $Value $token
    }
    catch {
        # Not a valid URI — fall through to inline scrub
        return Invoke-InlineScrub $Value
    }
}

function Invoke-InlineScrub {
    <#
    .SYNOPSIS
        Scrub PII from free-text or partially structured column values.
        Applied to any column not in the targeted column lists.
        Order: GUIDs → IPv6 → IPv4 → Email (to avoid regex cross-contamination).
    #>
    param([string]$Value, [int]$SubnetPreserve = 16)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    # GUIDs first — must come before IPv4 (GUIDs contain hex that could confuse IP regex)
    $Value = $ReGuid.Replace($Value, {
        param($m)
        ConvertTo-AnonymisedGuid $m.Value
    })

    # IPv6 before IPv4
    $Value = $ReIPv6.Replace($Value, {
        param($m)
        ConvertTo-AnonymisedIP $m.Value $SubnetPreserve
    })

    # IPv4
    $Value = $ReIPv4.Replace($Value, {
        param($m)
        ConvertTo-AnonymisedIP $m.Value $SubnetPreserve
    })

    # Email / UPN
    $Value = $ReEmail.Replace($Value, {
        param($m)
        ConvertTo-AnonymisedEmail $m.Value
    })

    return $Value
}

function Invoke-AnonymiseCell {
    <#
    .SYNOPSIS Route a cell value to the correct anonymisation function based on column name. #>
    param(
        [string]$ColNormalised,
        [string]$Value,
        [int]$SubnetPreserve
    )

    # Skip empty or placeholder values
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -in @("", "nan", "None", "N/A", "-", "null")) {
        return $Value
    }

    if ($EmailColumns.Contains($ColNormalised))       { return ConvertTo-AnonymisedEmail $Value }
    if ($DisplayNameColumns.Contains($ColNormalised)) { return ConvertTo-AnonymisedDisplayName $Value }
    if ($IpColumns.Contains($ColNormalised))          { return ConvertTo-AnonymisedIP $Value $SubnetPreserve }
    if ($GuidColumns.Contains($ColNormalised))        { return ConvertTo-AnonymisedGuid $Value }
    if ($UrlColumns.Contains($ColNormalised))         { return ConvertTo-AnonymisedUrl $Value }

    # Default — inline scrub for unrecognised or free-text columns
    return Invoke-InlineScrub $Value $SubnetPreserve
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

if (-not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}

$inputPath = Resolve-Path $InputFile

if (-not $OutputFile) {
    $dir        = Split-Path $inputPath -Parent
    $base       = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)
    $OutputFile = Join-Path $dir "$($base)_anonymised.csv"
}

$subnetInt = [int]$PreserveSubnet

# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "→ Processing: $(Split-Path $inputPath -Leaf)" -ForegroundColor Cyan

# Read CSV — use Import-Csv for proper quoted field handling
try {
    $rows = Import-Csv -Path $inputPath
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 1
}

if ($rows.Count -eq 0) {
    Write-Warning "Input file is empty or has no data rows."
    exit 0
}

$headers = $rows[0].PSObject.Properties.Name
Write-Host "  Rows     : $($rows.Count.ToString('N0'))"
Write-Host "  Columns  : $($headers.Count)"

# Identify columns to drop
$dropActual = $headers | Where-Object {
    $DropColumns.Contains($_.ToLower().Replace("_", "").Replace(" ", ""))
}

if ($dropActual) {
    Write-Host "  Dropping : $($dropActual -join ', ')" -ForegroundColor Yellow
}

# Identify columns to process and pre-compute normalised names
$processColumns = $headers | Where-Object { $_ -notin $dropActual }
$colMap = @{}
foreach ($col in $processColumns) {
    $colMap[$col] = $col.ToLower().Replace("_", "").Replace(" ", "")
}

if ($PSBoundParameters.ContainsKey('Verbose') -or $VerbosePreference -eq 'Continue') {
    Write-Host "  Processing columns:"
    foreach ($col in $processColumns) {
        Write-Host "    → $col" -ForegroundColor Gray
    }
}

# Process rows
Write-Host "  Anonymising..." -NoNewline

$results = foreach ($row in $rows) {
    $newRow = [ordered]@{}
    foreach ($col in $processColumns) {
        $newRow[$col] = Invoke-AnonymiseCell `
            -ColNormalised $colMap[$col] `
            -Value $row.$col `
            -SubnetPreserve $subnetInt
    }
    [pscustomobject]$newRow
}

Write-Host " done." -ForegroundColor Green

# Write anonymised CSV
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "  ✓ Output  : $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to write output file: $_"
    exit 1
}

# Write mapping file if requested
if ($ShowMapping -and $script:Mapping.Count -gt 0) {
    $mappingPath = [System.IO.Path]::ChangeExtension($OutputFile, $null).TrimEnd('.') `
                  + "_mapping.json"
    try {
        $script:Mapping | ConvertTo-Json -Depth 2 | Set-Content -Path $mappingPath -Encoding UTF8
        Write-Host "  ✓ Mapping : $mappingPath" -ForegroundColor Green
        Write-Host "  ⚠  Keep the mapping file private — it contains original values" `
                   -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Could not write mapping file: $_"
    }
}

Write-Host ""
Write-Host "✓ Complete. $($script:Mapping.Count.ToString('N0')) unique values anonymised." `
           -ForegroundColor Cyan

# Cleanup
$script:Sha256.Dispose()
