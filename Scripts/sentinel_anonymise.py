#!/usr/bin/env python3
"""
sentinel_anonymise.py
---------------------
Anonymises CSV exports from Microsoft Sentinel and Defender Advanced Hunting
queries. Detects and redacts PII using consistent hashing — the same input
value always produces the same anonymised token, preserving analytical
relationships across rows and files.

Handles:
    - Email addresses         → user_<hash>@redacted.local
    - IPv4 addresses          → preserves /16 subnet, redacts host (x.x.xxx.xxx)
    - IPv6 addresses          → ipv6_<hash>
    - Entra object GUIDs      → id_<hash>
    - UPNs (user@domain)      → same as email handling
    - Display names           → detected in known columns, replaced with Person_<hash>
    - Domain names            → domain_<hash>.local (in known columns)
    - Hostnames               → host_<hash>

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

Usage:
    python3 sentinel_anonymise.py input.csv
    python3 sentinel_anonymise.py input.csv --output clean.csv
    python3 sentinel_anonymise.py input.csv --show-mapping
    python3 sentinel_anonymise.py input.csv --preserve-subnet /24
    python3 sentinel_anonymise.py *.csv               (glob — multiple files)

Output:
    input_anonymised.csv (default) or --output path
    input_mapping.json (if --show-mapping, for your reference only — keep private)

Requirements:
    pip install pandas --break-system-packages
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import pandas as pd
except ImportError:
    print("ERROR: pandas required. Run: pip install pandas --break-system-packages")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Columns where the entire cell value is treated as an email/UPN
EMAIL_COLUMNS = {
    "userprincipalname", "initiatorupn", "targetupn", "userid",
    "recipientemailaddress", "senderfromaddress", "accountupn",
    "mailboxownerupn", "compromisedupn", "recipientemailaddress",
}

# Columns where the entire cell value is treated as a display name
DISPLAY_NAME_COLUMNS = {
    "userdisplayname", "accountdisplayname", "senderdisplayname",
    "displayname", "initiatorname",
}

# Columns where the entire cell value is treated as an IP address
IP_COLUMNS = {
    "ipaddress", "clientip", "senderipv4", "senderipv6",
    "ipaddr", "ip",
}

# Columns where the entire cell value is treated as a GUID/object ID
GUID_COLUMNS = {
    "userid", "initiatorid", "targetid", "accountid", "correlationid",
    "clientrequestid", "operationid", "accountobjectid", "objectid",
}

# Columns where URL content should be anonymised
URL_COLUMNS = {
    "url", "requesturi", "urlchain",
}

# Columns where domain names appear
DOMAIN_COLUMNS = {
    "location",  # "Sweden Central" — kept as-is (not PII), but included for review
}

# Columns to drop entirely (raw JSON blobs — too complex to reliably anonymise)
DROP_COLUMNS = {
    "rawEventData", "additionaldetails", "targetresources", "initiatedby",
    "authenticationdetails", "operationproperties", "devicedetailparsed",
}

# Preserve this many octets of IPv4 for subnet context
# /16 = preserve first 2 octets (default)
# /24 = preserve first 3 octets
DEFAULT_SUBNET_PRESERVE = 16

# Regex patterns for inline PII detection in free-text columns
RE_EMAIL = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE
)
RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
RE_IPV6 = re.compile(
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}'
)
RE_GUID = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
    r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)


# ---------------------------------------------------------------------------
# Anonymisation helpers
# ---------------------------------------------------------------------------

# Global mapping table — original → anonymised, for --show-mapping output
_mapping: dict[str, str] = {}


def _hash(value: str, length: int = 8) -> str:
    """SHA-256 hash of value, truncated to length hex chars. Deterministic."""
    return hashlib.sha256(value.lower().strip().encode()).hexdigest()[:length]


def _record(original: str, anonymised: str) -> str:
    """Record mapping and return anonymised value."""
    if original and original not in _mapping:
        _mapping[original] = anonymised
    return anonymised


def anonymise_email(value: str) -> str:
    if not value or not value.strip():
        return value
    v = value.strip()
    token = f"user_{_hash(v)}@redacted.local"
    return _record(v, token)


def anonymise_ip(value: str, subnet_preserve: int = DEFAULT_SUBNET_PRESERVE) -> str:
    if not value or not value.strip():
        return value
    v = value.strip()
    try:
        addr = ipaddress.ip_address(v)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = v.split(".")
            if subnet_preserve == 24:
                token = f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
            else:  # /16 default
                token = f"{parts[0]}.{parts[1]}.xxx.xxx"
        else:
            token = f"ipv6_{_hash(v)}"
        return _record(v, token)
    except ValueError:
        # Not a valid IP — fall through to inline scrub
        return v


def anonymise_guid(value: str) -> str:
    if not value or not value.strip():
        return value
    v = value.strip()
    if RE_GUID.match(v):
        token = f"id_{_hash(v, 12)}"
        return _record(v, token)
    return v


def anonymise_display_name(value: str) -> str:
    if not value or not value.strip():
        return value
    v = value.strip()
    token = f"Person_{_hash(v)}"
    return _record(v, token)


def anonymise_url(value: str) -> str:
    """Redact host and path from URLs, preserve scheme and query structure."""
    if not value or not value.strip():
        return value
    v = value.strip()
    try:
        parsed = urlparse(v)
        host_token = f"host_{_hash(parsed.netloc)}" if parsed.netloc else ""
        # Scrub GUIDs and emails from path
        path = RE_GUID.sub(lambda m: f"id_{_hash(m.group(), 8)}", parsed.path)
        path = RE_EMAIL.sub(lambda m: anonymise_email(m.group()), path)
        token = f"{parsed.scheme}://{host_token}{path}"
        _record(v, token)
        return token
    except Exception:
        return v


def scrub_inline(value: str, subnet_preserve: int = DEFAULT_SUBNET_PRESERVE) -> str:
    """
    Scrub PII from free-text or JSON column values using regex.
    Applied to columns not in the targeted lists above.
    """
    if not value or not isinstance(value, str):
        return value

    # GUIDs first (before IPv4 — GUIDs contain hex digits that could confuse IP regex)
    value = RE_GUID.sub(lambda m: anonymise_guid(m.group()), value)
    # IPv6 before IPv4
    value = RE_IPV6.sub(lambda m: anonymise_ip(m.group(), subnet_preserve), value)
    # IPv4
    value = RE_IPV4.sub(lambda m: anonymise_ip(m.group(), subnet_preserve), value)
    # Email / UPN
    value = RE_EMAIL.sub(lambda m: anonymise_email(m.group()), value)

    return value


# ---------------------------------------------------------------------------
# Column dispatcher
# ---------------------------------------------------------------------------

def anonymise_cell(col_lower: str, value, subnet_preserve: int) -> str:
    """Route a cell to the correct anonymisation function based on column name."""
    if not isinstance(value, str):
        value = str(value) if pd.notna(value) else ""
    if not value or value in ("", "nan", "None", "N/A", "-"):
        return value

    if col_lower in EMAIL_COLUMNS:
        return anonymise_email(value)
    if col_lower in DISPLAY_NAME_COLUMNS:
        return anonymise_display_name(value)
    if col_lower in IP_COLUMNS:
        return anonymise_ip(value, subnet_preserve)
    if col_lower in GUID_COLUMNS:
        return anonymise_guid(value)
    if col_lower in URL_COLUMNS:
        return anonymise_url(value)

    # Free-text / JSON columns — inline scrub
    return scrub_inline(value, subnet_preserve)


# ---------------------------------------------------------------------------
# File processor
# ---------------------------------------------------------------------------

def process_file(
    input_path: Path,
    output_path: Path,
    subnet_preserve: int,
    show_mapping: bool,
    verbose: bool,
) -> None:
    print(f"\n→ Processing: {input_path.name}")

    try:
        df = pd.read_csv(input_path, dtype=str, keep_default_na=False)
    except Exception as e:
        print(f"  ERROR reading file: {e}")
        return

    print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")

    # Drop raw JSON blob columns
    cols_to_drop = [c for c in df.columns if c.lower() in DROP_COLUMNS]
    if cols_to_drop:
        df.drop(columns=cols_to_drop, inplace=True)
        print(f"  Dropped columns (raw JSON): {cols_to_drop}")

    # Anonymise remaining columns
    for col in df.columns:
        col_lower = col.lower().replace(" ", "").replace("_", "")
        df[col] = df[col].apply(
            lambda v: anonymise_cell(col_lower, v, subnet_preserve)
        )
        if verbose:
            print(f"  Processed column: {col}")

    # Write output
    df.to_csv(output_path, index=False, quoting=csv.QUOTE_ALL)
    print(f"  ✓ Written: {output_path.name}")

    # Write mapping file if requested
    if show_mapping and _mapping:
        mapping_path = output_path.with_suffix("").with_name(
            output_path.stem + "_mapping.json"
        )
        with open(mapping_path, "w") as f:
            json.dump(_mapping, f, indent=2)
        print(f"  ✓ Mapping written: {mapping_path.name}")
        print(f"  ⚠  Keep the mapping file private — it contains original values")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Anonymise Sentinel / Advanced Hunting CSV exports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input CSV file(s). Supports glob patterns.",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (only valid for single file input).",
    )
    parser.add_argument(
        "--preserve-subnet",
        choices=["16", "24"],
        default="16",
        help="IPv4 subnet octets to preserve. /16 = x.x.xxx.xxx (default), /24 = x.x.x.xxx",
    )
    parser.add_argument(
        "--show-mapping",
        action="store_true",
        help="Write a JSON file mapping original → anonymised values. Keep this private.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each column as it is processed.",
    )

    args = parser.parse_args()

    subnet_preserve = int(args.preserve_subnet)

    # Resolve input files
    input_paths = [Path(p) for p in args.inputs]
    missing = [p for p in input_paths if not p.exists()]
    if missing:
        print(f"ERROR: File(s) not found: {[str(p) for p in missing]}")
        sys.exit(1)

    if args.output and len(input_paths) > 1:
        print("ERROR: --output can only be used with a single input file.")
        sys.exit(1)

    for input_path in input_paths:
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = input_path.with_name(
                input_path.stem + "_anonymised" + input_path.suffix
            )

        process_file(
            input_path=input_path,
            output_path=output_path,
            subnet_preserve=subnet_preserve,
            show_mapping=args.show_mapping,
            verbose=args.verbose,
        )

    print(f"\n✓ Done. {len(input_paths)} file(s) processed.")
    print(f"  Total unique values anonymised: {len(_mapping):,}")


if __name__ == "__main__":
    main()
