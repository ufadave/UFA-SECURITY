#!/usr/bin/env python3
"""
Obsidian Inbox Router
Watches ~/Downloads/obsidian-inbox for .md files and routes them
into the correct vault folder based on filename prefix or #tags.

Routing priority:
  1. Filename prefix  (e.g. INTEL-, INFO-, KQL-, IR-)
  2. Tags inside file (reads the #tags line)
  3. Falls back to _Inbox if nothing matches
"""

import os
import re
import shutil
import time
import logging
from pathlib import Path
from datetime import datetime

# ── Configuration ────────────────────────────────────────────────────────────

INBOX     = Path.home() / "Downloads" / "obsidian-inbox"
VAULT     = Path.home() / "Documents" / "UFA-Security"
LOG_FILE  = Path("/tmp/obsidian-router.log")

# Prefix → vault folder mapping (case-insensitive, checked first)
# KQL-Detection is a flat folder per the Apr 26 restructure decision.
# Content type is differentiated by tag (#detection/query | analytics-rule | hunting), not subfolder.
PREFIX_ROUTES = {
    "INTEL":    "Threat-Hunting/TTPs",
    "TTP":      "Threat-Hunting/TTPs",
    "HUNT":     "Threat-Hunting/Campaigns",
    "KQL":      "KQL-Detection",
    "IR":       "IR-DFIR/Cases",
    "PLAYBOOK": "IR-DFIR/Playbooks",
    "WDAC":     "WDAC/Runbooks",
    "OT":       "OT-SCADA/Assets",
    "SCADA":    "OT-SCADA/Assets",
    "HARD":     "Hardening/Controls",
    "INFO":     "Research/Articles",
    "TOOL":     "Research/Tools",
    "TRAINING": "Research/Training",
    "CLAUDE":   "Research/Claude",
    "MTG":      "Meetings",
    "PROJ":     "Projects",
    "RES":      "Research/Articles",
    "RESEARCH": "Research/Articles",
}

# Tag → vault folder mapping (scans #tags line in file body)
# All KQL-related tags route to the flat KQL-Detection/ folder.
TAG_ROUTES = {
    "intel":              "Threat-Hunting/TTPs",
    "ttp":                "Threat-Hunting/TTPs",
    "threat-hunting":     "Threat-Hunting/Campaigns",
    "kql":                "KQL-Detection",
    "detection":          "KQL-Detection",
    "analytics-rule":     "KQL-Detection",
    "hunting-query":      "KQL-Detection",
    "ransomware":         "Threat-Hunting/TTPs",
    "incident":           "IR-DFIR/Cases",
    "dfir":               "IR-DFIR/Cases",
    "playbook":           "IR-DFIR/Playbooks",
    "wdac":               "WDAC/Runbooks",
    "ot-scada":           "OT-SCADA/Assets",
    "ot":                 "OT-SCADA/Assets",
    "hardening":          "Hardening/Controls",
    "resource":           "Research/Articles",
    "tool":               "Research/Tools",
    "training":           "Research/Training",
    "research":           "Research/Articles",
}

FALLBACK = "_Inbox"
POLL_INTERVAL = 5  # seconds

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("obsidian-router")

# ── Routing logic ─────────────────────────────────────────────────────────────

def route_by_prefix(filename: str):
    """Check filename for a known prefix (e.g. INTEL-, KQL-)."""
    stem = Path(filename).stem.upper()
    for prefix, folder in PREFIX_ROUTES.items():
        if stem.startswith(prefix + "-") or stem.startswith(prefix + "_"):
            return folder
    return None


def route_by_tags(filepath: Path):
    """Scan file content for a #tags line and match against TAG_ROUTES."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
        # Look for a line starting with #tags or containing multiple #hashtags
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("#tags") or (
                line.count("#") >= 2 and not line.startswith("#")
            ):
                tags = re.findall(r"#([\w\-]+)", line.lower())
                for tag in tags:
                    if tag in TAG_ROUTES:
                        return TAG_ROUTES[tag]
    except Exception as e:
        log.warning(f"Could not read tags from {filepath.name}: {e}")
    return None


def resolve_destination(filepath: Path) -> Path:
    """Determine vault destination folder for a given .md file."""
    folder = route_by_prefix(filepath.name) or route_by_tags(filepath) or FALLBACK
    dest_dir = VAULT / folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    return dest_dir


def safe_move(src: Path, dest_dir: Path) -> Path:
    """Move file. On name collision, the new arrival wins and the old copy is
    archived to _Inbox/conflicts/ for review.

    Rationale: a re-drop almost always means "replace" — it's a regenerated or
    updated note. Silently keeping both (the old behaviour) produced ghost
    duplicates that were only discovered weeks later. The new file takes the
    canonical name; the displaced original is preserved aside in case the
    replacement was a mistake.
    """
    dest = dest_dir / src.name
    if dest.exists():
        conflict_dir = VAULT / "_Inbox" / "conflicts"
        conflict_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        old_aside = conflict_dir / f"{dest.stem}-OLD-{ts}.md"
        shutil.move(str(dest), str(old_aside))
        log.warning(
            f"  CONFLICT  {src.name} replaces existing copy in {dest_dir.relative_to(VAULT)} "
            f"→ old copy archived to _Inbox/conflicts/{old_aside.name}"
        )
    shutil.move(str(src), str(dest))
    return dest

# ── Main loop ─────────────────────────────────────────────────────────────────

def watch():
    # Wait for filesystem to be ready after login
    time.sleep(10)

    INBOX.mkdir(parents=True, exist_ok=True)
    (VAULT / FALLBACK).mkdir(parents=True, exist_ok=True)

    log.info(f"Obsidian Router started")
    log.info(f"  Inbox : {INBOX}")
    log.info(f"  Vault : {VAULT}")
    log.info(f"  Polling every {POLL_INTERVAL}s — drop .md files into inbox to route them")

    seen = set()

    while True:
        try:
            for f in sorted(INBOX.glob("*.md")):
                if f in seen:
                    continue
                # Small delay to ensure file is fully written before moving
                time.sleep(0.5)
                dest_dir = resolve_destination(f)
                dest = safe_move(f, dest_dir)
                rel = dest.relative_to(VAULT)
                log.info(f"  ROUTED  {f.name}  →  {rel}")
                seen.add(f)  # won't exist anymore but prevents re-check on slow FS

        except KeyboardInterrupt:
            log.info("Router stopped.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    watch()
