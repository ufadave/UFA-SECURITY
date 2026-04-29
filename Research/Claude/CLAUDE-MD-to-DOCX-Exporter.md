# Resource — Obsidian MD to DOCX Exporter

**Script:** `~/Documents/md-to-docx/md-to-docx.js`
**Date:** 2026-04-25
**Type:** Tool

---

## Setup (one time)

```bash
npm install -g docx
chmod +x ~/Documents/md-to-docx/md-to-docx.js
```

---

## Usage

```bash
# Export from Security vault
node ~/Documents/md-to-docx/md-to-docx.js ~/Documents/UFA-Security

# Export from Personal vault
node ~/Documents/md-to-docx/md-to-docx.js ~/Documents/Personal-Vault
```

---

## How It Works

- Add `#export` to any note's tags line
- Run the script — it scans the whole vault, finds every `#export` note, converts them all
- Output lands in `_Exports/` inside the vault
- Remove `#export` from the tag when done

---

## Output Formatting

- H1 in dark forest green, H2 in burnt orange, H3 in mid green
- Branded header with note title + CONFIDENTIAL label
- Branded footer with date and page numbers
- Tables with dark green header rows and alternating row shading
- Code blocks in monospace with grey background
- Wikilinks automatically stripped to plain text

---

## Tags
#resource #tool #obsidian #export #docx

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
