# Claude & Obsidian — Tips & Commands

**Last Updated:** 2026-04-25

---

## Generating KQL Query Notes

Just ask Claude to "generate the Obsidian note" for any query. Examples:

- "Generate the Obsidian note for the NTLMv2 query"
- "Create the Obsidian note for this KQL query" + paste the query
- "Generate a KQL note for [topic]" — Claude will write the query and note together

The file will be prefixed with `KQL-` so the router places it automatically in `Detection-KQL/Queries`.

---

## Inbox Router — Filename Prefixes

Drop any `.md` file into `~/Downloads/obsidian-inbox/` and the router places it automatically.

| Prefix | Destination |
|--------|-------------|
| `INTEL-` | `Threat-Hunting/TTPs` |
| `TTP-` | `Threat-Hunting/TTPs` |
| `HUNT-` | `Threat-Hunting/Campaigns` |
| `KQL-` | `Detection-KQL/Queries` |
| `RULE-` | `Detection-KQL/Analytics-Rules` |
| `HUNTING-` | `Detection-KQL/Hunting-Queries` |
| `IR-` | `IR-DFIR/Cases` |
| `PLAYBOOK-` | `IR-DFIR/Playbooks` |
| `WDAC-` | `WDAC/Runbooks` |
| `OT-` | `OT-SCADA/Assets` |
| `SCADA-` | `OT-SCADA/Assets` |
| `HARD-` | `Hardening/Controls` |
| `INFO-` | `Research/Articles` |
| `TOOL-` | `Research/Tools` |
| `TRAINING-` | `Research/Training` |

If no prefix matches, the router falls back to `#tags` in the file. If nothing matches, the file lands in `_Inbox`.

---

## Email Tags

When forwarding links to yourself, use subject line tags to trigger processing:

- `[INTEL]` — threat intel, active campaigns, advisories, detection-worthy content
- `[INFO]` — tools, training labs, research, interesting reads

Claude checks Gmail for these tags when you say **"check mail"** and generates ready-to-drop `.md` notes for each link.

---

## Checking Mail

Say **"check mail"** — Claude scans your Gmail inbox for `[INTEL]` and `[INFO]` tagged emails, fetches the URLs, researches the content, and generates Obsidian notes.

Note: X/Twitter links cannot be fetched directly. Claude researches the topic from other sources and flags where content needs manual review.

---

## Router Management

| Task                    | Command                                                                  |
| ----------------------- | ------------------------------------------------------------------------ |
| Check router is running | `launchctl list \| grep obsidian-router`                                 |
| Watch live log          | `tail -f /tmp/obsidian-router.log`                                       |
| Stop router             | `launchctl unload ~/Library/LaunchAgents/com.dave.obsidian-router.plist` |
| Start router            | `launchctl load ~/Library/LaunchAgents/com.dave.obsidian-router.plist`   |
| Script location         | `/usr/local/bin/obsidian_router.py`                                      |
| Plist location          | `~/Library/LaunchAgents/com.dave.obsidian-router.plist`                  |

---

## Tags
#tips #obsidian #claude #workflow

---

## Changelog
| Date | Change |
|------|--------|
| 2026-04-25 | Created |
