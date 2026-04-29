---
title: zshrc Additions — Mac Workflow
date_created: 2026-04-28
tags:
  - "#resource"
  - "#status/active"
icon: LiTerminal
---

# zshrc Additions — Mac Workflow

Custom aliases and prompt configuration added to `~/.zshrc` to support the Obsidian vault workflow, router management, and general Mac terminal use.

---

## How to Apply

```bash
# Append to existing .zshrc without overwriting anything
cat ~/Downloads/zshrc-additions.sh >> ~/.zshrc

# Reload immediately — no Terminal restart needed
source ~/.zshrc
```

**Check for conflicts first** — if you already have `grep` or `python` aliases in your `.zshrc`, the new ones will conflict:

```bash
grep "alias grep\|alias python" ~/.zshrc
```

Remove the older duplicates if found.

---

## Alias Reference

### Obsidian Vault

| Alias | Command | Purpose |
|-------|---------|---------|
| `inbox` | `cp -f ~/Downloads/outputs/*.md ~/Downloads/obsidian-inbox/` | Copy all Claude outputs to router inbox |
| `vault` | `cd ~/Documents/UFA-Security` | Jump to vault root |
| `templates` | `cd ~/Documents/UFA-Security/_Templates` | Jump to templates folder |
| `daily` | `cd ~/Documents/UFA-Security/_Daily` | Jump to daily notes |
| `weekly` | `cd ~/Documents/UFA-Security/_Weekly` | Jump to weekly notes |
| `exports` | `cd ~/Documents/UFA-Security/_Exports` | Jump to exports folder |
| `docx` | `node ~/Documents/md-to-docx/md-to-docx.js ~/Documents/UFA-Security` | Run md-to-docx exporter |
| `vaultsearch` | `grep -r --include='*.md' -l` | Search vault notes by string — returns filenames |

**Usage — vaultsearch:**
```bash
vaultsearch 'Handala' ~/Documents/UFA-Security
vaultsearch 'detection_candidate' ~/Documents/UFA-Security/Threat-Hunting
```

### Router Management

| Alias | Purpose |
|-------|---------|
| `router-log` | Watch router log live |
| `router-status` | Check if router is running (number = PID, dash = stopped) |
| `router-restart` | Unload and reload the launchd plist |
| `router-run` | Run router manually if launchd won't start it |

### Navigation

| Alias | Purpose |
|-------|---------|
| `..` / `...` | Up one / two directories |
| `ll` | `ls -lah` — detailed listing with hidden files |
| `lls` | Sort by file size |
| `llt` | Sort by modified time (most recent first) |
| `recent` | Files modified in the last 24 hours in current directory |
| `catn` | `cat` with line numbers |

### Network & Security

| Alias | Purpose |
|-------|---------|
| `myip` | Show public IP — confirm VPN is active |
| `ports` | Show all listening ports |
| `flushdns` | Flush macOS DNS cache |
| `ping3` | Ping with 3 packets |
| `nmap-quick` | `nmap -sV --open -T4` — quick service scan |
| `nmap-ping` | `nmap -sn` — ping sweep, no port scan |

### Python & Node

| Alias | Purpose |
|-------|---------|
| `python` | Points to `python3` |
| `pip` | `pip3 --break-system-packages` — avoids macOS pip errors |
| `serve` | Start HTTP server on port 8080 in current directory |

### Git (Obsidian Git backup)

| Alias | Purpose |
|-------|---------|
| `gs` | `git status` |
| `gp` | `git push` |
| `gpl` | `git pull` |
| `gl` | `git log --oneline -10` |
| `gaa "message"` | Stage all and commit in one command |

**Usage — gaa:**
```bash
gaa "weekly vault backup"
```

---

## Prompt

Shows current git branch when inside a git repo:

```
dave@cosmiccrisp UFA-Security main $
```

Configured via:
```bash
parse_git_branch() {
  git branch 2>/dev/null | sed -n 's/* //p'
}
export PS1="%n@%m %1~ \$(parse_git_branch)\$ "
```

---

## File Location

The original additions file: `~/Downloads/zshrc-additions.sh`

To view current aliases at any time:
```bash
alias
```

To edit `.zshrc` directly:
```bash
nano ~/.zshrc
# or
open ~/.zshrc
```

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created — aliases added to ~/.zshrc |
