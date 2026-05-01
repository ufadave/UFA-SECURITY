---
title: Gmail Triage Tiers
date_created: 2026-04-28
tags:
  - "#resource"
  - "#status/active"
icon: LiMail
---

# Gmail Triage Tiers

The default `check mail` workflow runs full research and note generation for every tagged email. On low-volume days this is appropriate. On high-volume days, or when most emails are `[INFO]` and `[RESEARCH]` rather than `[INTEL]`, it's over-engineered. Three tiers let you match effort to the day.

---

## Trigger Phrases

| Phrase | Behaviour |
|--------|-----------|
| `check mail` | Full treatment for everything — current default behaviour unchanged |
| `check mail quick` | Full treatment for `[INTEL]`, lightweight notes for `[INFO]` and `[RESEARCH]` |
| `check mail triage` | Scan only — bullet list of what's in the inbox, no notes generated |

---

## What Each Tier Produces

| Tier | `[INTEL]` | `[INFO]` | `[RESEARCH]` |
|------|-----------|----------|--------------|
| `check mail` | Full note + KQL stubs | Full note | Full note |
| `check mail quick` | Full note + KQL stubs | Lightweight note | Lightweight note |
| `check mail triage` | Listed only | Listed only | Listed only |

`[INTEL]` always gets full treatment regardless of tier — it has direct operational impact and always warrants KQL stubs, MITRE mapping, and environment relevance assessment.

`[INFO]` and `[RESEARCH]` are where the over-engineering lives on quiet days. The lightweight path handles them in a fraction of the time while still creating a routable note.

---

## Lightweight Note Structure

Used for `[INFO]` and `[RESEARCH]` in `quick` tier. Template: `INFO-Lightweight-Template.md`.

```
source URL
date
one-sentence summary (What It Is)
one-sentence relevance assessment
action item if obvious
```

If relevance is minimal: "Low — file for reference" is a valid relevance entry. The note exists as a record without requiring analysis time.

---

## Triage Tier Output Format

Used in `triage` tier — no notes generated, returns a list like:

```
Inbox — 4 unread tagged emails

[INTEL] Iranian APT new LNK delivery variant — action recommended
[INTEL] Rockwell PLC vulnerability advisory — action recommended  
[INFO]  SANS reading room: Zero Trust architecture patterns — low priority
[RESEARCH] Academic paper: KQL optimisation techniques — medium priority
```

Follow up with `check mail` or `check mail quick` to generate notes for specific items, or respond with the subjects you want actioned.

---

## When to Use Each Tier

| Situation | Recommended Tier |
|-----------|-----------------|
| Morning routine, unknown inbox volume | `check mail triage` first, then decide |
| Mostly `[INTEL]` emails | `check mail` |
| Mixed inbox, time-limited | `check mail quick` |
| Just want to see what's there | `check mail triage` |
| End of week catch-up | `check mail quick` |

---

## Related Notes

- [[CLAUDE-Context-Brief]]
- [[CLAUDE-Prompt-Template]]

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-28 | Created — implementing triage tier improvement from vault review session |
