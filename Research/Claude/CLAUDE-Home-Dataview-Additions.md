---
title: Home.md Dataview Additions — Coverage Map & Stale Sweep
type: reference
created: 2026-05-05
---

# Home.md Dataview Additions

Two paste-ready blocks for `Home.md`. Each is self-contained and can be dropped under a new H2 section. Both read live from the vault on render, so they stay current as you create and tag notes.

Routes to `Research/Claude/` via the inbox router (CLAUDE- prefix).

---

## Block 1 — Detection Coverage vs Priority Threats

Surfaces every MITRE technique referenced in `Detection-KQL/` notes and flags priority-threat techniques that have **no** matching detection.

**Prerequisite:** KQL notes need a `mitre` field. Cleanest is YAML frontmatter:

```yaml
---
mitre: [T1078, T1059.001]
---
```

Inline also works (`mitre:: T1078` in the body). Backfill incrementally — the query handles missing fields gracefully.

### Paste under `## Detection Coverage` in Home.md

````markdown
## Detection Coverage

### Techniques covered by at least one detection

```dataview
TABLE WITHOUT ID
  file.link AS "Detection",
  mitre AS "MITRE",
  status AS "Status"
FROM "Detection-KQL"
WHERE mitre
SORT file.name ASC
```

### Priority-threat gap check — no detection on file

```dataviewjs
const priority = {
  "T1078":      "Valid Accounts (Iranian APT, SyncJacking)",
  "T1098":      "Account Manipulation (Service Principal abuse)",
  "T1098.001":  "Additional Cloud Credentials",
  "T1110":      "Brute Force",
  "T1556":      "Modify Authentication Process (SyncJacking)",
  "T1606.002":  "SAML Tokens",
  "T1199":      "Trusted Relationship",
  "T1136.003":  "Create Cloud Account",
  "T1059.001":  "PowerShell",
  "T1071.001":  "Web Protocols (C2)",
  "T1567":      "Exfil to Web Service",
  "T0883":      "Internet Accessible Device (OT)",
  "T0886":      "Remote Services (OT)"
};

const covered = new Set();
for (const p of dv.pages('"Detection-KQL"')) {
  const m = p.mitre;
  if (!m) continue;
  const list = Array.isArray(m) ? m : [m];
  list.forEach(t => covered.add(String(t).trim()));
}

const gaps = Object.entries(priority)
  .filter(([t]) => !covered.has(t))
  .map(([t, name]) => [t, name]);

if (gaps.length === 0) {
  dv.paragraph("All priority techniques have at least one detection note.");
} else {
  dv.table(["Technique", "Name — why it matters"], gaps);
}
```
````

The priority list is meant to evolve. Treat it as a config block — once it grows, lift it out into `_Templates/Priority-Techniques.md` and import.

---

## Block 2 — Vault Hygiene Sweep

Stale `#status/draft` notes and anything tagged `#pending-review` (e.g. X/Twitter sources that couldn't be fetched at intel-triage time).

### Paste under `## Vault Hygiene` in Home.md

````markdown
## Vault Hygiene

### Draft notes older than 14 days

```dataview
TABLE WITHOUT ID
  file.link AS "Note",
  file.folder AS "Folder",
  dateformat(file.mtime, "yyyy-MM-dd") AS "Last touched"
FROM #status/draft
WHERE file.mtime < date(today) - dur(14 days)
SORT file.mtime ASC
```

### Pending manual review

```dataview
TABLE WITHOUT ID
  file.link AS "Note",
  file.folder AS "Folder",
  dateformat(file.mtime, "yyyy-MM-dd") AS "Last touched"
FROM #pending-review
SORT file.mtime ASC
```

### Action-required (cross-vault)

```dataview
TABLE WITHOUT ID
  file.link AS "Note",
  file.folder AS "Folder",
  dateformat(file.mtime, "yyyy-MM-dd") AS "Last touched"
FROM #action-required
SORT file.mtime ASC
```
````

---

## Notes

- `dataviewjs` blocks require Dataview's JS query setting enabled: Settings → Dataview → Enable JavaScript Queries.
- Both blocks update on render. No manual refresh.
- The hygiene block pairs well with your weekly note routine — link it from the weekly template if you want it surfaced every Monday.

## Tags

#resource #status/done
