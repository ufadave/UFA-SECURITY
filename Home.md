# Security Operations — Home

> **Vault:** UFA-Security | **Owner:** Dave

---

## 🔴 Action Required
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #action-required
WHERE !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## ⏳ Pending Review
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #pending-review
WHERE !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## ⌛ Stale Drafts — >14 Days
```dataview
TABLE WITHOUT ID
  file.link AS "Note",
  file.folder AS "Location",
  dateformat(file.mtime, "yyyy-MM-dd") AS "Last touched"
FROM #status/draft
WHERE file.mtime < date(today) - dur(14 days)
AND !contains(file.path, "_Templates")
SORT file.mtime ASC
```

---

## ⚠️ Router Conflicts — Needs Triage
> Files diverted by the router because a file with the same name already existed at the destination. Pick the winner, delete the loser.
```dataview
TABLE WITHOUT ID
  file.link AS "Conflicting note",
  dateformat(file.mtime, "yyyy-MM-dd HH:mm") AS "Diverted at"
FROM "_Inbox/conflicts"
SORT file.mtime DESC
```

---

## 🚨 Open Incidents
```dataview
TABLE severity AS "Severity", file.mtime AS "Opened"
FROM #ir AND #status/active
WHERE !contains(file.tags, "#finding")
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🔍 Open Findings
```dataview
TABLE severity AS "Severity", case_id AS "Case", file.mtime AS "Updated"
FROM #finding
WHERE (status = "open" OR contains(file.tags, "#status/active") OR contains(file.tags, "#status/draft"))
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🏗️ Active Projects
```dataview
TABLE status AS "Status", file.mtime AS "Last Updated"
FROM #project AND #status/active
WHERE !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🎯 Active Hunts
```dataview
TABLE mitre AS "MITRE", tactic AS "Tactic", file.mtime AS "Updated"
FROM #hunt AND #status/active
WHERE !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🛒 Vendor Evaluations
```dataview
TABLE vendor AS "Vendor", category AS "Category", eval_status AS "Status", file.mtime AS "Updated"
FROM #vendor
WHERE eval_status != "Rejected" AND eval_status != "Deployed"
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 📊 Intel Feed — Last 14 Days
```dataview
TABLE file.mtime AS "Updated", file.folder AS "Location"
FROM #intel
WHERE file.mtime >= date(today) - dur(14 days)
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🎯 Detection Backlog — From Intel
```dataview
TABLE source AS "Source", file.folder AS "Location", file.mtime AS "Date"
FROM #intel OR #resource
WHERE detection_candidate = true
AND !contains(file.tags, "#status/done")
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🔧 Detection Notes — Draft
```dataview
TABLE table AS "Table", mitre AS "MITRE", file.mtime AS "Updated"
FROM #detection AND #status/draft
WHERE !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## ✅ Deployed — MDE Custom Detection Rules
```dataview
TABLE mde_rule_id AS "Rule ID", mitre AS "MITRE", file.mtime AS "Deployed"
FROM #detection
WHERE promoted_to_rule = true
AND mde_rule_id != "" AND mde_rule_id != null
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## ✅ Deployed — Sentinel Analytics Rules
```dataview
TABLE sentinel_rule_id AS "Rule GUID", mitre AS "MITRE", file.mtime AS "Deployed"
FROM #detection
WHERE promoted_to_rule = true
AND sentinel_rule_id != "" AND sentinel_rule_id != null
AND !contains(file.path, "_Templates")
SORT file.mtime DESC
```

---

## 🧭 Detection Coverage — MITRE Map

### Techniques covered by at least one detection
```dataview
TABLE WITHOUT ID
  file.link AS "Detection",
  mitre AS "MITRE",
  status AS "Status"
FROM "KQL-Detection"
WHERE mitre
AND !contains(file.path, "_Templates")
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
for (const p of dv.pages('"KQL-Detection"')) {
  if (p.file.path.includes("_Templates")) continue;
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

---

## 🛡️ Hardening Controls
```dataview
TABLE category AS "Category", priority AS "Priority", status AS "Status", deployed AS "Deployed"
FROM #hardening
WHERE !contains(file.path, "_Templates")
SORT priority ASC, file.mtime DESC
```

---

## 📅 Recent Notes

### Latest Daily
```dataview
LIST
FROM "_Daily"
SORT file.name DESC
LIMIT 3
```

### Latest Weekly
```dataview
LIST
FROM "_Weekly"
SORT file.name DESC
LIMIT 2
```

---

## 🗺️ Map of Content

### [[KQL-Detection/|Detection & KQL]]
> All KQL content lives in this flat folder. Slice by content-type tag:
> `#detection/query`, `#detection/mde-rule`, `#detection/analytics-rule`, `#detection/hunting`, `#detection/audit`

### [[Hardening/|Hardening]]
- [[Hardening/Controls/|Controls]]
- [[Hardening/Policies/|Policies]]
- [[Hardening/Validation/|Validation]]

### [[WDAC/|WDAC]]
- [[WDAC/Policies/|Policies]]
- [[WDAC/Rings/|Rings]]
- [[WDAC/Runbooks/|Runbooks]]

### [[IR-DFIR/|IR & DFIR]]
- [[IR-DFIR/Playbooks/|Playbooks]]
- [[IR-DFIR/Cases/|Cases]]
- [[IR-DFIR/Templates/|Templates]]

### [[Threat-Hunting/|Threat Hunting]]
- [[Threat-Hunting/TTPs/|TTPs]]
- [[Threat-Hunting/Campaigns/|Campaigns]]
- [[Threat-Hunting/Tools/|Tools]]

### [[OT-SCADA/|OT & SCADA]]
- [[OT-SCADA/Assets/|Assets]]
- [[OT-SCADA/Vulnerabilities/|Vulnerabilities]]
- [[OT-SCADA/Compliance/|Compliance]]

### [[Projects/|Projects]]
### [[Research/|Research]]
### [[Meetings/|Meetings]]

---

## 📌 Active Work
> Update manually with current focus items

- [ ] 
- [ ] 
- [ ] 
