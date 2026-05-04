# Security Operations — Home

> **Vault:** UFA-Security | **Owner:** Dave

---

## 🔴 Action Required
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #action-required
SORT file.mtime DESC
```

---

## ⏳ Pending Review
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #pending-review
SORT file.mtime DESC
```

---

## 🚨 Open Incidents
```dataview
TABLE severity AS "Severity", file.mtime AS "Opened"
FROM #ir AND #status/active
WHERE !contains(file.tags, "#finding")
SORT file.mtime DESC
```

---

## 🔍 Open Findings
```dataview
TABLE severity AS "Severity", case_id AS "Case", file.mtime AS "Updated"
FROM #finding
WHERE status = "open" OR contains(file.tags, "#status/active") OR contains(file.tags, "#status/draft")
SORT file.mtime DESC
```

---

## 🏗️ Active Projects
```dataview
TABLE status AS "Status", file.mtime AS "Last Updated"
FROM #project AND #status/active
SORT file.mtime DESC
```

---

## 🎯 Active Hunts
```dataview
TABLE mitre AS "MITRE", tactic AS "Tactic", file.mtime AS "Updated"
FROM #hunt AND #status/active
SORT file.mtime DESC
```

---

## 🛒 Vendor Evaluations
```dataview
TABLE vendor AS "Vendor", category AS "Category", eval_status AS "Status", file.mtime AS "Updated"
FROM #vendor
WHERE eval_status != "Rejected" AND eval_status != "Deployed"
SORT file.mtime DESC
```

---

## 📊 Intel Feed — Last 14 Days
```dataview
TABLE file.mtime AS "Updated", file.folder AS "Location"
FROM #intel
WHERE file.mtime >= date(today) - dur(14 days)
SORT file.mtime DESC
```

---

## 🎯 Detection Backlog — From Intel
```dataview
TABLE source AS "Source", file.folder AS "Location", file.mtime AS "Date"
FROM #intel OR #resource
WHERE detection_candidate = true
AND !contains(file.tags, "#status/done")
SORT file.mtime DESC
```

---

## 🔧 Detection Notes — Draft
```dataview
TABLE table AS "Table", mitre AS "MITRE", file.mtime AS "Updated"
FROM #detection AND #status/draft
SORT file.mtime DESC
```

---

## ✅ Promoted to Sentinel Rules
```dataview
TABLE sentinel_rule_id AS "Rule GUID", mitre AS "MITRE", file.mtime AS "Promoted"
FROM #detection
WHERE promoted_to_rule = true
SORT file.mtime DESC
```

---

## 🛡️ Hardening Controls
```dataview
TABLE category AS "Category", priority AS "Priority", status AS "Status", deployed AS "Deployed"
FROM #hardening
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

### [[Detection-KQL/|Detection & KQL]]
- [[Detection-KQL/Queries/|Queries]]
- [[Detection-KQL/Analytics-Rules/|Analytics Rules]]
- [[Detection-KQL/Hunting-Queries/|Hunting Queries]]

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
