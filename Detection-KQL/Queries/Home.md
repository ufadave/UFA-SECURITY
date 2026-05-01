# Security Operations — Home

> **Vault:** UFA-Security | **Owner:** Dave | **Updated:** 2026-04-29

---

## 📊 Intel Feed — Last 14 Days
```dataview
TABLE file.mtime AS "Updated", file.folder AS "Location"
FROM #intel
WHERE file.mtime >= date(today) - dur(14 days)
SORT file.mtime DESC
```

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

## 🎯 Detection Backlog — From Intel
```dataview
TABLE source AS "Source", file.mtime AS "Date"
FROM "Threat-Hunting/TTPs" OR "Research/Articles"
WHERE detection_candidate = true
AND !contains(tags, "status/done")
SORT file.mtime DESC
```

---

## 🔧 Detection Notes — Draft
```dataview
TABLE file.folder AS "Location", file.mtime AS "Updated"
FROM #detection AND #status/draft
SORT file.mtime DESC
```

---

## ✅ Promoted to Sentinel Rules
```dataview
TABLE sentinel_rule_id AS "Rule GUID", file.mtime AS "Promoted"
FROM "Detection-KQL"
WHERE promoted_to_rule = true
SORT file.mtime DESC
```

---

## 🏗️ Active Projects
```dataview
TABLE file.mtime AS "Last Updated"
FROM #project AND #status/active
SORT file.mtime DESC
```

---

## 🚨 Open Incidents
```dataview
TABLE file.mtime AS "Opened"
FROM #ir AND #status/active
SORT file.mtime DESC
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

## 📅 Notes
- [[_Daily/2026-04-28|Today]]
- [[_Daily/2026-04-27|Yesterday]]
- [[_Weekly/2026-W18|This Week (W18)]]
- [[_Weekly/2026-W17|Last Week (W17)]]

---

## 📌 Active Work
> Update manually with current focus items

- [ ] 
- [ ] 
- [ ] 
