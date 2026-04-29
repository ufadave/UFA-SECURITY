<%*
const meetingType = await tp.system.suggester(
  ["Security/Technical", "Management/Stakeholder", "Vendor", "Incident", "CAB", "1:1", "Project", "Other"],
  ["Security/Technical", "Management/Stakeholder", "Vendor", "Incident", "CAB", "1:1", "Project", "Other"]
);
tR += `# ${await tp.system.prompt("Meeting title?")}\n`;
tR += `\n**Date:** ${tp.date.now("YYYY-MM-DD")} | **Time:** ${tp.date.now("HH:mm")}\n`;
tR += `**Type:** ${meetingType}\n`;
tR += `**Attendees:** \n`;
tR += `**Facilitator:** \n`;
if (meetingType === "Project") {
  tR += `**Project:** [[]]\n`;
}
tR += `
---

## Agenda
1. 
2. 
3. 

---

## Notes


---

## Decisions Made
- 
- 

---

## Action Items
| Action | Owner | Due |
|--------|-------|-----|
|  |  |  |
|  |  |  |

---

## Next Meeting
**Date:** | **Topic:**

---

## Tags
#meeting `;
tR += await tp.system.suggester(
  ["#security", "#management", "#vendor", "#incident", "#cab", "#project"],
  ["#security", "#management", "#vendor", "#incident", "#cab", "#project"]
);
tR += `\n
---

## Changelog
| Date | Change |
|------|--------|
| ${tp.date.now("YYYY-MM-DD")} | Created |
`;
-%>
