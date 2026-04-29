For your specific use case — security ops vault plus training log — here are the plugins worth installing:

**Core ones to add now**

- **Dataview** — treats your vault like a database. You can write queries that pull all `#intel` notes from the last 7 days, show all Week 4 sessions, or list every KQL note with status `Draft`. Extremely powerful once you have enough notes.
- **Calendar** — adds a calendar view in the sidebar. Click any day to open that day's daily note. Simple but makes daily logging much more natural for training sessions.
- **Periodic Notes** — works with Calendar to auto-create daily/weekly notes from your templates. Set it up once and new notes appear automatically.

**Useful but optional**

- **Obsidian Git** — auto-commits your vault to a git repo on a schedule. Free backup and version history. Useful if you ever want to recover a deleted note or see how a note evolved.
- **Tag Wrangler** — rename and merge tags across the whole vault. Once your tag list grows it becomes essential.
- **Iconize** — adds icons to folders in the sidebar. Small thing but makes navigation much faster visually.

**Skip for now**

Canvas, Excalidraw, and most AI plugins are worth ignoring until the basics are solid. They add complexity without much payoff at this stage.

---

**Tutorials worth your time**

- **Nicole van der Hoeven on YouTube** — best practical Obsidian content, security-adjacent mindset, covers Dataview extensively. Start with her Dataview series.
- **Linking Your Thinking (Nick Milo)** — more philosophy of note-taking but useful for understanding how to build a connected vault rather than just a folder of files.
- **Obsidian official docs** — `help.obsidian.md` — actually well written, worth reading the Dataview and Templater sections specifically.
- **Dataview docs** — `blacksmithgu.github.io/obsidian-dataview` — the plugin docs are the best reference once you want to write your own queries.

Dataview is the one I'd prioritise learning first — once it's set up you can build a live dashboard on your `Home.md` that automatically surfaces recent intel notes, upcoming sessions, and draft KQL queries without any manual updating.#