# skills

Top-level home for every skill in this repository. A skill is a tracked instruction set that an
agent loads before doing one bounded kind of work. Two families live here:

| Path | Purpose | Status |
|---|---|---|
| `skills/review/` | Skills used by the review processes themselves (lanes, workers, personas): the reusable procedure a worker follows for one kind of review work. | Empty; authored during the architecture rework (`docs/TODO/09-skills-rework.md`). |
| `skills/agents/claude/` | Skills installed for Claude-style agents operating this repository (process reading, evidence retrieval, repo engineering). | Empty; same rework. |
| `skills/agents/codex/` | The same skills packaged for Codex (`SKILL.md` with frontmatter). | Empty; same rework. |
| `skills/_archive/` | The previous `appsec-review-process/agent-skills/` tree, moved here unchanged on 2026-09-21. **Not in use.** Nothing may point an agent at it. Delete it when the rework lands. | Archived. |

Until the rework lands, the only agent entry point is [`docs/agent-reader.md`](../docs/agent-reader.md).
