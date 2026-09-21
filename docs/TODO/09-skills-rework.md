# 09 -- Rework the skills into skills/

Goal: `skills/_archive/agent-skills/` holds the old Claude and Codex process-reader,
evidence-retrieval and repo-project-engineer prompts, archived because they pointed agents at a
read list that duplicated `docs/agent-reader.md`. Replace them with a small set of skills that
each do one thing, then delete the archive.

## Inputs
- `skills/README.md` (layout: `review/`, `agents/claude/`, `agents/codex/`).
- `skills/_archive/agent-skills/` (what they said; keep the hard rules, drop the read lists).
- `docs/agent-reader.md` (the read order lives here, not in a skill).
- Chunks 06-08 output (the docs a skill should point at).
- `appsec-review-process/TODO.md` item "Publish reusable Codex and Claude skill installation
  instructions".

## Steps
1. Decide the skill set. Proposed minimum: `process-reader` (rules only + "read docs/agent-reader.md"),
   `evidence-retrieval` (bounded retrieval procedure), `repo-project-engineer` (how to add a worker,
   schema, test, parity record). Each under `skills/agents/claude/<name>.md` and
   `skills/agents/codex/<name>/SKILL.md`, sharing one body file to avoid drift (Codex needs
   frontmatter; keep it as a 5-line wrapper).
2. `skills/review/`: one skill per review procedure a worker or persona follows that is not
   lane-specific (e.g. citing evidence, writing a worker-result envelope, refutation checklist).
   Start with what the lane prompts repeat; do not invent.
3. Installation instructions in `skills/README.md` for both agents; remove the TODO.md item.
4. `git rm -r skills/_archive`.

## Done when
`skills/_archive` is gone, every skill has both agent packagings, and AGENTS.md points at
`skills/README.md` for skills and `docs/agent-reader.md` for reading.

## Touches
`skills/`, `AGENTS.md`, `appsec-review-process/TODO.md`.
