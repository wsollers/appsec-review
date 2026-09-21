# Continuation prompts

Every continuation / handoff prompt for this repository lives in this folder. A continuation prompt
is what a fresh agent session (Claude, Codex or a person) is given to pick work up where an earlier
session stopped: the state at the time of writing, the working protocol, the lessons to carry, and
what to do next.

**Looking for where to start? Read the newest dated `*-appsec-review-continuation.md` first.** It says
which earlier prompts it supersedes.

## Rules

- **New prompts go here and nowhere else** — not in `appsec-review-process/`, not in the repository
  root, not in `Claude outputs/` or any other scratch directory. Commit them; an untracked prompt is
  invisible to the next session and to other agents.
- **Naming.** Session handoffs: `YYYY-MM-DD-<short-topic>.md`, dated by the day the prompt is FOR (a
  prompt written late on the 20th for the next day is `…-21-…`). Task-scoped prompts that stay valid
  until their task closes: `<task-or-topic>.md` without a date.
- **A prompt is a snapshot, not an authority.** State in it goes stale within hours. Its first step
  must re-derive ground truth (`git fetch`, `gh pr list`, `git worktree list`, the live stack's
  `compose ps`). When a prompt and the tracked docs disagree, the docs, the ADRs under
  `docs/decisions/`, `appsec-review-process/TODO.md` and run-owned
  `appsec-review-process/runs/<run_id>/data/` records win — see [`AGENTS.md`](../../AGENTS.md).
- **Never edit an old prompt to update it.** Write a new one that says what it supersedes, and add
  it to the index below. Fixing a broken path in an old prompt is fine.
- **No secrets, tokens, credentials or customer data** — prompts are tracked and pushed.
- Decisions belong in ADRs and `TODO.md`; a prompt may point at them but must not be the only place
  a decision is written down.

## Index

Session handoffs, newest first:

| Prompt | What it covers |
|---|---|
| [2026-09-21-appsec-review-continuation.md](2026-09-21-appsec-review-continuation.md) | State late 2026-09-20, the subagent/verification protocol, lessons 1–16, next tasks. Supersedes every earlier session handoff. |

Task-scoped prompts:

| Prompt | Task |
|---|---|
| [design-parity-worker-envelope.md](design-parity-worker-envelope.md) | Design parity Workstream B, batch 9 (common worker envelope); holds run ids `TODO.md` cites. |
| [scripts-to-pipeline-migration.md](scripts-to-pipeline-migration.md) | Migrating review jobs out of `scripts/` (see the Script Migration Rule in `AGENTS.md`). |
| [g02-owasp-workbench-decision.md](g02-owasp-workbench-decision.md) | G02 OWASP control workbench decision. |

## History of this folder

Until 2026-09-21 these files were spread over `appsec-review-process/continuation-*.md`,
`docs/continuation-prompt-*.md` and an untracked `Claude outputs/` directory. They were moved here
unchanged apart from path references. In the task-scoped prompts that came from
`appsec-review-process/`, a bare file name in backticks (for example `` `TODO.md` ``) means the file
of that name under `appsec-review-process/`.
