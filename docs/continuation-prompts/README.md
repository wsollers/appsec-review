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
| [2026-09-25-build-lane-construction.md](2026-09-25-build-lane-construction.md) | After D04 went live (SAT stages 1-9 all automatic, SAT `20260925T170552Z`): build lane next (`02-build-index`/`-plan`/`-resolution`, per-unit per build-unit-classification.md). hal5000 WSL workflow, Docker Desktop only. Supersedes the D04 prompt below for what comes next. |
| [2026-09-25-d04-sre-operations-topology-dispatch.md](2026-09-25-d04-sre-operations-topology-dispatch.md) | Scoped to one task: build and live-test D04 (automatic persona dispatch for `02-sre-operations-topology`, SAT stage 9). Done 2026-09-25 (live PASS); superseded by the build-lane prompt above. Written after D01-D03 were built, live-confirmed and merged (PR #39, `main` = `3f7b283`); branch `d04-sre-operations-topology-dispatch` exists and is empty. Native Linux host `zarathustra` workflow, not WSL. Supersedes sections 3-6 of the D02 prompt below for D03/D04 work. |
| [2026-09-24-d02-dev-project-discovery-construction.md](2026-09-24-d02-dev-project-discovery-construction.md) | Scoped to one task: D02 (`02-dev-project-discovery`) dispatch construction. Done 2026-09-25 (built, live-confirmed and merged with D03); superseded by the D04 prompt above for what comes next. |
| [2026-09-24-d01-persona-dispatch-construction.md](2026-09-24-d01-persona-dispatch-construction.md) | Scoped to one task: build and live-test D01 (automatic, unpooled persona dispatch for `02-repository-partition-discovery`), per `appsec-review-process/TODO.md` Phase 5b. Meant for a separate conversation from the one doing higher-level SAT architecture/sequencing. Does not supersede the 2026-09-21 prompt below for general coordinator protocol -- that prompt describes an earlier Linux-host/PR-based workflow now superseded in practice by the WSL/patch-based delivery this prompt itself documents (section 4). |
| [2026-09-21-appsec-review-continuation.md](2026-09-21-appsec-review-continuation.md) | State late 2026-09-20, the subagent/verification protocol, lessons 1–16, next tasks. Supersedes every earlier session handoff before it. |

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
