# Agent Entry Points

This repository keeps agent operating instructions in tracked docs and process skills.

- Codex agents: start with
  [`appsec-review-process/agent-skills/codex/process-reader/SKILL.md`](appsec-review-process/agent-skills/codex/process-reader/SKILL.md).
- Claude-style agents: start with
  [`appsec-review-process/agent-skills/claude/process-reader.md`](appsec-review-process/agent-skills/claude/process-reader.md).
- Shared reader map:
  [`docs/agent-reader.md`](docs/agent-reader.md).
- Continuation / handoff prompts (picking up earlier work): every one lives in
  [`docs/continuation-prompts/`](docs/continuation-prompts/README.md). Start from the newest dated
  prompt in its index, and write new prompts there and nowhere else.

When docs and old scratch evidence disagree, use the docs and run-owned
`appsec-review-process/runs/<run_id>/data/` records as authoritative.

## Script Migration Rule

Do not add new review-work logic under `scripts/`. That directory is legacy toolbox compatibility.
When a script is still doing review work, port the logic into `pipeline/` or a Dagster/run-owned
worker under `appsec-review-process/`, qualify the replacement, update callers, and then delete the
old script outright. No thin compatibility wrapper, no deprecation shim -- no tech debt.
