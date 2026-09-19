# Agent Entry Points

This repository keeps agent operating instructions in tracked docs and process skills.

- Codex agents: start with
  [`appsec-review-process/agent-skills/codex/process-reader/SKILL.md`](appsec-review-process/agent-skills/codex/process-reader/SKILL.md).
- Claude-style agents: start with
  [`appsec-review-process/agent-skills/claude/process-reader.md`](appsec-review-process/agent-skills/claude/process-reader.md).
- Shared reader map:
  [`docs/agent-reader.md`](docs/agent-reader.md).

When docs and old scratch evidence disagree, use the docs and run-owned
`appsec-review-process/runs/<run_id>/data/` records as authoritative.

## Script Migration Rule

Do not add new review-work logic under `scripts/`. That directory is legacy toolbox compatibility.
When a script is still doing review work, port the logic into `pipeline/` or a Dagster/run-owned
worker under `appsec-review-process/`, qualify the replacement, update callers, and then delete the
old script or leave only a thin compatibility wrapper with a deprecation note.
